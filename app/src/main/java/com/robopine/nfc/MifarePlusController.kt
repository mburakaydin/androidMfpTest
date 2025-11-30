package com.robopine.nfc

import android.nfc.tech.IsoDep
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// --- Error types (Swift enum MifarePlusError) -------------------------------

sealed class MifarePlusError(message: String) : Exception(message) {

    class InvalidResponseStatus(val status: Int) :
        MifarePlusError("Invalid response status: 0x${status.toString(16)}")

    object InvalidMac :
        MifarePlusError("Invalid MAC")

    class LengthMismatch(val expected: Int, val actual: Int) :
        MifarePlusError("Length mismatch: expected=$expected actual=$actual")

    class CryptoError(message: String) :
        MifarePlusError("Crypto error: $message")

    class InvalidInput(message: String) :
        MifarePlusError("Invalid input: $message")
}

// --- FirstAuthResult (session struct) ---------------------------------------

data class FirstAuthResult(
    var wCtr: Int,        // Swift UInt16 => Int (0..0xFFFF)
    var rCtr: Int,
    var ti: ByteArray,
    var keyEnc: ByteArray,
    var keyMac: ByteArray
)

// --- Controller -------------------------------------------------------------

class MifarePlusController(
    private val isoDep: IsoDep
) {

    companion object {
        private const val TAG = "MifarePlus"
    }

    private val secureRandom = SecureRandom()

    private var session = FirstAuthResult(
        wCtr = 0,
        rCtr = 0,
        ti = ByteArray(0),
        keyEnc = ByteArray(0),
        keyMac = ByteArray(0)
    )

    // MARK: - PUBLIC: First Auth (mfpFirstAuth)

    /**
     * First authentication (equivalent to Swift mfpFirstAuth).
     *
     * @param key AES-128 key (16 bytes)
     * @param keyNumber Key number (0..65535)
     */
    suspend fun mfpFirstAuth(
        key: ByteArray,
        keyNumber: Int
    ): FirstAuthResult {

        if (key.size != 16) {
            throw MifarePlusError.InvalidInput("key must be 16 bytes (AES-128)")
        }

        val sendBuf = ByteArray(256)
        val receiveBuf = ByteArray(256)

        val randA = ByteArray(16)
        val randB = ByteArray(16)

        var wCtr = 0
        var rCtr = 0

        // --- First command: 0x70 (request random B) ---
        var sentBytes = 0
        sendBuf[sentBytes++] = 0x70.toByte()
        sendBuf[sentBytes++] = (keyNumber and 0x00FF).toByte()
        sendBuf[sentBytes++] = ((keyNumber shr 8) and 0x00FF).toByte()
        sendBuf[sentBytes++] = 0x06
        repeat(6) {
            sendBuf[sentBytes++] = 0x00
        }

        wCtr = 0
        rCtr = 0

        val cmd1 = sendBuf.copyOfRange(0, sentBytes)
        Log.d(TAG, "mfpFirstAuth: CMD1 sentBytes=$sentBytes hex=${cmd1.toHex()}")

        val resp1 = transceive(cmd1)
        System.arraycopy(resp1, 0, receiveBuf, 0, resp1.size)
        val receivedBytes1 = resp1.size

        if (receivedBytes1 < 1) {
            throw MifarePlusError.InvalidResponseStatus(0x00)
        }
        if (receiveBuf[0] != 0x90.toByte()) {
            throw MifarePlusError.InvalidResponseStatus(receiveBuf[0].toInt() and 0xFF)
        }

        if (receivedBytes1 < 1 + 16) {
            throw MifarePlusError.LengthMismatch(17, receivedBytes1)
        }
        val encRandB = receiveBuf.copyOfRange(1, 1 + 16)

        // Local auth1
        val auth1Out = mfpFirstAuth1(
            key = key,
            randA = randA,
            randB = randB,
            encRandB = encRandB
        )

        // --- Second command: 0x72 + 32 bytes from auth1Out ---
        sentBytes = 0
        sendBuf[sentBytes++] = 0x72.toByte()
        auth1Out.forEach { b ->
            sendBuf[sentBytes++] = b
        }

        val cmd2 = sendBuf.copyOfRange(0, sentBytes)
        Log.d(TAG, "mfpFirstAuth: CMD2 sentBytes=$sentBytes hex=${cmd2.toHex()}")

        val resp2 = transceive(cmd2)
        System.arraycopy(resp2, 0, receiveBuf, 0, resp2.size)
        val receivedBytes2 = resp2.size

        if (receivedBytes2 < 1) {
            throw MifarePlusError.InvalidResponseStatus(0x00)
        }
        if (receiveBuf[0] != 0x90.toByte()) {
            throw MifarePlusError.InvalidResponseStatus(receiveBuf[0].toInt() and 0xFF)
        }

        if (receivedBytes2 < 1 + 32) {
            throw MifarePlusError.LengthMismatch(33, receivedBytes2)
        }
        val auth2In = receiveBuf.copyOfRange(1, 1 + 32)
        val auth2Out = mfpFirstAuth2(
            key = key,
            randA = randA,
            randB = randB,
            input = auth2In
        )

        if (auth2Out.size != 36) {
            throw MifarePlusError.LengthMismatch(36, auth2Out.size)
        }

        val ti = auth2Out.copyOfRange(0, 4)
        val keyEnc = auth2Out.copyOfRange(4, 20)
        val keyMac = auth2Out.copyOfRange(20, 36)

        wCtr = 0
        rCtr = 0

        val res = FirstAuthResult(
            wCtr = wCtr,
            rCtr = rCtr,
            ti = ti,
            keyEnc = keyEnc,
            keyMac = keyMac
        )
        session = res
        return res
    }

    // MARK: - Low-level transceive using IsoDep ------------------------------

    private suspend fun transceive(command: ByteArray): ByteArray =
        withContext(Dispatchers.IO) {
            Log.d(TAG, ">> CMD (${command.size} bytes): ${command.toHex()}")

            if (command.isEmpty()) {
                throw MifarePlusError.InvalidInput("Empty command to tag")
            }

            try {
                if (!isoDep.isConnected) {
                    isoDep.connect()
                }
                val response = isoDep.transceive(command)
                Log.d(TAG, "<< RSP (${response.size} bytes): ${response.toHex()}")
                response
            } catch (e: IOException) {
                Log.e(TAG, "IsoDep transceive error", e)
                throw e
            }
        }

    // MARK: - firstAuth1 / firstAuth2 (same logic as Swift) ------------------

    private fun mfpFirstAuth1(
        key: ByteArray,
        randA: ByteArray,   // out
        randB: ByteArray,   // out
        encRandB: ByteArray // in (16 bytes)
    ): ByteArray {         // out: 32 bytes to send

        if (key.size != 16) {
            throw MifarePlusError.InvalidInput("key must be 16 bytes")
        }
        if (encRandB.size != 16) {
            throw MifarePlusError.InvalidInput("encRandB must be 16 bytes")
        }

        // generate 16 byte random A
        secureRandom.nextBytes(randA)

        val ivZero = ByteArray(16)

        // AES-CBC decrypt encRandB
        val decrypted = aesCBCDecrypt(
            key = key,
            iv = ivZero,
            input = encRandB
        )
        System.arraycopy(decrypted, 0, randB, 0, 16)

        // temp_randB = randB shifted left 1 byte
        val tempRandB = randB.copyOf()
        val extra = tempRandB[0]
        for (i in 0 until 15) {
            tempRandB[i] = tempRandB[i + 1]
        }
        tempRandB[15] = extra

        // data = randA || tempRandB
        val data = ByteArray(32)
        System.arraycopy(randA, 0, data, 0, 16)
        System.arraycopy(tempRandB, 0, data, 16, 16)

        val encrypted = aesCBCEncrypt(
            key = key,
            iv = ivZero,
            input = data
        )
        return encrypted // 32 bytes
    }

    private fun mfpFirstAuth2(
        key: ByteArray,
        randA: ByteArray,
        randB: ByteArray,
        input: ByteArray     // 32 bytes
    ): ByteArray {          // 36 bytes: TI(4) + ENC(16) + MAC(16)

        if (key.size != 16) {
            throw MifarePlusError.InvalidInput("key must be 16 bytes")
        }
        if (randA.size != 16 || randB.size != 16) {
            throw MifarePlusError.InvalidInput("randA/randB must be 16 bytes each")
        }
        if (input.size != 32) {
            throw MifarePlusError.InvalidInput("input must be 32 bytes")
        }

        val ivZero = ByteArray(16)
        val data = aesCBCDecrypt(
            key = key,
            iv = ivZero,
            input = input
        ) // 32 bytes

        // extra = data[19]; shift data[4..19] right by 1
        val extra = data[19]
        var i = 19
        while (i > 4) {
            data[i] = data[i - 1]
            i--
        }
        data[4] = extra

        // check randA'
        val randAprime = data.copyOfRange(4, 20)
        if (!randAprime.contentEquals(randA)) {
            throw MifarePlusError.InvalidInput("randA mismatch in firstAuth2")
        }

        val result = ByteArray(36)

        // TI = data[0..3]
        System.arraycopy(data, 0, result, 0, 4)

        // KEY_ENC
        val keyEnc = ByteArray(16)
        // memcpy(&keyEnc[0], &randA[11], 5);
        for (j in 0 until 5) {
            keyEnc[j] = randA[11 + j]
        }
        // memcpy(&keyEnc[5], &randB[11], 5);
        for (j in 0 until 5) {
            keyEnc[5 + j] = randB[11 + j]
        }
        // XOR part
        for (j in 0 until 5) {
            keyEnc[10 + j] =
                (randA[4 + j].toInt() xor randB[4 + j].toInt()).toByte()
        }
        keyEnc[15] = 0x11

        val encKeyEnc = aesCBCEncrypt(
            key = key,
            iv = ivZero,
            input = keyEnc
        ) // 16 bytes
        System.arraycopy(encKeyEnc, 0, result, 4, 16)

        // KEY_MAC
        val keyMac = ByteArray(16)
        for (j in 0 until 5) {
            keyMac[j] = randA[7 + j]
        }
        for (j in 0 until 5) {
            keyMac[5 + j] = randB[7 + j]
        }
        for (j in 0 until 5) {
            keyMac[10 + j] =
                (randA[j].toInt() xor randB[j].toInt()).toByte()
        }
        keyMac[15] = 0x22

        val encKeyMac = aesCBCEncrypt(
            key = key,
            iv = ivZero,
            input = keyMac
        )
        System.arraycopy(encKeyMac, 0, result, 20, 16)

        return result
    }

    // MARK: - mfpRead ---------------------------------------------------------

    suspend fun mfpRead(
        blockNumber: Int,
        blockCount: Int    // number of 16-byte blocks
    ): ByteArray {

        if (session.ti.size != 4) {
            throw MifarePlusError.InvalidInput("TI must be 4 bytes")
        }
        if (session.keyMac.size != 16) {
            throw MifarePlusError.InvalidInput("keyMac must be 16 bytes")
        }

        val macSendBuf = ByteArray(4096)
        val macReceiveBuf = ByteArray(16)

        val sendBuf = ByteArray(128)
        val receiveBuf = ByteArray(4096)

        var sentBytes = 0

        // Command header
        sendBuf[sentBytes++] = 0x33
        sendBuf[sentBytes++] = (blockNumber and 0x00FF).toByte()
        sendBuf[sentBytes++] = ((blockNumber shr 8) and 0x00FF).toByte()
        sendBuf[sentBytes++] = blockCount.toByte()

        // --- Calculate CMAC (request) ---
        macSendBuf[0] = 0x33
        macSendBuf[1] = (session.rCtr and 0x00FF).toByte()
        macSendBuf[2] = ((session.rCtr shr 8) and 0x00FF).toByte()
        macSendBuf[3] = session.ti[0]
        macSendBuf[4] = session.ti[1]
        macSendBuf[5] = session.ti[2]
        macSendBuf[6] = session.ti[3]
        macSendBuf[7] = (blockNumber and 0x00FF).toByte()
        macSendBuf[8] = ((blockNumber shr 8) and 0x00FF).toByte()
        macSendBuf[9] = blockCount.toByte()

        val macReq = aesCMAC(
            key = session.keyMac,
            message = macSendBuf.copyOfRange(0, 10)
        )

        // append 8 odd CMAC bytes
        for (i in 0 until 16) {
            if (i % 2 == 1) {
                sendBuf[sentBytes++] = macReq[i]
            }
        }

        val cmd = sendBuf.copyOfRange(0, sentBytes)
        val resp = transceive(cmd)
        System.arraycopy(resp, 0, receiveBuf, 0, resp.size)
        val receivedBytes = resp.size

        session.rCtr = (session.rCtr + 1) and 0xFFFF

        if (receivedBytes < 1) {
            throw MifarePlusError.InvalidResponseStatus(0x00)
        }
        if (receiveBuf[0] != 0x90.toByte()) {
            throw MifarePlusError.InvalidResponseStatus(receiveBuf[0].toInt() and 0xFF)
        }

        val dataLen = receivedBytes - 9   // remove SC + 8-byte MAC
        val expectedLen = blockCount * 16
        if (dataLen != expectedLen) {
            throw MifarePlusError.LengthMismatch(expectedLen, dataLen)
        }

        // --- Check MAC on response ---
        macSendBuf[0] = receiveBuf[0]
        macSendBuf[1] = (session.rCtr and 0x00FF).toByte()
        macSendBuf[2] = ((session.rCtr shr 8) and 0x00FF).toByte()
        // Important: bytes 3..9 still contain TI + block info from request.

        val dataStart = 1
        val dataEnd = 1 + dataLen
        val respDataSlice = receiveBuf.copyOfRange(dataStart, dataEnd)
        for ((index, b) in respDataSlice.withIndex()) {
            macSendBuf[10 + index] = b
        }

        val macMsgLen = 10 + dataLen
        val macResp = aesCMAC(
            key = session.keyMac,
            message = macSendBuf.copyOfRange(0, macMsgLen)
        )

        var macStart = receivedBytes - 8
        for (i in 0 until 16) {
            if (i % 2 == 1) {
                if (receiveBuf[macStart] != macResp[i]) {
                    throw MifarePlusError.InvalidMac
                }
                macStart++
            }
        }

        // MAC ok
        return receiveBuf.copyOfRange(1, 1 + dataLen)
    }

    // MARK: - mfpWrite --------------------------------------------------------

    suspend fun mfpWrite(
        blockNumber: Int,
        blockCount: Int,    // max 3
        blockData: ByteArray // 16 * blockCount
    ) {

        if (session.ti.size != 4) {
            throw MifarePlusError.InvalidInput("TI must be 4 bytes")
        }
        if (session.keyMac.size != 16) {
            throw MifarePlusError.InvalidInput("keyMac must be 16 bytes")
        }
        if (blockCount <= 0 || blockCount > 3) {
            throw MifarePlusError.InvalidInput("blockCount must be 1..3")
        }
        if (blockData.size != blockCount * 16) {
            throw MifarePlusError.InvalidInput("blockData length mismatch")
        }

        val macSendBuf = ByteArray(4096)
        val macReceiveBuf = ByteArray(16)

        val sendBuf = ByteArray(4096)
        val receiveBuf = ByteArray(256)

        var sentBytes = 0

        sendBuf[sentBytes++] = 0xA3.toByte()
        sendBuf[sentBytes++] = (blockNumber and 0x00FF).toByte()
        sendBuf[sentBytes++] = ((blockNumber shr 8) and 0x00FF).toByte()

        // copy block data
        blockData.forEach { b ->
            sendBuf[sentBytes++] = b
        }

        // --- Calculate CMAC (request) ---
        var macLen = 0
        for (i in 0 until 128) macSendBuf[i] = 0x00

        macSendBuf[macLen++] = 0xA3.toByte()
        macSendBuf[macLen++] = (session.wCtr and 0x00FF).toByte()
        macSendBuf[macLen++] = ((session.wCtr shr 8) and 0x00FF).toByte()
        macSendBuf[macLen++] = session.ti[0]
        macSendBuf[macLen++] = session.ti[1]
        macSendBuf[macLen++] = session.ti[2]
        macSendBuf[macLen++] = session.ti[3]
        macSendBuf[macLen++] = (blockNumber and 0x00FF).toByte()
        macSendBuf[macLen++] = ((blockNumber shr 8) and 0x00FF).toByte()

        blockData.forEach { b ->
            macSendBuf[macLen++] = b
        }

        val macReq = aesCMAC(
            key = session.keyMac,
            message = macSendBuf.copyOfRange(0, macLen)
        )

        // append odd CMAC bytes
        for (i in 0 until 16) {
            if (i % 2 == 1) {
                sendBuf[sentBytes++] = macReq[i]
            }
        }

        val cmd = sendBuf.copyOfRange(0, sentBytes)
        val resp = transceive(cmd)
        System.arraycopy(resp, 0, receiveBuf, 0, resp.size)
        val receivedBytes = resp.size

        session.wCtr = (session.wCtr + 1) and 0xFFFF

        if (receivedBytes < 1) {
            throw MifarePlusError.InvalidResponseStatus(0x00)
        }
        if (receiveBuf[0] != 0x90.toByte()) {
            throw MifarePlusError.InvalidResponseStatus(receiveBuf[0].toInt() and 0xFF)
        }

        // --- Check MAC on response ---
        macSendBuf[0] = receiveBuf[0]
        macSendBuf[1] = (session.wCtr and 0x00FF).toByte()
        macSendBuf[2] = ((session.wCtr shr 8) and 0x00FF).toByte()
        macSendBuf[3] = session.ti[0]
        macSendBuf[4] = session.ti[1]
        macSendBuf[5] = session.ti[2]
        macSendBuf[6] = session.ti[3]

        val macResp = aesCMAC(
            key = session.keyMac,
            message = macSendBuf.copyOfRange(0, 7)
        )

        var macStart = receivedBytes - 8
        for (i in 0 until 16) {
            if (i % 2 == 1) {
                if (receiveBuf[macStart] != macResp[i]) {
                    throw MifarePlusError.InvalidMac
                }
                macStart++
            }
        }
    }

    // MARK: - mfpWriteSecure --------------------------------------------------

    suspend fun mfpWriteSecure(
        blockNumber: Int,
        blockData: ByteArray // 16 bytes clear data
    ) {

        if (blockData.size != 16) {
            throw MifarePlusError.InvalidInput("dataKey must be 16 bytes")
        }
        if (session.ti.size != 4) {
            throw MifarePlusError.InvalidInput("TI must be 4 bytes")
        }
        if (session.keyEnc.size != 16) {
            throw MifarePlusError.InvalidInput("keyEnc must be 16 bytes")
        }
        if (session.keyMac.size != 16) {
            throw MifarePlusError.InvalidInput("keyMac must be 16 bytes")
        }

        val macSendBuf = ByteArray(4096)
        val sendBuf = ByteArray(4096)
        val receiveBuf = ByteArray(256)

        val ivec = ByteArray(16)
        var ivecLen = 0

        // --- Build IV (9.6.1.2), 16 bytes ---
        ivec[ivecLen++] = session.ti[0]
        ivec[ivecLen++] = session.ti[1]
        ivec[ivecLen++] = session.ti[2]
        ivec[ivecLen++] = session.ti[3]

        repeat(3) {
            ivec[ivecLen++] = (session.rCtr and 0x00FF).toByte()
            ivec[ivecLen++] = ((session.rCtr shr 8) and 0x00FF).toByte()
            ivec[ivecLen++] = (session.wCtr and 0x00FF).toByte()
            ivec[ivecLen++] = ((session.wCtr shr 8) and 0x00FF).toByte()
        }

        // Encrypt 16 bytes using keyEnc and ivec (CBC)
        val encryptedData = aesCBCEncrypt(
            key = session.keyEnc,
            iv = ivec,
            input = blockData
        )

        // --- Build command ---
        var sentBytes = 0
        sendBuf[sentBytes++] = 0xA1.toByte()
        sendBuf[sentBytes++] = (blockNumber and 0x00FF).toByte()
        sendBuf[sentBytes++] = ((blockNumber shr 8) and 0x00FF).toByte()

        encryptedData.forEach { b ->
            sendBuf[sentBytes++] = b
        }

        // --- CMAC (request) ---
        var macLen = 0
        for (i in 0 until 128) macSendBuf[i] = 0

        macSendBuf[macLen++] = 0xA1.toByte()
        macSendBuf[macLen++] = (session.wCtr and 0x00FF).toByte()
        macSendBuf[macLen++] = ((session.wCtr shr 8) and 0x00FF).toByte()
        macSendBuf[macLen++] = session.ti[0]
        macSendBuf[macLen++] = session.ti[1]
        macSendBuf[macLen++] = session.ti[2]
        macSendBuf[macLen++] = session.ti[3]
        macSendBuf[macLen++] = (blockNumber and 0x00FF).toByte()
        macSendBuf[macLen++] = ((blockNumber shr 8) and 0x00FF).toByte()

        encryptedData.forEach { b ->
            macSendBuf[macLen++] = b
        }

        val macReq = aesCMAC(
            key = session.keyMac,
            message = macSendBuf.copyOfRange(0, macLen)
        )

        for (i in 0 until 16) {
            if (i % 2 == 1) {
                sendBuf[sentBytes++] = macReq[i]
            }
        }

        val cmd = sendBuf.copyOfRange(0, sentBytes)
        val resp = transceive(cmd)
        System.arraycopy(resp, 0, receiveBuf, 0, resp.size)
        val receivedBytes = resp.size

        session.wCtr = (session.wCtr + 1) and 0xFFFF

        if (receivedBytes < 1) {
            throw MifarePlusError.InvalidResponseStatus(0x00)
        }
        if (receiveBuf[0] != 0x90.toByte()) {
            throw MifarePlusError.InvalidResponseStatus(receiveBuf[0].toInt() and 0xFF)
        }

        // --- Check MAC on response ---
        macSendBuf[0] = receiveBuf[0]
        macSendBuf[1] = (session.wCtr and 0x00FF).toByte()
        macSendBuf[2] = ((session.wCtr shr 8) and 0x00FF).toByte()
        macSendBuf[3] = session.ti[0]
        macSendBuf[4] = session.ti[1]
        macSendBuf[5] = session.ti[2]
        macSendBuf[6] = session.ti[3]

        val macResp = aesCMAC(
            key = session.keyMac,
            message = macSendBuf.copyOfRange(0, 7)
        )

        var macStart = receivedBytes - 8
        for (i in 0 until 16) {
            if (i % 2 == 1) {
                if (receiveBuf[macStart] != macResp[i]) {
                    throw MifarePlusError.InvalidMac
                }
                macStart++
            }
        }
    }

    // MARK: - AES helpers -----------------------------------------------------

    private fun aesCBCEncrypt(
        key: ByteArray,
        iv: ByteArray,
        input: ByteArray
    ): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            val skey = SecretKeySpec(key, "AES")
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, skey, ivSpec)
            return cipher.doFinal(input)
        } catch (e: GeneralSecurityException) {
            throw MifarePlusError.CryptoError("AES CBC encrypt failed: ${e.message}")
        }
    }

    private fun aesCBCDecrypt(
        key: ByteArray,
        iv: ByteArray,
        input: ByteArray
    ): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            val skey = SecretKeySpec(key, "AES")
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, skey, ivSpec)
            return cipher.doFinal(input)
        } catch (e: GeneralSecurityException) {
            throw MifarePlusError.CryptoError("AES CBC decrypt failed: ${e.message}")
        }
    }

    // AES-ECB (single block) used for CMAC
    private fun aesECBEncryptBlock(
        key: ByteArray,
        block: ByteArray
    ): ByteArray {
        require(block.size == 16) { "Block must be 16 bytes" }
        try {
            val cipher = Cipher.getInstance("AES/ECB/NoPadding")
            val skey = SecretKeySpec(key, "AES")
            cipher.init(Cipher.ENCRYPT_MODE, skey)
            return cipher.doFinal(block)
        } catch (e: GeneralSecurityException) {
            throw MifarePlusError.CryptoError("AES ECB encrypt failed: ${e.message}")
        }
    }

    // MARK: - AES-CMAC (RFC 4493) ---------------------------------------------

    private fun aesCMAC(key: ByteArray, message: ByteArray): ByteArray {
        val blockSize = 16
        val rb: Byte = 0x87.toByte()

        fun leftShiftOne(block: ByteArray): ByteArray {
            val out = ByteArray(block.size)
            var carry = 0
            for (i in block.indices.reversed()) {
                val v = block[i].toInt() and 0xFF
                out[i] = ((v shl 1) or carry).toByte()
                carry = (v ushr 7) and 0x01
            }
            return out
        }

        val zeroBlock = ByteArray(blockSize)
        val L = aesECBEncryptBlock(key, zeroBlock)

        var k1 = leftShiftOne(L)
        if ((L[0].toInt() and 0x80) != 0) {
            k1[blockSize - 1] = (k1[blockSize - 1].toInt() xor rb.toInt()).toByte()
        }

        var k2 = leftShiftOne(k1)
        if ((k1[0].toInt() and 0x80) != 0) {
            k2[blockSize - 1] = (k2[blockSize - 1].toInt() xor rb.toInt()).toByte()
        }

        if (message.isEmpty()) {
            // special case: 1 block of padding only
            val mLast = ByteArray(blockSize)
            mLast[0] = 0x80.toByte()
            for (i in 0 until blockSize) {
                mLast[i] = (mLast[i].toInt() xor k2[i].toInt()).toByte()
            }
            val x = ByteArray(blockSize) // all zeros
            val y = ByteArray(blockSize)
            for (i in 0 until blockSize) {
                y[i] = (x[i].toInt() xor mLast[i].toInt()).toByte()
            }
            return aesECBEncryptBlock(key, y)
        }

        val n = (message.size + blockSize - 1) / blockSize
        val lastComplete = (message.size % blockSize) == 0

        val lastBlockStart = (n - 1) * blockSize
        val mLast = ByteArray(blockSize)

        if (lastComplete) {
            // M_last = last 16 bytes
            for (i in 0 until blockSize) {
                mLast[i] = message[lastBlockStart + i]
            }
            for (i in 0 until blockSize) {
                mLast[i] = (mLast[i].toInt() xor k1[i].toInt()).toByte()
            }
        } else {
            val lastLen = message.size - lastBlockStart
            for (i in 0 until lastLen) {
                mLast[i] = message[lastBlockStart + i]
            }
            mLast[lastLen] = 0x80.toByte()
            for (i in 0 until blockSize) {
                mLast[i] = (mLast[i].toInt() xor k2[i].toInt()).toByte()
            }
        }

        var x = ByteArray(blockSize) // all zeros

        // process all but last block
        if (n > 1) {
            for (i in 0 until (n - 1)) {
                val block = ByteArray(blockSize)
                val start = i * blockSize
                for (j in 0 until blockSize) {
                    block[j] = message[start + j]
                }
                val tmp = ByteArray(blockSize)
                for (j in 0 until blockSize) {
                    tmp[j] = (x[j].toInt() xor block[j].toInt()).toByte()
                }
                x = aesECBEncryptBlock(key, tmp)
            }
        }

        val y = ByteArray(blockSize)
        for (i in 0 until blockSize) {
            y[i] = (x[i].toInt() xor mLast[i].toInt()).toByte()
        }
        return aesECBEncryptBlock(key, y)
    }
}

// --- Small helpers ----------------------------------------------------------

private fun ByteArray.toHex(): String =
    joinToString(" ") { "%02X".format(it) }
