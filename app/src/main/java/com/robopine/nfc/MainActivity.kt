package com.robopine.nfc

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.*

private fun ByteArray?.toHex(): String =
    this?.joinToString(" ") { "%02X".format(it) } ?: "N/A"
class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private val scope = MainScope()

    private lateinit var txtInfo: TextView
    private var nfcAdapter: NfcAdapter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        txtInfo = findViewById(R.id.textStatus)   // your TextView id
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            null
        )
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    // ------------------------------------------------------------------------
    // This is the part you asked about
    // ------------------------------------------------------------------------
    override fun onTagDiscovered(tag: Tag) {
        val iso = IsoDep.get(tag) ?: return

        scope.launch {
            val infoBuilder = StringBuilder()

            try {
                iso.connect()

                // ---- IsoDep basic info ----
                val hi = iso.hiLayerResponse
                val ats = iso.historicalBytes

                infoBuilder.appendLine("---- IsoDep Info ----")
                infoBuilder.appendLine("HiLayer: ${hi.toHex()}")
                infoBuilder.appendLine("ATS (RATS Response): ${ats.toHex()}")
                infoBuilder.appendLine()

                // ---- MIFARE Plus SL3 stuff ----
                val controller = MifarePlusController(iso)

                // 0xFF..FF..FF (16 bytes)
                val keyFF = ByteArray(16) { 0xFF.toByte() }

                // keyNumber must match your card configuration.
                // 0x4000 is just an example (same as in your Swift usage).
                val auth = controller.mfpFirstAuth(
                    key = keyFF,
                    keyNumber = 0x4000
                )

                infoBuilder.appendLine("---- FirstAuth Result ----")
                infoBuilder.appendLine("wCtr: ${auth.wCtr}")
                infoBuilder.appendLine("rCtr: ${auth.rCtr}")
                infoBuilder.appendLine("TI:   ${auth.ti.toHex()}")
                infoBuilder.appendLine("KeyEnc: ${auth.keyEnc.toHex()}")
                infoBuilder.appendLine("KeyMac: ${auth.keyMac.toHex()}")
                infoBuilder.appendLine()

                // ---- Read 5 sectors (1..5) ----
                // Classic-style mapping:
                // sector 0: block 0..3
                // sector 1: block 4..7
                // sector 2: block 8..11
                // ...
                infoBuilder.appendLine("---- Sector Data (1..5) ----")

                for (sector in 1..5) {
                    val firstBlock = sector * 4      // sector 1 -> 4, sector 2 -> 8, ...
                    val blockCount = 4               // 4 blocks per sector

                    val sectorBytes = controller.mfpRead(
                        blockNumber = firstBlock,
                        blockCount = blockCount
                    )

                    infoBuilder.appendLine("Sector $sector (blocks $firstBlock..${firstBlock + 3}):")

                    // sectorBytes length = blockCount * 16
                    for (i in 0 until blockCount) {
                        val from = i * 16
                        val to = from + 16
                        val blockBytes = sectorBytes.copyOfRange(from, to)
                        val blockNo = firstBlock + i
                        infoBuilder.appendLine("  Block $blockNo: ${blockBytes.toHex()}")
                    }

                    infoBuilder.appendLine()
                }

            } catch (e: Exception) {
                infoBuilder.appendLine("ERROR: ${e.javaClass.simpleName}: ${e.message}")
            } finally {
                try {
                    iso.close()
                } catch (_: Exception) {
                }
            }

            // Update UI
            withContext(Dispatchers.Main) {
                txtInfo.text = infoBuilder.toString()
            }
        }
    }
}
