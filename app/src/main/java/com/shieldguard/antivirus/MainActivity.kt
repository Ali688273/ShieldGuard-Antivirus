package com.shieldguard.antivirus

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var scanButton: Button
    private lateinit var scanner: VirusScanner

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(64, 64, 64, 64)
        }

        statusText = TextView(this).apply {
            text = "آنتی ویروس شیلد گارد\nجهت بررسی دستگاه دکمه زیر را فشار دهید."
            textSize = 18f
            setPadding(0, 0, 0, 32)
        }

        scanButton = Button(this).apply {
            text = "شروع اسکن هوشمند"
        }

        layout.addView(statusText)
        layout.addView(scanButton)
        setContentView(layout)

        scanner = VirusScanner(this)

        scanButton.setOnClickListener {
            runFullScan()
        }
    }

    private fun runFullScan() {
        statusText.text = "در حال اسکن برنامه‌های نصب‌شده..."
        scanButton.isEnabled = false

        lifecycleScope.launch(Dispatchers.IO) {
            val appResults = scanner.scanInstalledApps()
            val threats = appResults.filter { it.isMalicious }

            withContext(Dispatchers.Main) {
                if (threats.isEmpty()) {
                    statusText.text = "دستگاه شما کاملاً امن است!\nتعداد برنامه‌های بررسی‌شده: ${appResults.size}"
                } else {
                    statusText.text = "هشدار! موارد مشکوک یافت شد:\n" +
                            threats.joinToString("\n") { "${it.name}: ${it.reason}" }
                }
                scanButton.isEnabled = true
            }
        }
    }
}
