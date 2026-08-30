package com.shieldguard.antivirus

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var scanner: VirusScanner
    private lateinit var resultText: TextView
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        scanner = VirusScanner(this)
        resultText = findViewById(R.id.resultText)
        statusText = findViewById(R.id.statusText)

        val btnScanApps = findViewById<Button>(R.id.btnScanApps)
        val btnScanFiles = findViewById<Button>(R.id.btnScanFiles)
        val btnCloudScan = findViewById<Button>(R.id.btnCloudScan)

        btnScanApps.setOnClickListener {
            val results = scanner.scanApps()
            if (results.isEmpty()) {
                resultText.text = "هیچ برنامه مشکوکی پیدا نشد."
                statusText.text = "برنامه‌ها امن هستند"
                statusText.setTextColor(getColor(android.R.color.holo_green_light))
            } else {
                val sb = StringBuilder("⚠️ موارد مشکوک در برنامه‌ها:\n\n")
                results.forEach { sb.append("• ${it.title}\n  توضیح: ${it.description}\n\n") }
                resultText.text = sb.toString()
                statusText.text = "هشدار! موارد مشکوک یافت شد"
                statusText.setTextColor(getColor(android.R.color.holo_red_light))
            }
        }

        btnScanFiles.setOnClickListener {
            val results = scanner.scanMediaFiles()
            if (results.isEmpty()) {
                resultText.text = "هیچ فایل یا رسانه آلوده‌ای یافت نشد."
            } else {
                val sb = StringBuilder("⚠️ فایل‌های مشکوک به ویروس:\n\n")
                results.forEach { sb.append("• ${it.title}\n  علت: ${it.description}\n\n") }
                resultText.text = sb.toString()
            }
        }

        btnCloudScan.setOnClickListener {
            resultText.text = "در حال استعلام از موتور ابری (۷۰ آنتی‌ویروس)..."
            thread {
                // تست اتصال به سرور جهانی ۷۰ آنتی ویروس
                val res = scanner.scanWithVirusTotal("", "YOUR_API_KEY")
                runOnUiThread {
                    resultText.text = res
                }
            }
        }
    }
}
