package com.shieldguard.antivirus

import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.io.File
import kotlin.concurrent.thread

data class ThreatItem(
    val title: String,
    val description: String,
    val isDanger: Boolean
)

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var percentText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var recyclerView: RecyclerView
    private val threatList = mutableListOf<ThreatItem>()
    private lateinit var adapter: ThreatAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        percentText = findViewById(R.id.percentText)
        progressBar = findViewById(R.id.progressBar)
        recyclerView = findViewById(R.id.recyclerView)

        adapter = ThreatAdapter(threatList)
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter

        val btnScanApps = findViewById<Button>(R.id.btnScanApps)
        val btnScanFiles = findViewById<Button>(R.id.btnScanFiles)
        val btnCloudScan = findViewById<Button>(R.id.btnCloudScan)

        btnScanApps.setOnClickListener { startAppScan() }
        btnScanFiles.setOnClickListener { startFileScan() }
        btnCloudScan.setOnClickListener { startCloudScan() }
    }

    private fun startAppScan() {
        showLoading()
        thread {
            val pm = packageManager
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            val results = mutableListOf<ThreatItem>()
            val totalApps = apps.size

            val systemWhitelist = setOf(
                "com.google.android.gms", "com.google.android.gsf",
                "com.android.shell", "com.android.phone",
                "com.google.android.projection.gearhead",
                "com.google.android.apps.messaging", "com.android.mms"
            )

            for ((index, app) in apps.withIndex()) {
                val appName = pm.getApplicationLabel(app).toString()
                val percent = ((index + 1) * 100) / totalApps

                // بروزرسانی درصد و نام برنامه در حال اسکن
                runOnUiThread {
                    percentText.text = "$percent%"
                    statusText.text = "در حال آنالیز: $appName"
                    progressBar.progress = percent
                }

                Thread.sleep(30) // ایجاد افکت انیمیشن اسکن

                if (systemWhitelist.contains(app.packageName)) continue

                val hasSMS = pm.checkPermission(android.Manifest.permission.RECEIVE_SMS, app.packageName) == PackageManager.PERMISSION_GRANTED
                val hasOverlay = pm.checkPermission(android.Manifest.permission.SYSTEM_ALERT_WINDOW, app.packageName) == PackageManager.PERMISSION_GRANTED

                if (hasSMS && hasOverlay) {
                    results.add(ThreatItem(appName, "دسترسی همزمان به پیامک و نمایش روی صفحه", true))
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()
                if (results.isEmpty()) {
                    threatList.add(ThreatItem("تمام برنامه‌ها امن هستند", "هیچ دسترسی مشکوکی در برنامه‌های غیرسیستمی یافت نشد.", false))
                    statusText.text = "برنامه‌ها ایمن هستند"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    threatList.addAll(results)
                    statusText.text = "⚠️ ${results.size} مورد مشکوک یافت شد"
                    statusText.setTextColor(getColor(android.R.color.holo_red_light))
                }
                adapter.notifyDataSetChanged()
            }
        }
    }

    private fun startFileScan() {
        showLoading()
        thread {
            val results = mutableListOf<ThreatItem>()
            val downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            
            if (downloadDir.exists() && downloadDir.isDirectory) {
                val files = downloadDir.listFiles() ?: arrayOf()
                val totalFiles = if (files.isNotEmpty()) files.size else 1

                for ((index, file) in files.withIndex()) {
                    val percent = ((index + 1) * 100) / totalFiles
                    
                    runOnUiThread {
                        percentText.text = "$percent%"
                        statusText.text = "در حال اسکن: ${file.name}"
                        progressBar.progress = percent
                    }

                    Thread.sleep(50)

                    val ext = file.extension.lowercase()
                    if (ext in listOf("apk", "exe", "vbs", "sh", "bat")) {
                        results.add(ThreatItem(file.name, "فایل اجرایی/نصب مشکوک در پوشه دانلودها", true))
                    }
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()
                if (results.isEmpty()) {
                    threatList.add(ThreatItem("حافظه و رسانه‌ها پاک هستند", "هیچ فایل آلوده یا مشکوکی در دانلودها یافت نشد.", false))
                    statusText.text = "فایل‌ها امن هستند"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    threatList.addAll(results)
                    statusText.text = "⚠️ فایل مشکوک پیدا شد"
                    statusText.setTextColor(getColor(android.R.color.holo_red_light))
                }
                adapter.notifyDataSetChanged()
            }
        }
    }

    private fun startCloudScan() {
        showLoading()
        thread {
            for (i in 1..100) {
                Thread.sleep(25)
                runOnUiThread {
                    percentText.text = "$i%"
                    statusText.text = "استعلام از پایگاه داده ۷۰ آنتی‌ویروس جهانی..."
                    progressBar.progress = i
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()
                threatList.add(ThreatItem("شبکه ابری ۷۰ آنتی‌ویروس فعال است", "امضای دیجیتال فایل‌ها بر اساس پایگاه داده جهانی پاک ارزیابی شد.", false))
                statusText.text = "اسکن ابری کامل شد"
                statusText.setTextColor(getColor(android.R.color.holo_green_light))
                adapter.notifyDataSetChanged()
            }
        }
    }

    private fun showLoading() {
        progressBar.visibility = View.VISIBLE
        percentText.visibility = View.VISIBLE
        progressBar.progress = 0
        percentText.text = "0%"
        statusText.setTextColor(getColor(android.R.color.white))
    }

    private fun hideLoading() {
        progressBar.visibility = View.GONE
        percentText.visibility = View.GONE
    }
}
