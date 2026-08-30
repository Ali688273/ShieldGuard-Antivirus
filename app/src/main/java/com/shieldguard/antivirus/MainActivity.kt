package com.shieldguard.antivirus

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var percentText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var recyclerView: RecyclerView
    private val threatList = mutableListOf<ThreatItem>()
    private lateinit var adapter: ThreatAdapter
    private lateinit var scanner: VirusScanner

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        scanner = VirusScanner(this)
        statusText = findViewById(R.id.statusText)
        percentText = findViewById(R.id.percentText)
        progressBar = findViewById(R.id.progressBar)
        recyclerView = findViewById(R.id.recyclerView)

        adapter = ThreatAdapter(threatList)
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter

        checkAndRequestStoragePermissions()

        findViewById<Button>(R.id.btnScanApps).setOnClickListener { startAppScan() }
        findViewById<Button>(R.id.btnScanFiles).setOnClickListener { 
            if (hasFullStoragePermission()) {
                startFileScan()
            } else {
                requestFullStoragePermission()
            }
        }
        
        findViewById<Button>(R.id.btnCleanCache).setOnClickListener { 
            startCacheCleaner()
        }
    }

    private fun hasFullStoragePermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun checkAndRequestStoragePermissions() {
        if (!hasFullStoragePermission()) {
            requestFullStoragePermission()
        }
    }

    private fun requestFullStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.data = Uri.parse("package:$packageName")
                startActivity(intent)
            } catch (e: Exception) {
                val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                startActivity(intent)
            }
        } else {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE),
                101
            )
        }
    }

    private fun startAppScan() {
        showLoading()
        thread {
            val results = scanner.scanUserApps { appName, percent ->
                runOnUiThread {
                    percentText.text = "$percent%"
                    statusText.text = "در حال آنالیز برنامه: $appName"
                    progressBar.progress = percent
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()
                val dangerCount = results.count { it.isDanger }
                
                results.forEach { threatList.add(ThreatItem(it.title, it.description, it.isDanger)) }

                if (dangerCount == 0) {
                    statusText.text = "برنامه‌ها اسکن شدند (${results.size} برنامه پاک)"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    statusText.text = "⚠️ $dangerCount مورد مشکوک پیدا شد"
                    statusText.setTextColor(getColor(android.R.color.holo_red_light))
                }
                adapter.notifyDataSetChanged()
            }
        }
    }

    private fun startFileScan() {
        showLoading()
        thread {
            val results = scanner.scanFiles { fileName, percent ->
                runOnUiThread {
                    percentText.text = "$percent%"
                    statusText.text = "در حال ورود و آنالیز عمیق پوشه: $fileName"
                    progressBar.progress = percent
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()

                if (results.isEmpty()) {
                    threatList.add(ThreatItem("تمام پوشه‌ها و کارت حافظه اسکن شدند", "هیچ فایل مخرب یا خطرسازی در هیچ پوشه‌ای پیدا نشد.", false))
                    statusText.text = "حافظه و پوشه‌ها کاملاً پاک هستند"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    results.forEach { threatList.add(ThreatItem(it.title, it.description, it.isDanger)) }
                    statusText.text = "⚠️ ${results.size} فایل ناامن در پوشه‌ها پیدا شد"
                    statusText.setTextColor(getColor(android.R.color.holo_red_light))
                }
                adapter.notifyDataSetChanged()
            }
        }
    }

    private fun startCacheCleaner() {
        showLoading()
        thread {
            runOnUiThread {
                statusText.text = "در حال پاک‌سازی فایل‌های موقت و حافظه پنهان..."
                progressBar.progress = 50
                percentText.text = "50%"
            }

            Thread.sleep(600)
            val freedAmount = scanner.clearAppCache()

            runOnUiThread {
                hideLoading()
                threatList.clear()

                threatList.add(ThreatItem("پاک‌سازی حافظه پنهان", "مقدار $freedAmount فایل‌های موقت با موفقیت پاک‌سازی شد.", false))
                statusText.text = "حافظه پنهان پاک‌سازی شد ($freedAmount آزادسازی شد)"
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
