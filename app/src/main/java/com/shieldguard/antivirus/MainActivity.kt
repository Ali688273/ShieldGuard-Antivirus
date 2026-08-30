package com.shieldguard.antivirus

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
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

    private val STORAGE_PERMISSION_CODE = 101

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

        checkAndRequestPermissions()

        findViewById<Button>(R.id.btnScanApps).setOnClickListener { startAppScan() }
        findViewById<Button>(R.id.btnScanFiles).setOnClickListener { 
            if (hasStoragePermission()) {
                startFileScan()
            } else {
                checkAndRequestPermissions()
            }
        }
        
        findViewById<Button>(R.id.btnCleanCache).setOnClickListener { 
            startCacheCleaner()
        }
    }

    private fun hasStoragePermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_IMAGES) == PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_VIDEO) == PackageManager.PERMISSION_GRANTED
        } else {
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun checkAndRequestPermissions() {
        if (!hasStoragePermission()) {
            val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                arrayOf(
                    Manifest.permission.READ_MEDIA_IMAGES,
                    Manifest.permission.READ_MEDIA_VIDEO,
                    Manifest.permission.READ_MEDIA_AUDIO
                )
            } else {
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)
            }
            ActivityCompat.requestPermissions(this, permissions, STORAGE_PERMISSION_CODE)
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
                    statusText.text = "⚠️ $dangerCount مورد مشکوک از بین ${results.size} برنامه یافت شد"
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
                    statusText.text = "در حال آنالیز عمیق پوشه‌ها: $fileName"
                    progressBar.progress = percent
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()

                if (results.isEmpty()) {
                    threatList.add(ThreatItem("حافظه و کارت حافظه پاک هستند", "هیچ فایل مخرب یا خطرسازی در پوشه‌ها پیدا نشد.", false))
                    statusText.text = "هیچ فایل مشکوکی پیدا نشد"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    results.forEach { threatList.add(ThreatItem(it.title, it.description, it.isDanger)) }
                    statusText.text = "⚠️ ${results.size} فایل ناامن پیدا شد"
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
                statusText.text = "در حال محاسبه و آزادسازی حافظه پنهان..."
                progressBar.progress = 50
                percentText.text = "50%"
            }

            Thread.sleep(800)
            val cacheSizeBefore = scanner.getCacheSize()
            val success = scanner.clearAppCache()

            runOnUiThread {
                hideLoading()
                threatList.clear()

                if (success) {
                    threatList.add(ThreatItem("پاک‌سازی فایل‌های موقت", "فایل‌های کش موقت برنامه با موفقیت آزادسازی شدند ($cacheSizeBefore).", false))
                    threatList.add(ThreatItem("پاک‌سازی کش کلی دستگاه", "برای آزادسازی کامل حافظه پنهان سایر برنامه‌ها، صفحه مدیریت حافظه باز شد.", false))
                    statusText.text = "حافظه پنهان آزادسازی شد"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    statusText.text = "خطا در پاک‌سازی کش"
                    statusText.setTextColor(getColor(android.R.color.holo_red_light))
                }
                adapter.notifyDataSetChanged()

                try {
                    val intent = Intent(Settings.ACTION_INTERNAL_STORAGE_SETTINGS)
                    startActivity(intent)
                } catch (e: Exception) {
                    Toast.makeText(this@MainActivity, "تنظیمات حافظه باز شد", Toast.LENGTH_SHORT).show()
                }
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
