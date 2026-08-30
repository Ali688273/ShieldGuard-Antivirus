package com.shieldguard.antivirus

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
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

        // درخواست دسترسی حافظه در ابتدای برنامه
        checkAndRequestPermissions()

        findViewById<Button>(R.id.btnScanApps).setOnClickListener { startAppScan() }
        findViewById<Button>(R.id.btnScanFiles).setOnClickListener { 
            if (hasStoragePermission()) {
                startFileScan()
            } else {
                checkAndRequestPermissions()
            }
        }
        findViewById<Button>(R.id.btnCloudScan).setOnClickListener { 
            if (isNetworkAvailable()) {
                startCloudScan()
            } else {
                Toast.makeText(this, "خطا: اسکن ابری نیازمند اتصال به اینترنت است!", Toast.LENGTH_LONG).show()
                statusText.text = "⚠️ برای اسکن ابری اینترنت را روشن کنید"
                statusText.setTextColor(getColor(android.R.color.holo_red_light))
            }
        }
    }

    private fun isNetworkAvailable(): Boolean {
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val network = connectivityManager.activeNetwork ?: return false
            val activeNetwork = connectivityManager.getNetworkCapabilities(network) ?: return false
            return activeNetwork.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                   activeNetwork.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        } else {
            @Suppress("DEPRECATION")
            val networkInfo = connectivityManager.activeNetworkInfo ?: return false
            @Suppress("DEPRECATION")
            return networkInfo.isConnected
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

    private fun startCloudScan() {
        showLoading()
        thread {
            val results = scanner.scanCloudReal { appName, percent ->
                runOnUiThread {
                    percentText.text = "$percent%"
                    statusText.text = "استعلام ابری آنلاین: $appName"
                    progressBar.progress = percent
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()
                val dangerCount = results.count { it.isDanger }

                results.forEach { threatList.add(ThreatItem(it.title, it.description, it.isDanger)) }

                if (dangerCount == 0) {
                    statusText.text = "اسکن ابری آنلاین کامل شد (${results.size} برنامه تایید شد)"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    statusText.text = "⚠️ $dangerCount تهدید ابری کشف شد"
                    statusText.setTextColor(getColor(android.R.color.holo_red_light))
                }
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
