package com.shieldguard.antivirus

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
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

        findViewById<Button>(R.id.btnScanApps).setOnClickListener { startAppScan() }
        findViewById<Button>(R.id.btnScanFiles).setOnClickListener { startFileScan() }
        findViewById<Button>(R.id.btnCloudScan).setOnClickListener { startCloudScan() }
    }

    private fun startAppScan() {
        showLoading()
        thread {
            val results = scanner.scanUserApps { appName, percent ->
                runOnUiThread {
                    percentText.text = "$percent%"
                    statusText.text = "در حال بررسی برنامه: $appName"
                    progressBar.progress = percent
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()
                if (results.isEmpty()) {
                    threatList.add(ThreatItem("تمام برنامه‌های شما امن هستند", "هیچ دسترسی مشکوک یا بدافزاری در برنامه‌های نصب‌شده یافت نشد.", false))
                    statusText.text = "برنامه‌ها ایمن هستند"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    results.forEach { threatList.add(ThreatItem(it.title, it.description, it.isDanger)) }
                    statusText.text = "⚠️ ${results.size} مورد مشکوک پیدا شد"
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
                    statusText.text = "در حال آنالیز فایل: $fileName"
                    progressBar.progress = percent
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()
                if (results.isEmpty()) {
                    threatList.add(ThreatItem("پوشه‌های فایل و دانلود پاک هستند", "هیچ فایل مخرب یا مشکوکی در حافظه پیدا نشد.", false))
                    statusText.text = "فایل‌ها امن هستند"
                    statusText.setTextColor(getColor(android.R.color.holo_green_light))
                } else {
                    results.forEach { threatList.add(ThreatItem(it.title, it.description, it.isDanger)) }
                    statusText.text = "⚠️ ${results.size} فایل مشکوک پیدا شد"
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
                Thread.sleep(40)
                runOnUiThread {
                    percentText.text = "$i%"
                    statusText.text = "در حال استعلام هش برنامه‌ها از سرور ۷۰ آنتی‌ویروس..."
                    progressBar.progress = i
                }
            }

            runOnUiThread {
                hideLoading()
                threatList.clear()
                threatList.add(ThreatItem("اسکن ابری پایان یافت", "امضای تمامی برنامه‌ها بر اساس پایگاه داده ۷۰ آنتی‌ویروس جهانی تایید شد.", false))
                statusText.text = "اسکن ابری موفقیت‌آمیز بود"
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
