package com.shieldguard.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Environment
import java.io.File
import java.security.MessageDigest
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class ScanResult(
    val title: String,
    val description: String,
    val type: String // "APP", "FILE", "CLOUD"
)

class VirusScanner(private val context: Context) {

    private val systemWhitelist = setOf(
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.google.android.projection.gearhead",
        "com.android.shell",
        "com.android.phone",
        "com.google.android.apps.messaging",
        "com.android.mms"
    )

    // اسکن برنامه‌ها
    fun scanApps(): List<ScanResult> {
        val pm = context.packageManager
        val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        val list = mutableListOf<ScanResult>()

        for (app in installedApps) {
            if (systemWhitelist.contains(app.packageName)) continue

            val appName = pm.getApplicationLabel(app).toString()
            val hasSMS = pm.checkPermission(android.Manifest.permission.RECEIVE_SMS, app.packageName) == PackageManager.PERMISSION_GRANTED
            val hasOverlay = pm.checkPermission(android.Manifest.permission.SYSTEM_ALERT_WINDOW, app.packageName) == PackageManager.PERMISSION_GRANTED

            if (hasSMS && hasOverlay) {
                list.add(ScanResult(appName, "دسترسی همزمان مشکوک به پیامک و نمایش روی صفحه", "APP"))
            }
        }
        return list
    }

    // اسکن فایل‌ها، عکس‌ها و ویدیوها (فقط هشدار)
    fun scanMediaFiles(): List<ScanResult> {
        val list = mutableListOf<ScanResult>()
        val downloadFolder = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        
        if (downloadFolder.exists() && downloadFolder.isDirectory) {
            downloadFolder.listFiles()?.forEach { file ->
                if (file.extension.lowercase() in listOf("apk", "exe", "vbs")) {
                    list.add(ScanResult(file.name, "فایل مشکوک اجرایی در پوشه دانلودها یافته شد", "FILE"))
                }
            }
        }
        return list
    }

    // اسکن ابری با پایگاه داده ۷۰ آنتی‌ویروس (VirusTotal API)
    fun scanWithVirusTotal(filePath: String, apiKey: String): String {
        return try {
            val file = File(filePath)
            if (!file.exists()) return "فایل یافت نشد"

            val md = MessageDigest.getInstance("SHA-256")
            val hash = md.digest(file.readBytes()).joinToString("") { "%02x".format(it) }

            val url = URL("https://www.virustotal.com/api/v3/files/$hash")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.setRequestProperty("x-apikey", apiKey)

            if (conn.responseCode == 200) {
                val response = conn.inputStream.bufferedReader().readText()
                val json = JSONObject(response)
                val stats = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats")
                val malicious = stats.getInt("malicious")
                "نتیجه: $malicious آنتی‌ویروس از ۷۰ موتور، این فایل را آلوده تشخیص دادند."
            } else {
                "فایل جدید است یا در پایگاه داده جهانی VirusTotal ثبت نشده."
            }
        } catch (e: Exception) {
            "خطا در اتصال به شبکه‌ی ۷۰ آنتی‌ویروس"
        }
    }
}
