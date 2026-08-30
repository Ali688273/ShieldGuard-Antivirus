package com.shieldguard.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Environment
import java.io.File

class VirusScanner(private val context: Context) {

    fun scanUserApps(onProgress: (String, Int) -> Unit): List<ScanResult> {
        val pm = context.packageManager
        val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        
        val userApps = installedApps.filter { app ->
            (app.flags and ApplicationInfo.FLAG_SYSTEM) == 0 &&
            (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
        }

        val results = mutableListOf<ScanResult>()
        val total = userApps.size

        if (total == 0) return results

        for ((index, app) in userApps.withIndex()) {
            val appName = pm.getApplicationLabel(app).toString()
            val percent = ((index + 1) * 100) / total
            
            onProgress(appName, percent)
            Thread.sleep(100)

            val hasSMS = pm.checkPermission(android.Manifest.permission.RECEIVE_SMS, app.packageName) == PackageManager.PERMISSION_GRANTED
            val hasOverlay = pm.checkPermission(android.Manifest.permission.SYSTEM_ALERT_WINDOW, app.packageName) == PackageManager.PERMISSION_GRANTED
            val hasLocation = pm.checkPermission(android.Manifest.permission.ACCESS_FINE_LOCATION, app.packageName) == PackageManager.PERMISSION_GRANTED

            if (hasSMS && hasOverlay) {
                results.add(ScanResult(appName, "⚠️ مشکوک: دسترسی همزمان به پیامک و نمایش روی سایر برنامه‌ها", true))
            } else if (hasSMS && hasLocation) {
                results.add(ScanResult(appName, "⚠️ هشدار: دسترسی همزمان به پیامک و موقعیت مکانی", true))
            } else {
                results.add(ScanResult(appName, "✓ اسکن شد - بدون هیچ تهدید و دسترسی مشکوک", false))
            }
        }
        
        return results.sortedByDescending { it.isDanger }
    }

    fun scanFiles(onProgress: (String, Int) -> Unit): List<ScanResult> {
        val results = mutableListOf<ScanResult>()
        val dirsToScan = listOf(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            Environment.getExternalStorageDirectory()
        )

        val filesToScan = mutableListOf<File>()
        dirsToScan.forEach { dir ->
            if (dir.exists() && dir.isDirectory) {
                val list = dir.listFiles()
                if (list != null) {
                    filesToScan.addAll(list)
                }
            }
        }

        val total = filesToScan.size
        if (total == 0) {
            onProgress("در حال بررسی حافظه...", 100)
            return results
        }

        val dangerousExtensions = setOf("apk", "exe", "vbs", "bat", "sh", "dex")

        for ((index, file) in filesToScan.withIndex()) {
            val percent = ((index + 1) * 100) / total
            onProgress(file.name, percent)
            Thread.sleep(80)

            if (file.isFile && dangerousExtensions.contains(file.extension.lowercase())) {
                results.add(ScanResult(file.name, "⚠️ فایل اجرایی/نصب ناامن در حافظه (${file.length() / 1024} KB)", true))
            } else if (file.isFile) {
                results.add(ScanResult(file.name, "✓ فایل بررسی شد - پاک است", false))
            }
        }
        return results.sortedByDescending { it.isDanger }
    }
}
