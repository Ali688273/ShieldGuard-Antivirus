package com.shieldguard.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Environment
import androidx.core.content.ContextCompat
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
                results.add(ScanResult(appName, "✓ اسکن شد - بدون دسترسی مشکوک", false))
            }
        }
        return results.sortedByDescending { it.isDanger }
    }

    fun scanFiles(onProgress: (String, Int) -> Unit): List<ScanResult> {
        val results = mutableListOf<ScanResult>()
        val allFiles = mutableListOf<File>()

        // پیدا کردن مسیرهای حافظه داخلی و رم خارجی (SD Card)
        val storageDirs = ContextCompat.getExternalFilesDirs(context, null)
        val rootDirs = mutableListOf<File>()
        
        rootDirs.add(Environment.getExternalStorageDirectory()) // حافظه داخلی
        
        storageDirs.forEach { dir ->
            dir?.let {
                var parent = it.parentFile
                while (parent != null && parent.name != "Android") {
                    parent = parent.parentFile
                }
                if (parent != null && parent.parentFile != null) {
                    rootDirs.add(parent.parentFile!!) // مسیر رم خارجی
                }
            }
        }

        // جمع‌آوری بازگشتی تمام فایل‌ها درون تمام پوشه‌ها
        rootDirs.distinctBy { it.absolutePath }.forEach { root ->
            if (root.exists()) {
                collectFilesRecursively(root, allFiles, maxDepth = 5)
            }
        }

        val total = allFiles.size
        if (total == 0) {
            onProgress("در حال بررسی حافظه...", 100)
            return results
        }

        val dangerousExtensions = setOf("apk", "exe", "vbs", "bat", "sh", "dex")

        for ((index, file) in allFiles.withIndex()) {
            val percent = ((index + 1) * 100) / total
            onProgress(file.name, percent)

            if (dangerousExtensions.contains(file.extension.lowercase())) {
                results.add(ScanResult(file.name, "⚠️ فایل ناامن در مسیر: ${file.parent} (${file.length() / 1024} KB)", true))
            }
        }
        return results
    }

    private fun collectFilesRecursively(dir: File, fileList: MutableList<File>, maxDepth: Int) {
        if (maxDepth <= 0) return
        val files = dir.listFiles() ?: return
        for (file in files) {
            if (file.isDirectory) {
                // نادیده گرفتن پوشه‌های سیستمی سنگین یا خاص
                if (!file.name.startsWith(".")) {
                    collectFilesRecursively(file, fileList, maxDepth - 1)
                }
            } else if (file.isFile) {
                fileList.add(file)
            }
        }
    }
}
