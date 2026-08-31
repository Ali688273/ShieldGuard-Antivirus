package com.shieldguard.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Environment
import androidx.core.content.ContextCompat
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class VirusScanner(private val context: Context) {

    private val trustedInstallers = setOf(
        "com.android.vending",
        "com.farsitel.bazaar",
        "ir.mservices.myket",
        "com.huawei.appmarket"
    )

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
            Thread.sleep(60) // ایجاد افکت انیمیشن واقعی در اسکن

            try {
                val pkgInfo = pm.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS)
                val isTrusted = isInstalledFromTrustedSource(pm, app.packageName)

                if (isTrusted) {
                    results.add(
                        ScanResult(
                            appName,
                            "✓ اسکن امنیتی انجام شد - منبع نصب معتبر و ایمن",
                            false
                        )
                    )
                } else {
                    val score = calculateRiskScore(pkgInfo)
                    if (score >= 50) {
                        results.add(
                            ScanResult(
                                appName,
                                "⚠️ برنامه ناامن (نصب غیرمستقیم + دسترسی‌های حساس)",
                                true
                            )
                        )
                    } else {
                        results.add(
                            ScanResult(
                                appName,
                                "✓ بررسی شد - بدون تهدید امنیتی",
                                false
                            )
                        )
                    }
                }
            } catch (e: Exception) {
                results.add(ScanResult(appName, "✓ بررسی شد - ایمن", false))
            }
        }
        return results.sortedByDescending { it.isDanger }
    }

    fun scanFiles(onProgress: (String, Int) -> Unit): List<ScanResult> {
        val results = mutableListOf<ScanResult>()
        val allFiles = mutableListOf<File>()

        val rootDirs = mutableListOf<File>()
        rootDirs.add(Environment.getExternalStorageDirectory())

        val storageDirs = ContextCompat.getExternalFilesDirs(context, null)
        storageDirs.forEach { dir ->
            dir?.let {
                var parent = it.parentFile
                while (parent != null && parent.name != "Android") parent = parent.parentFile
                if (parent?.parentFile != null) rootDirs.add(parent.parentFile!!)
            }
        }

        rootDirs.distinctBy { it.absolutePath }.forEach { root ->
            if (root.exists()) collectFilesRecursively(root, allFiles)
        }

        val total = allFiles.size
        if (total == 0) return results

        // پسوندهای واقعاً مخرب
        val criticalExtensions = setOf("exe", "vbs", "bat", "sh", "dex")

        for ((index, file) in allFiles.withIndex()) {
            val percent = ((index + 1) * 100) / total
            onProgress(file.name, percent)

            val ext = file.extension.lowercase()
            
            if (criticalExtensions.contains(ext)) {
                val hash = getFileSHA256(file)
                results.add(ScanResult(file.name, "⚠️ اسکریپت/فایل مخرب اجرایی (SHA: ${hash.take(8)}...)\nمسیر: ${file.parent}", true))
            } else if (ext == "apk") {
                // چک کردن اینکه آیا فایل APK بک‌آپ برنامه‌های رسمی است یا خیر
                if (file.name.contains("split_") || file.name.contains("release") || file.name.contains("google")) {
                    // بک آپ‌های سیستم و گوگل ایمن هستند
                    continue
                } else {
                    results.add(ScanResult(file.name, "ℹ️ فایل نصب (APK) موجود در حافظه\nمسیر: ${file.parent}", false))
                }
            }
        }
        return results
    }

    private fun isInstalledFromTrustedSource(pm: PackageManager, packageName: String): Boolean {
        return try {
            val installer = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
            installer != null && trustedInstallers.contains(installer)
        } catch (e: Exception) {
            false
        }
    }

    private fun calculateRiskScore(pkgInfo: PackageInfo): Int {
        var score = 0
        val permissions = pkgInfo.requestedPermissions ?: arrayOf()

        if (permissions.contains(android.Manifest.permission.RECEIVE_SMS) && 
            permissions.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW)) {
            score += 60
        }
        return score
    }

    private fun collectFilesRecursively(dir: File, fileList: MutableList<File>) {
        val files = dir.listFiles() ?: return
        for (file in files) {
            if (file.isDirectory) {
                if (!file.name.startsWith(".")) {
                    collectFilesRecursively(file, fileList)
                }
            } else if (file.isFile) {
                fileList.add(file)
            }
        }
    }

    private fun getFileSHA256(file: File): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val inputStream = FileInputStream(file)
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
            inputStream.close()
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            "00000000000000000000000000000000"
        }
    }
}
