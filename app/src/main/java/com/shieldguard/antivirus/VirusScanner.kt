package com.shieldguard.antivirus

import android.content.Context
import android.content.pm.PackageManager
import java.io.File
import java.security.MessageDigest

data class ScanResult(
    val name: String,
    val pathOrPackage: String,
    val isMalicious: Boolean,
    val reason: String
)

class VirusScanner(private val context: Context) {

    private val knownMalwareHashes = setOf(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    fun scanInstalledApps(): List<ScanResult> {
        val results = mutableListOf<ScanResult>()
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        for (pkg in packages) {
            val appName = pkg.applicationInfo.loadLabel(pm).toString()
            val requestedPermissions = pkg.requestedPermissions

            var isDangerous = false
            var reason = "برنامه ایمن است"

            if (requestedPermissions != null) {
                val hasSms = requestedPermissions.contains("android.permission.RECEIVE_SMS")
                val hasOverlay = requestedPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW")

                if (hasSms && hasOverlay) {
                    isDangerous = true
                    reason = "دسترسی همزمان مشکوک به پیامک و نمایش روی سایر برنامه‌ها"
                }
            }

            results.add(ScanResult(appName, pkg.packageName, isDangerous, reason))
        }
        return results
    }

    fun scanFile(file: File): ScanResult {
        if (!file.exists() || file.isDirectory) {
            return ScanResult(file.name, file.absolutePath, false, "فایل نامعتبر")
        }

        val hash = calculateSHA256(file)
        val isMalicious = knownMalwareHashes.contains(hash)
        val reason = if (isMalicious) "شناسایی فایل مخرب مطابقت داده شده" else "فایل پاک است"

        return ScanResult(file.name, file.absolutePath, isMalicious, reason)
    }

    private fun calculateSHA256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { inputStream ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
