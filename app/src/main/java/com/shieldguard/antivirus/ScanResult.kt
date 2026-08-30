package com.shieldguard.antivirus

data class ScanResult(
    val title: String,
    val description: String,
    val isDanger: Boolean
)
