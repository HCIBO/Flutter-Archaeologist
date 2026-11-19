package com.archaeologist.archaeologist_demo

import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "com.archaeologist.demo/security")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "deviceStatus" -> result.success(
                        mapOf(
                            "rooted" to isRooted(),
                            "debugger" to Debug.isDebuggerConnected(),
                            "adb" to (Settings.Global.getInt(contentResolver, "adb_enabled", 0) == 1),
                            "developerOptions" to (Settings.Global.getInt(contentResolver, "development_settings_enabled", 0) == 1),
                            "emulator" to isEmulator(),
                        )
                    )
                    else -> result.notImplemented()
                }
            }
    }

    private fun isRooted(): Boolean {
        val paths = listOf("/system/xbin/su", "/system/bin/su", "/sbin/su", "/system/app/Superuser.apk", "/data/local/xbin/su")
        if (paths.any { File(it).exists() }) return true
        if (Build.TAGS?.contains("test-keys") == true) return true
        return try {
            Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su")).inputStream.bufferedReader().readLine() != null
        } catch (e: Exception) {
            false
        }
    }

    private fun isEmulator(): Boolean =
        Build.FINGERPRINT.startsWith("generic") || Build.HARDWARE.contains("goldfish") ||
            Build.HARDWARE.contains("ranchu") || Build.MODEL.contains("google_sdk") ||
            Build.PRODUCT.contains("sdk_gphone") || File("/dev/qemu_pipe").exists()
}
