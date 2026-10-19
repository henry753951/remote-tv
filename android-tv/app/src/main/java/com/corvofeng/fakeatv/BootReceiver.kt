package com.corvofeng.fakeatv

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

class BootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val allowed = setOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED, Intent.ACTION_USER_PRESENT,
            "android.intent.action.QUICKBOOT_POWERON", "com.htc.intent.action.QUICKBOOT_POWERON",
            "com.dangbei.action.WAKEUP", "com.mstar.android.intent.action.SUSPEND_RESUME",
            "com.droidlogic.intent.action.STANDBY_WAKEUP")
        if (action !in allowed) return
        Log.i(TAG, "onReceive broadcast: $action")

        if (action == AtvService.ACTION_SET_MENU_BINDING) {
            val btn = intent.getStringExtra(AtvService.EXTRA_BUTTON)
                ?: intent.getStringExtra("button")
                ?: "none"
            val lower = btn.lowercase().trim()
            DeviceInfo.setMenuButtonBinding(context, lower)
            RemoteController.menuBindingButton = lower
            AtvAccessibilityService.instance?.menuBindingButton = lower
            Log.i(TAG, "Menu binding updated via BootReceiver: $lower")
            return
        }

        val deviceName = DeviceInfo.getDeviceName(context)
        val serviceIntent = Intent(context, AtvService::class.java).apply {
            this.action = AtvService.ACTION_START
            putExtra(AtvService.EXTRA_NAME, deviceName)
            putExtra(AtvService.EXTRA_PIN, DeviceInfo.getPairingPin(context))
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
            Log.i(TAG, "AtvService started successfully from boot broadcast: $action")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start AtvService on broadcast ($action)", e)
        }
    }
}
