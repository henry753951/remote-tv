package com.corvofeng.fakeatv

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val detail = intent?.getStringExtra(AtvService.EXTRA_EVENT_DETAIL).orEmpty()
            updateUi()
            if (detail.startsWith("Verified:") || detail.startsWith("SessionStarted:")) finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        KeyDispatcher.setMode(this, InjectionMode.ADB)
        findViewById<Button>(R.id.btnToggle).setOnClickListener { finish() }
        if (!AtvService.isRunning) {
            startForegroundService(Intent(this, AtvService::class.java).setAction(AtvService.ACTION_START))
        }
        findViewById<TextView>(R.id.tvPin).apply {
            alpha = 0f
            scaleX = 0.94f
            scaleY = 0.94f
            animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(240).start()
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(AtvService.BROADCAST_EVENT)
        androidx.core.content.ContextCompat.registerReceiver(this, receiver, filter,
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED)
        updateUi()
    }

    override fun onPause() {
        unregisterReceiver(receiver)
        super.onPause()
    }

    private fun updateUi() {
        findViewById<TextView>(R.id.tvPin).text = DeviceInfo.getPairingPin(this).toString().toCharArray().joinToString("  ")
        findViewById<TextView>(R.id.tvStatus).text = if (LocalAdbDriver.isConnected.get())
            getString(R.string.remote_ready, DeviceInfo.getDeviceName(this)) else
            getString(R.string.remote_authorize)
    }
}
