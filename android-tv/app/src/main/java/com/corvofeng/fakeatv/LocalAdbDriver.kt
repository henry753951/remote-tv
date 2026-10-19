package com.corvofeng.fakeatv

import android.content.Context
import android.util.Log
import android.os.SystemClock
import android.view.KeyEvent
import dadb.AdbKeyPair
import dadb.AdbStream
import dadb.Dadb
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

object LocalAdbDriver {
    private const val TAG = "LocalAdbDriver"
    private const val ADB_HOST = "127.0.0.1"
    private const val ADB_PORT = 5555

    private val executor = Executors.newSingleThreadExecutor()
    private var appContext: Context? = null
    private var dadbInstance: Dadb? = null
    private var shellStream: AdbStream? = null
    private var replies: ArrayBlockingQueue<String>? = null

    val isConnected = AtomicBoolean(false)

    fun init(context: Context) {
        appContext = context.applicationContext
        initAsync()
    }

    fun initAsync(callback: ((Boolean) -> Unit)? = null) {
        executor.execute {
            val ok = connectInternal()
            callback?.invoke(ok)
        }
    }

    @Synchronized
    fun connectInternal(): Boolean {
        if (isConnected.get() && shellStream != null) {
            return true
        }
        closeInternal()
        try {
            Log.i(TAG, "Attempting to connect to local ADB at $ADB_HOST:$ADB_PORT...")
            val context = appContext ?: return false
            val d = run {
                val keyDir = File(context.filesDir, "adb")
                keyDir.mkdirs()
                val privFile = File(keyDir, "adbkey")
                val pubFile = File(keyDir, "adbkey.pub")
                if (!privFile.exists() || !pubFile.exists()) {
                    Log.i(TAG, "Generating internal ADB keypair at $keyDir...")
                    AdbKeyPair.generate(privFile, pubFile)
                }
                val keyPair = AdbKeyPair.read(privFile, pubFile)
                Dadb.create(ADB_HOST, ADB_PORT, keyPair)
            }

            dadbInstance = d
            val apk = context.applicationInfo.sourceDir.replace("'", "'\\''")
            val stream = d.open("shell:CLASSPATH='$apk' exec app_process /system/bin com.corvofeng.fakeatv.PersistentInput")
            shellStream = stream
            val responses = ArrayBlockingQueue<String>(1)
            replies = responses
            Thread {
                try {
                    while (true) {
                        val line = stream.source.readUtf8LineStrict(256)
                        if (!responses.offer(line)) break
                    }
                } catch (_: Exception) {
                    responses.offer("CLOSED")
                }
            }.apply { name = "AtvInputReplies"; isDaemon = true; start() }
            check(responses.poll(4, TimeUnit.SECONDS) == "READY") { "Input helper not ready" }
            isConnected.set(true)
            Log.i(TAG, "Persistent local ADB input ready")
            return true
        } catch (e: Exception) {
            Log.w(TAG, "Failed to connect to local ADB ($ADB_HOST:$ADB_PORT): ${e.message}")
            closeInternal()
            return false
        }
    }

    @Synchronized
    fun closeInternal() {
        try { shellStream?.close() } catch (_: Exception) {}
        try { dadbInstance?.close() } catch (_: Exception) {}
        shellStream = null
        replies = null
        dadbInstance = null
        isConnected.set(false)
    }

    private val KEY_MAP = mapOf(
        "up" to KeyEvent.KEYCODE_DPAD_UP,
        "down" to KeyEvent.KEYCODE_DPAD_DOWN,
        "left" to KeyEvent.KEYCODE_DPAD_LEFT,
        "right" to KeyEvent.KEYCODE_DPAD_RIGHT,
        "select" to KeyEvent.KEYCODE_DPAD_CENTER,
        "menu" to KeyEvent.KEYCODE_BACK,
        "home" to KeyEvent.KEYCODE_HOME,
        "play_pause" to KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE,
        "volume_up" to KeyEvent.KEYCODE_VOLUME_UP,
        "volume_down" to KeyEvent.KEYCODE_VOLUME_DOWN,
        "mute" to KeyEvent.KEYCODE_VOLUME_MUTE,
        "power" to KeyEvent.KEYCODE_POWER,
        "sleep" to KeyEvent.KEYCODE_SLEEP,
        "wake" to KeyEvent.KEYCODE_WAKEUP,
        "channel_up" to KeyEvent.KEYCODE_CHANNEL_UP,
        "channel_down" to KeyEvent.KEYCODE_CHANNEL_DOWN,
        "guide" to KeyEvent.KEYCODE_GUIDE,
        "siri" to KeyEvent.KEYCODE_SEARCH
    )

    fun sendKey(buttonName: String, isMappedToMenu: Boolean = false): Boolean {
        val keycode = if (isMappedToMenu) {
            KeyEvent.KEYCODE_MENU
        } else {
            KEY_MAP[buttonName.lowercase()] ?: return false
        }

        if (!isConnected.get()) {
            initAsync()
            return false
        }

        return synchronized(this) {
            try {
                val stream = shellStream ?: return false
                val started = SystemClock.elapsedRealtime()
                stream.sink.writeInt(keycode).flush()
                check(replies?.poll(2, TimeUnit.SECONDS) == "OK $keycode") { "Input acknowledgement missing" }
                Log.d(TAG, "Input accepted: $buttonName in ${SystemClock.elapsedRealtime() - started} ms")
                true
            } catch (e: Exception) {
                Log.w(TAG, "Input failed: ${e.message}; reconnecting without replay")
                closeInternal()
                initAsync()
                false
            }
        }
    }
}
