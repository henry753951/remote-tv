package com.corvofeng.fakeatv

import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Direct hardware remote controller simulator (Tier 1).
 *
 * Writes Linux input_event structs directly to the TV box's remote receiver
 * device node (/dev/input/event0, driver: fdd70030.pwm / gpio-keys/remotectl).
 * Key layout follows /vendor/usr/keylayout/fdd70030_pwm.kl.
 *
 * Provides:
 *  - 0-latency physical remote simulation
 *  - Universal compatibility across all TV apps, Leanback launchers, and video players
 *  - Bypasses Android framework when hardware permissions allow
 */
object RemoteController {
    private const val TAG = "RemoteController"
    private const val DEFAULT_EVENT_PATH = "/dev/input/event0"

    private const val EV_SYN = 0
    private const val EV_KEY = 1
    private const val SYN_REPORT = 0

    // Key codes matching /vendor/usr/keylayout/fdd70030_pwm.kl
    const val KEY_ENTER = 28
    const val KEY_HOME = 102
    const val KEY_UP = 103
    const val KEY_LEFT = 105
    const val KEY_RIGHT = 106
    const val KEY_DOWN = 108
    const val KEY_MUTE = 113
    const val KEY_VOLUMEDOWN = 114
    const val KEY_VOLUMEUP = 115
    const val KEY_POWER = 116
    const val KEY_MENU = 139
    const val KEY_BACK = 158
    const val KEY_PLAYPAUSE = 164
    const val KEY_SEARCH = 217

    private val KEY_MAP = mapOf(
        "up" to KEY_UP,
        "down" to KEY_DOWN,
        "left" to KEY_LEFT,
        "right" to KEY_RIGHT,
        "select" to KEY_ENTER,
        "menu" to KEY_BACK,
        "home" to KEY_HOME,
        "play_pause" to KEY_PLAYPAUSE,
        "volume_up" to KEY_VOLUMEUP,
        "volume_down" to KEY_VOLUMEDOWN,
        "mute" to KEY_MUTE,
        "power" to KEY_POWER,
        "siri" to KEY_SEARCH
    )

    private var outputStream: FileOutputStream? = null
    var isHardwareAvailable: Boolean = false
        private set

    init {
        initDevice()
    }

    fun initDevice(): Boolean {
        try {
            val file = File(DEFAULT_EVENT_PATH)
            if (file.exists() && file.canWrite()) {
                if (outputStream == null) {
                    outputStream = FileOutputStream(file)
                }
                isHardwareAvailable = true
                Log.i(TAG, "Hardware remote driver opened successfully: $DEFAULT_EVENT_PATH")
                return true
            } else {
                Log.d(TAG, "Cannot write to $DEFAULT_EVENT_PATH (exists=${file.exists()}, canWrite=${file.canWrite()})")
            }
        } catch (e: Exception) {
            Log.d(TAG, "Failed to open $DEFAULT_EVENT_PATH: ${e.message}")
        }
        isHardwareAvailable = false
        return false
    }

    @Volatile
    var menuBindingButton: String = "none"

    fun sendKey(name: String, isMappedToMenu: Boolean = false): Boolean {
        val lowerName = name.lowercase().trim()
        val mappedMenu = isMappedToMenu || (menuBindingButton.isNotBlank() &&
                menuBindingButton != "none" &&
                menuBindingButton.equals(lowerName, ignoreCase = true))

        val keyCode = if (mappedMenu) {
            KEY_MENU
        } else {
            KEY_MAP[lowerName]
        } ?: return false

        return sendHardwareKey(keyCode)
    }

    fun handleButton(name: String) {
        sendKey(name)
    }

    private fun sendHardwareKey(keyCode: Int): Boolean {
        synchronized(this) {
            if (outputStream == null && !initDevice()) {
                return false
            }
            try {
                val stream = outputStream ?: return false
                val buf = ByteBuffer.allocate(96).order(ByteOrder.LITTLE_ENDIAN)

                // 1. Key DOWN
                putEvent(buf, EV_KEY, keyCode, 1)
                putEvent(buf, EV_SYN, SYN_REPORT, 0)
                // 2. Key UP
                putEvent(buf, EV_KEY, keyCode, 0)
                putEvent(buf, EV_SYN, SYN_REPORT, 0)

                stream.write(buf.array())
                stream.flush()
                Log.d(TAG, "Hardware key written successfully: keyCode=$keyCode")
                return true
            } catch (e: Exception) {
                Log.w(TAG, "Error writing to hardware event device: ${e.message}")
                try { outputStream?.close() } catch (_: Exception) {}
                outputStream = null
                isHardwareAvailable = false
                return false
            }
        }
    }

    private fun putEvent(buf: ByteBuffer, type: Int, code: Int, value: Int) {
        // struct input_event on Linux 64-bit kernel:
        // struct timeval { long tv_sec; long tv_usec; } = 16 bytes
        // __u16 type = 2 bytes
        // __u16 code = 2 bytes
        // __s32 value = 4 bytes
        // Total = 24 bytes
        buf.putLong(0L) // tv_sec
        buf.putLong(0L) // tv_usec
        buf.putShort(type.toShort())
        buf.putShort(code.toShort())
        buf.putInt(value)
    }
}
