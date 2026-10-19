package com.corvofeng.fakeatv;

import android.os.SystemClock;
import android.view.InputDevice;
import android.view.InputEvent;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import java.io.DataInputStream;
import java.io.EOFException;
import java.lang.reflect.Method;

/** Runs as the already-authorized ADB shell; exits when its private stdin closes. */
public final class PersistentInput {
    static boolean allowed(int code) {
        switch (code) {
            case 0: case 3: case 4: case 19: case 20: case 21: case 22: case 23:
            case 24: case 25: case 26: case 82: case 84: case 85: case 164:
            case 166: case 167: case 172: case 223: case 224:
                return true;
            default:
                return false;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && "--self-test".equals(args[0])) {
            for (int code = -1; code <= 300; code++) {
                boolean expected = ("," + "0,3,4,19,20,21,22,23,24,25,26,82,84,85,164,166,167,172,223,224" + ",")
                        .contains("," + code + ",");
                if (allowed(code) != expected) throw new AssertionError(code);
            }
            System.out.println("SELFTEST OK");
            return;
        }
        Class<?> type = Class.forName("android.hardware.input.InputManager");
        Object manager = type.getDeclaredMethod("getInstance").invoke(null);
        Method inject = type.getMethod("injectInputEvent", InputEvent.class, int.class);
        DataInputStream input = new DataInputStream(System.in);
        System.out.println("READY");
        System.out.flush();
        while (true) {
            int code;
            try { code = input.readInt(); } catch (EOFException closed) { return; }
            if (!allowed(code)) throw new IllegalArgumentException("Unsupported key");
            if (code != 0) {
                long now = SystemClock.uptimeMillis();
                KeyEvent down = new KeyEvent(now, now, KeyEvent.ACTION_DOWN, code, 0, 0,
                        KeyCharacterMap.VIRTUAL_KEYBOARD, 0, 0, InputDevice.SOURCE_DPAD);
                // Wait for acceptance, not animation completion; keep down/up in order.
                if (!Boolean.TRUE.equals(inject.invoke(manager, down, 1)))
                    throw new IllegalStateException("Key down rejected");
                KeyEvent up = KeyEvent.changeAction(down, KeyEvent.ACTION_UP);
                if (!Boolean.TRUE.equals(inject.invoke(manager, up, 1)))
                    throw new IllegalStateException("Key up rejected");
            }
            System.out.println("OK " + code);
            System.out.flush();
        }
    }
}
