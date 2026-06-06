package com.example.logcat.manager;

import android.content.pm.ApplicationInfo;
import android.os.Debug;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileReader;

/**
 * 디버거 연결, Frida/Xposed 후킹 프레임워크 감지.
 * 감지 즉시 프로세스를 강제 종료하여 동적 분석을 차단.
 */
public class AntiTamperGuard {

    private static final String TAG = "AntiTamperGuard";

    private static final String[] FRIDA_ARTIFACTS = {
            "frida-agent",
            "frida-gadget",
            "frida_agent_main",
            "gum-js-loop",
            "gmain",
    };

    private static final String[] XPOSED_ARTIFACTS = {
            "XposedBridge",
            "de.robv.android.xposed",
    };

    /**
     * 앱 시작 시 반드시 호출. 위협 감지 시 즉시 종료.
     * @param appInfo ApplicationInfo (MainActivity에서 getApplicationInfo() 전달)
     */
    public static void checkAndTerminateIfCompromised(ApplicationInfo appInfo) {
        if (isDebuggerAttached()) {
            Log.e(TAG, "Debugger detected. Terminating.");
            terminateProcess();
        }
        if (isDebuggableBuild(appInfo)) {
            Log.e(TAG, "Debuggable flag set. Terminating.");
            terminateProcess();
        }
        if (isFridaPresent()) {
            Log.e(TAG, "Frida agent detected. Terminating.");
            terminateProcess();
        }
        if (isXposedPresent()) {
            Log.e(TAG, "Xposed framework detected. Terminating.");
            terminateProcess();
        }
    }

    private static boolean isDebuggerAttached() {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger();
    }

    private static boolean isDebuggableBuild(ApplicationInfo appInfo) {
        return (appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    private static boolean isFridaPresent() {
        // /proc/self/maps 에서 Frida 관련 artifact 검색
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                for (String artifact : FRIDA_ARTIFACTS) {
                    if (lower.contains(artifact)) {
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {
            // 읽기 실패는 무시
        }

        // Frida 기본 포트 27042 리스닝 여부 확인 (/proc/net/tcp)
        return isFridaPortOpen();
    }

    private static boolean isFridaPortOpen() {
        // 포트 27042 = 0x69C2 (little-endian hex in /proc/net/tcp)
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/net/tcp"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("69C2") || line.contains("69c2")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static boolean isXposedPresent() {
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = br.readLine()) != null) {
                for (String artifact : XPOSED_ARTIFACTS) {
                    if (line.contains(artifact)) {
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {
        }

        // Xposed 클래스 로딩 시도로 감지
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            if (cl != null) {
                cl.loadClass("de.robv.android.xposed.XposedBridge");
                return true;
            }
        } catch (ClassNotFoundException ignored) {
        }
        return false;
    }

    private static void terminateProcess() {
        android.os.Process.killProcess(android.os.Process.myPid());
        System.exit(1);
    }
}
