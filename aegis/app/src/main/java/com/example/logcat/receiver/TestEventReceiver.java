package com.example.logcat.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.example.logcat.manager.LogHandler;
import com.example.logcat.manager.ServerTransmitter;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * 에뮬레이터 테스트용 이벤트 주입 수신기.
 * BluetoothLog / AppExecutionLog를 adb broadcast로 트리거.
 */
public class TestEventReceiver extends BroadcastReceiver {

    public static final String ACTION_APP_EXECUTION = "com.example.logcat.INJECT_APP_EXECUTION";
    public static final String ACTION_BLUETOOTH     = "com.example.logcat.INJECT_BLUETOOTH";
    private static final String TAG = "TestEventReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (action == null) return;

        if (ACTION_APP_EXECUTION.equals(action)) {
            injectInBackground(context, "AppExecutionLog.txt", new String[]{
                    " Foreground App: com.android.settings",
                    " Background App: com.example.logcat",
                    " Foreground App: com.example.logcat",
                    " Text: Settings",
                    " Content Description: Settings menu",
                    " Class Name: android.widget.TextView",
                    " Clickable: true, Enabled: true, Focusable: true"
            });
        } else if (ACTION_BLUETOOTH.equals(action)) {
            injectInBackground(context, "BluetoothLog.txt", new String[]{
                    " Bluetooth connected to: AEGIS-TestDevice [AA:BB:CC:DD:EE:FF]",
                    " A2DP streaming started on device: AEGIS-TestDevice",
                    " A2DP streaming stopped on device: AEGIS-TestDevice",
                    " Bluetooth disconnected from: AEGIS-TestDevice [AA:BB:CC:DD:EE:FF]"
            });
        }
    }

    private void injectInBackground(Context context, String filename, String[] messages) {
        new Thread(() -> {
            try {
                ServerTransmitter st = new ServerTransmitter(context);
                LogHandler lh = new LogHandler(context, st, filename);
                lh.initializeLogFile();

                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
                String serverTs = ServerTransmitter.resolveServerTimestamp(context);

                for (String msg : messages) {
                    String ts = sdf.format(new Date());
                    String line = ts + msg + " ; serverTimestamp: " + serverTs + "\n";
                    lh.appendToLogFile(line);
                    Thread.sleep(100);
                }
                Log.d(TAG, "Injected " + messages.length + " entries into " + filename);
            } catch (Exception e) {
                Log.e(TAG, "Injection failed for " + filename, e);
            }
        }).start();
    }
}
