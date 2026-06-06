package com.example.logcat.queue;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Constraints;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import com.example.logcat.manager.CryptoManager;
import com.example.logcat.manager.ServerTransmitter;

import java.util.List;

/**
 * WorkManager Worker: 네트워크 복구 시 오프라인 큐를 서버로 플러시.
 * NetworkType.CONNECTED 제약으로 Wi-Fi/데이터 연결 시에만 실행.
 */
public class UploadQueueWorker extends Worker {

    private static final String TAG = "UploadQueueWorker";
    private static final int MAX_RETRIES = 5;

    public UploadQueueWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        Context ctx = getApplicationContext();
        OfflineLogDatabase db = OfflineLogDatabase.getInstance(ctx);
        OfflineLogDao dao = db.offlineLogDao();
        CryptoManager cm = CryptoManager.getInstance();
        ServerTransmitter transmitter = new ServerTransmitter(ctx);

        List<OfflineLogEntity> pending = dao.getAllPending();
        if (pending.isEmpty()) {
            Log.d(TAG, "No pending offline logs.");
            return Result.success();
        }

        Log.d(TAG, "Flushing " + pending.size() + " offline log(s)...");
        boolean anyFailed = false;

        for (OfflineLogEntity entry : pending) {
            if (entry.retryCount >= MAX_RETRIES) {
                Log.w(TAG, "Max retries exceeded for id=" + entry.id + ", dropping.");
                dao.deleteById(entry.id);
                continue;
            }
            try {
                // 복호화 후 서버 전송
                String logContent = cm.decryptToString(entry.encryptedLogContent);
                boolean success = transmitter.uploadEncryptedLog(
                        entry.deviceId, entry.logType, logContent, entry.chainHash);

                if (success) {
                    dao.deleteById(entry.id);
                    Log.d(TAG, "Flushed offline entry id=" + entry.id);
                } else {
                    dao.incrementRetry(entry.id);
                    anyFailed = true;
                }
            } catch (Exception e) {
                Log.e(TAG, "Failed to flush entry id=" + entry.id, e);
                dao.incrementRetry(entry.id);
                anyFailed = true;
            }
        }

        return anyFailed ? Result.retry() : Result.success();
    }

    /** 앱 시작/네트워크 복구 시 호출하여 플러시 작업 예약. */
    public static void scheduleFlush(Context ctx) {
        Constraints constraints = new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build();

        OneTimeWorkRequest request = new OneTimeWorkRequest.Builder(UploadQueueWorker.class)
                .setConstraints(constraints)
                .build();

        WorkManager.getInstance(ctx)
                .enqueueUniqueWork("aegis_offline_flush",
                        androidx.work.ExistingWorkPolicy.KEEP, request);

        Log.d(TAG, "Offline flush work scheduled.");
    }
}
