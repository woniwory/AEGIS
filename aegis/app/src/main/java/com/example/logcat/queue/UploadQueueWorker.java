package com.example.logcat.queue;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.BackoffPolicy;
import androidx.work.Constraints;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import com.example.logcat.manager.CryptoManager;
import com.example.logcat.manager.LogHandler;
import com.example.logcat.manager.ServerTransmitter;

import java.util.List;
import java.util.concurrent.TimeUnit;

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
        long totalBytes = dao.totalContentBytes();
        int runAttempt = getRunAttemptCount();

        Log.d(TAG, "══════════════════════════════════════");
        Log.d(TAG, "[FLUSH START] 실행 시작"
                + " | 큐=" + pending.size() + "개"
                + " | 용량=" + (totalBytes / 1024) + "KB"
                + " | 재시도=" + runAttempt + "회차");
        Log.d(TAG, "══════════════════════════════════════");

        boolean anyFailed = false;
        int successCount = 0, failCount = 0, skipCount = 0;

        for (OfflineLogEntity entry : pending) {
            if (entry.retryCount >= MAX_RETRIES) {
                Log.w(TAG, "[FLUSH] MAX_RETRIES(" + MAX_RETRIES + ") 초과 → 삭제:"
                        + " id=" + entry.id + " type=" + entry.logType
                        + " retry=" + entry.retryCount);
                dao.deleteById(entry.id);
                skipCount++;
                continue;
            }

            Log.d(TAG, "[FLUSH] 전송 시도: id=" + entry.id
                    + " type=" + entry.logType
                    + " retry=" + entry.retryCount + "/" + MAX_RETRIES);

            try {
                long decStart = System.currentTimeMillis();
                String logContent = cm.decryptToString(entry.encryptedLogContent);
                Log.d(TAG, "[FLUSH] 복호화 완료: " + (System.currentTimeMillis() - decStart) + "ms"
                        + " contentLen=" + logContent.length());

                String transmissionTs = ServerTransmitter.resolveServerTimestamp(ctx);
                if (transmissionTs != null) {
                    logContent = logContent + " ; transmissionTimestamp: " + transmissionTs;
                    Log.d(TAG, "[FLUSH] transmissionTimestamp 추가: " + transmissionTs);
                } else {
                    Log.w(TAG, "[FLUSH] transmissionTimestamp 없음 — 타임스탬프 없이 전송");
                }

                boolean success = transmitter.uploadEncryptedLog(
                        entry.deviceId, entry.logType, logContent, entry.chainHash);

                if (success) {
                    dao.deleteById(entry.id);
                    LogHandler.clearLogFileStatic(ctx, entry.deviceId, entry.logType);
                    successCount++;
                    Log.d(TAG, "[FLUSH] 전송 성공 → DB에서 삭제: id=" + entry.id + " type=" + entry.logType);
                } else {
                    dao.incrementRetry(entry.id);
                    anyFailed = true;
                    failCount++;
                    Log.w(TAG, "[FLUSH] 전송 실패: id=" + entry.id
                            + " type=" + entry.logType
                            + " retry=" + (entry.retryCount + 1) + "/" + MAX_RETRIES);
                }
            } catch (Exception e) {
                dao.incrementRetry(entry.id);
                anyFailed = true;
                failCount++;
                Log.e(TAG, "[FLUSH] 예외 발생: id=" + entry.id + " type=" + entry.logType, e);
            }
        }

        Log.d(TAG, "[FLUSH] 큐 처리 결과: 성공=" + successCount
                + " 실패=" + failCount + " 스킵=" + skipCount);

        Log.d(TAG, "[FLUSH] .txt 파일 스캔 시작 (오프라인 중 트리거 미발생 분)");
        boolean txtFailed = LogHandler.sendAllPendingTxt(ctx, transmitter);
        if (txtFailed) {
            Log.w(TAG, "[FLUSH] .txt 파일 전송 중 일부 실패");
        } else {
            Log.d(TAG, "[FLUSH] .txt 파일 전송 완료");
        }
        anyFailed = anyFailed || txtFailed;

        int remaining = dao.countPending();
        Log.d(TAG, "══════════════════════════════════════");
        Log.d(TAG, "[FLUSH END] 완료"
                + " | 결과=" + (anyFailed ? "일부실패→재시도예약" : "전체성공")
                + " | 잔여큐=" + remaining + "개");
        Log.d(TAG, "══════════════════════════════════════");

        return anyFailed ? Result.retry() : Result.success();
    }

    public static void scheduleFlush(Context ctx) {
        Constraints constraints = new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build();

        OneTimeWorkRequest request = new OneTimeWorkRequest.Builder(UploadQueueWorker.class)
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
                .build();

        WorkManager.getInstance(ctx)
                .enqueueUniqueWork("aegis_offline_flush",
                        androidx.work.ExistingWorkPolicy.KEEP, request);

        Log.d(TAG, "[SCHEDULE] 오프라인 플러시 작업 예약 완료 (KEEP 정책, 지수 백오프 1분~)");
    }
}
