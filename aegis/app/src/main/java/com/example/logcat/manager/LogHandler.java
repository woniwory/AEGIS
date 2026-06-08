package com.example.logcat.manager;

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;
import android.util.Log;

import com.example.logcat.queue.OfflineLogDatabase;
import com.example.logcat.queue.UploadQueueWorker;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * 로그 파일 관리자.
 * - 로그 항목을 AES-256-GCM(CryptoManager)으로 암호화하여 저장
 * - 각 항목 기록 시 ForwardHashChain으로 H_i = SHA-256(M_i || H_{i-1}) 갱신
 * - 파일 크기 초과/긴급 이벤트 시 ServerTransmitter로 전송
 */
public class LogHandler {

    private static final String TAG = "LogFileManager";
    private static final long MAX_LOG_FILE_SIZE = 512 * 1024; // 512 KB

    private final String filename;
    private final String directoryName;
    private final String hashFileName;
    private final ContentResolver contentResolver;
    private final Context context;
    private File logFile;
    private File hashFile;
    private File internalDir;
    private final String androidID;
    private final ServerTransmitter serverTransmitter;

    // 전방향 안전 해시 체인 (이 LogHandler 인스턴스 전용)
    private final ForwardHashChain hashChain;

    // 업로드 직렬화 큐 — 동시 다수 업로드로 인한 서버 timeout 방지
    private static final ExecutorService uploadExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "aegis-upload");
        t.setDaemon(true);
        return t;
    });

    private final Map<String, File> logFiles = new HashMap<>();
    private final Map<String, File> hashFiles = new HashMap<>();
    private final List<String> logFileNames = new ArrayList<>();
    private final List<String> hashFileNames = new ArrayList<>();

    public LogHandler(Context context, ServerTransmitter serverTransmitter, String filename) {
        this.context = context;
        this.contentResolver = context.getContentResolver();
        this.serverTransmitter = serverTransmitter;

        androidID = getAndroidID(context, contentResolver);
        this.filename = androidID + "_" + filename;
        this.directoryName = filename.replace(".txt", "");
        this.hashFileName = androidID + "_" + directoryName + "_hash.txt";

        // 로그 타입별 전방향 해시 체인 초기화
        this.hashChain = new ForwardHashChain(context, directoryName);

        logFileNames.add(androidID + "_AntiForensicLog.txt");
        logFileNames.add(androidID + "_AppExecutionLog.txt");
        logFileNames.add(androidID + "_BluetoothLog.txt");
        logFileNames.add(androidID + "_CallingLog.txt");
        logFileNames.add(androidID + "_MessageLog.txt");
        logFileNames.add(androidID + "_FileLog.txt");

        hashFileNames.add(androidID + "_AntiForensicLog_hash.txt");
        hashFileNames.add(androidID + "_AppExecutionLog_hash.txt");
        hashFileNames.add(androidID + "_BluetoothLog_hash.txt");
        hashFileNames.add(androidID + "_CallingLog_hash.txt");
        hashFileNames.add(androidID + "_MessageLog_hash.txt");
        hashFileNames.add(androidID + "_FileLog_hash.txt");
    }

    public static String getAndroidID(Context context, ContentResolver contentResolver) {
        return Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID);
    }

    /**
     * 서버 타임스탬프 획득 — 오프셋 방식으로 온/오프라인 통합.
     * 네트워크 호출 없이 elapsedRealtime + offset 으로 계산.
     * 최초 동기화 또는 재부팅 시에만 서버 fetch 발생.
     */
    public static String resolveServerTimestamp(Context context) {
        // 1. SharedPreferences 캐시 기반으로 로컬 추정 시간 계산 (네트워크 호출을 원천 차단하여 ANR 방지)
        String estimated = ServerTransmitter.getEstimatedServerTimestamp(context);
        if (estimated != null) {
            return estimated;
        }

        // 2. 캐시가 없는 최초 구동 시점에만 온라인인 경우 1회 동기화 시도
        if (ServerTransmitter.isNetworkAvailable(context)) {
            String ts = ServerTransmitter.getServerTimestamp();
            if (ts != null) {
                ServerTransmitter.saveServerTimestampCache(context, ts);
                return ts;
            }
        }
        return null;
    }

    public void initializeLogFile() {
        internalDir = new File(context.getFilesDir(), directoryName);
        if (internalDir.exists()) {
            applyWritableToDirectory(internalDir);
        } else if (!internalDir.mkdirs()) {
            Log.e(TAG, "Failed to create log directory: " + internalDir.getAbsolutePath());
            return;
        }
        logFile = new File(internalDir, filename);
        hashFile = new File(internalDir, hashFileName);
        createFileIfAbsent(logFile);
        createFileIfAbsent(hashFile);

        logFiles.put(filename, logFile);
        hashFiles.put(hashFileName, hashFile);

        applyReadOnly(logFile);
        applyReadOnly(hashFile);
        applyReadOnlyToDirectory(internalDir);
    }

    private void createFileIfAbsent(File f) {
        try {
            if (f.createNewFile()) {
                Log.d(TAG, "Created: " + f.getAbsolutePath());
            }
        } catch (IOException e) {
            Log.e(TAG, "File create error: " + e.getMessage());
        }
    }

    /**
     * 로그 메시지를 파일에 기록.
     * 메시지는 CryptoManager로 암호화 후 저장하고,
     * ForwardHashChain으로 체인 해시를 갱신하여 hash file에 기록.
     */
    public void appendToLogFile(String message) {
        applyWritableToDirectory(internalDir);
        applyWritable(logFile);

        try {
            // 1. AES-256-GCM 암호화 (at-rest)
            String encryptedLine = CryptoManager.getInstance().encryptString(message) + "\n";

            // 2. 파일 쓰기
            try (FileOutputStream fos = new FileOutputStream(logFile, true)) {
                fos.write(encryptedLine.getBytes(StandardCharsets.UTF_8));
            }

            // 3. 전방향 해시 체인 갱신: H_i = SHA-256(M_i || H_{i-1})
            String newChainHash = hashChain.advance(message);
            updateHashFile(newChainHash);

            // 4. 오프라인 상태면 WorkManager 플러시 예약 (온라인 복구 시 .txt 전송)
            if (!ServerTransmitter.isNetworkAvailable(context)) {
                Log.d(TAG, "[OFFLINE] 오프라인 감지 → scheduleFlush 등록: " + directoryName);
                UploadQueueWorker.scheduleFlush(context);
            } else {
                Log.d(TAG, "[ONLINE] 온라인 상태로 기록: " + directoryName);
            }

            Log.d(TAG, "Logged & chained: " + directoryName);
        } catch (IOException e) {
            Log.e(TAG, "appendToLogFile error: " + e.getMessage());
        } finally {
            applyReadOnly(logFile);
            applyReadOnlyToDirectory(internalDir);
        }
    }

    public Path getLogFilePath() {
        return Path.of(logFile.getAbsolutePath());
    }

    public String getFilename() {
        return filename;
    }

    public String getCurrentChainHash() {
        return hashChain.getCurrentHash();
    }

    /** 온라인 전송 성공 후 .txt 파일을 비운다. 해시 체인은 유지. */
    public void clearLogFile() {
        applyWritableToDirectory(internalDir);
        applyWritable(logFile);
        try (FileOutputStream fos = new FileOutputStream(logFile, false)) {
            // 빈 내용으로 덮어씀
        } catch (IOException e) {
            Log.e(TAG, "clearLogFile error: " + e.getMessage());
        } finally {
            applyReadOnly(logFile);
            applyReadOnlyToDirectory(internalDir);
        }
    }

    /**
     * 온라인 복구 시 WorkManager에서 호출: 모든 로그 타입의 .txt 파일에 쌓인 내용을 서버로 전송.
     * 큐 플러시 이후에 실행되어, 512KB 트리거 없이 오프라인에서 쌓인 .txt를 처리.
     */
    /**
     * @return 하나 이상 실패 시 true (Worker가 retry 해야 함)
     */
    public static boolean sendAllPendingTxt(Context context, ServerTransmitter serverTransmitter) {
        String deviceId = getAndroidID(context, context.getContentResolver());
        String[] logTypes = {"AntiForensicLog", "CallingLog", "BluetoothLog",
                "MessageLog", "FileLog", "AppExecutionLog"};
        CryptoManager crypto = CryptoManager.getInstance();
        boolean anyFailed = false;

        String transmissionTs = ServerTransmitter.resolveServerTimestamp(context);
        if (transmissionTs != null) {
            Log.d(TAG, "[sendAllPendingTxt] transmissionTimestamp: " + transmissionTs);
        }

        for (String logType : logTypes) {
            File dir = new File(context.getFilesDir(), logType);
            File logFile = new File(dir, deviceId + "_" + logType + ".txt");
            if (!logFile.exists() || logFile.length() == 0) continue;

            Log.d(TAG, "[sendAllPendingTxt] 확인: " + logType + " — 크기=" + logFile.length() + "bytes");
            try {
                dir.setWritable(true, false);
                dir.setExecutable(true, false);
                logFile.setWritable(true, false);

                byte[] raw = java.nio.file.Files.readAllBytes(logFile.toPath());
                String rawText = new String(raw, java.nio.charset.StandardCharsets.UTF_8);

                StringBuilder sb = new StringBuilder();
                for (String line : rawText.split("\n")) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()) continue;
                    try {
                        sb.append(crypto.decryptToString(trimmed)).append("\n");
                    } catch (Exception ex) {
                        sb.append(trimmed).append("\n");
                    }
                }
                String logContent = sb.toString().trim();
                if (logContent.isEmpty()) continue;

                // 해시 계산
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                String normalized = String.join("\n", logContent.split("\\r?\n"));
                byte[] hashBytes = md.digest(normalized.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                StringBuilder hashSb = new StringBuilder();
                for (byte b : hashBytes) hashSb.append(String.format("%02x", b));
                String hash = hashSb.toString();

                if (transmissionTs != null) {
                    StringBuilder tempSb = new StringBuilder();
                    String[] contentLines = logContent.split("\\r?\\n");
                    for (int i = 0; i < contentLines.length; i++) {
                        String lineStr = contentLines[i];
                        if (lineStr.trim().isEmpty()) continue;
                        tempSb.append(lineStr).append(" ; transmissionTimestamp: ").append(transmissionTs);
                        if (i < contentLines.length - 1) {
                            tempSb.append("\n");
                        }
                    }
                    logContent = tempSb.toString();
                    normalized = String.join("\n", logContent.split("\\r?\\n"));
                    hashBytes = md.digest(normalized.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    hashSb = new StringBuilder();
                    for (byte b : hashBytes) hashSb.append(String.format("%02x", b));
                    hash = hashSb.toString();
                }

                Log.d(TAG, "[ONLINE] 네트워크 복구 후 .txt 전송: " + logType);
                boolean sent = serverTransmitter.uploadEncryptedLog(deviceId, logType, logContent, hash);
                if (sent) {
                    clearLogFileStatic(context, deviceId, logType);
                    Log.d(TAG, "[ONLINE] .txt 전송 성공: " + logType);
                } else {
                    // 전송 실패 → SQLCipher 큐에 보관 후 .txt 비움 (WorkManager가 재시도)
                    Log.w(TAG, "[ONLINE→OFFLINE] .txt 전송 실패, 큐에 보관: " + logType);
                    serverTransmitter.queueOffline(deviceId, logType, logContent, hash);
                    clearLogFileStatic(context, deviceId, logType);
                    anyFailed = true;
                }
            } catch (Exception e) {
                Log.e(TAG, "sendAllPendingTxt error: " + logType, e);
                anyFailed = true;
            }
        }
        return anyFailed;
    }

    /**
     * WorkManager에서 로거 인스턴스 없이 호출하는 정적 버전.
     * logType: "AntiForensicLog", "CallingLog" 등 (확장자 없이)
     */
    public static void clearLogFileStatic(Context context, String deviceId, String logType) {
        File dir = new File(context.getFilesDir(), logType);
        File logFile = new File(dir, deviceId + "_" + logType + ".txt");
        if (!logFile.exists()) return;
        if (dir.exists()) {
            dir.setWritable(true, false);
            dir.setExecutable(true, false);
        }
        logFile.setWritable(true, false);
        try (FileOutputStream fos = new FileOutputStream(logFile, false)) {
            // 빈 내용으로 덮어씀
        } catch (IOException e) {
            Log.e(TAG, "clearLogFileStatic error: " + e.getMessage());
        } finally {
            logFile.setWritable(false, false);
            if (dir.exists()) dir.setWritable(false, false);
        }
        Log.d(TAG, "Cleared .txt after offline flush: " + logType);
    }

    public void updateHashFile(String hash) {
        applyWritableToDirectory(internalDir);
        applyWritable(hashFile);
        try (FileOutputStream fos = new FileOutputStream(hashFile, false)) {
            fos.write((hash + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            Log.e(TAG, "Hash file write error: " + e.getMessage());
        } finally {
            applyReadOnly(hashFile);
            applyReadOnlyToDirectory(internalDir);
        }
    }

    public void checkFileSizeAndHandle(String fileName) {
        File lf = logFiles.get(fileName);
        if (lf != null && lf.length() >= MAX_LOG_FILE_SIZE) {
            Log.d(TAG, fileName + " exceeded 512KB, triggering send...");
            uploadExecutor.submit(() -> triggerSendFile(fileName));
        }
    }

    private void createNewFile(String fileName, String hashFileName) {
        String logName = extractLogName(fileName);
        File targetDir = new File(internalDir.getParent(), logName);
        applyWritableToDirectory(targetDir);
        if (!targetDir.exists()) targetDir.mkdirs();
        File newLog = new File(targetDir, fileName);
        File newHash = new File(targetDir, hashFileName);
        createFileIfAbsent(newLog);
        createFileIfAbsent(newHash);
        applyReadOnly(newLog);
        applyReadOnly(newHash);
        applyReadOnlyToDirectory(targetDir);
        if (fileName.equals(this.filename)) {
            this.logFile = newLog;
            this.hashFile = newHash;
            hashChain.reset();
        }
    }

    /**
     * 단일 로그 파일에 대한 트리거 전송.
     * 온라인 → 전송 시도 → 실패 시 오프라인 큐
     * 오프라인 → 즉시 오프라인 큐
     * 어떤 경우든 .txt는 초기화됨.
     */
    private void triggerSendFile(String logFileName) {
        String logFilePath = internalDir.getParent() + "/" + extractLogName(logFileName);
        File lf = new File(logFilePath, logFileName);
        if (!lf.exists() || lf.length() == 0) return;

        String logContent = readAndDecryptContent(lf);
        if (logContent == null || logContent.isEmpty()) return;

        String contentHash = computeContentHash(logContent);
        String logType = extractLogName(logFileName);
        String hashFn = logFileName.replace(".txt", "_hash.txt");

        boolean isOnline = ServerTransmitter.isNetworkAvailable(context);
        if (isOnline) {
            Log.d(TAG, "[ONLINE] 전송 시도: " + logType);
            boolean sent = serverTransmitter.uploadEncryptedLog(androidID, logType, logContent, contentHash);
            if (sent) {
                Log.d(TAG, "[ONLINE] 전송 성공: " + logType);
            } else {
                Log.w(TAG, "[ONLINE→OFFLINE] 전송 실패, 오프라인 큐 저장: " + logType);
                serverTransmitter.queueOffline(androidID, logType, logContent, contentHash);
                UploadQueueWorker.scheduleFlush(context);
            }
        } else {
            Log.d(TAG, "[OFFLINE] 오프라인 큐 저장: " + logType);
            serverTransmitter.queueOffline(androidID, logType, logContent, contentHash);
            UploadQueueWorker.scheduleFlush(context);
        }

        // 온/오프라인 무관하게 .txt 초기화 (큐 or 서버로 넘겼으므로)
        deleteLogFiles(logFileName);
        deleteHashFiles(hashFn);
        createNewFile(logFileName, hashFn);
    }

    /** 로그 파일을 읽어 각 줄을 복호화한 평문 전체를 반환. */
    private String readAndDecryptContent(File logFile) {
        try {
            applyWritableToDirectory(logFile.getParentFile());
            applyWritable(logFile);
            byte[] raw = java.nio.file.Files.readAllBytes(logFile.toPath());
            applyReadOnly(logFile);
            applyReadOnlyToDirectory(logFile.getParentFile());

            String rawText = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
            CryptoManager crypto = CryptoManager.getInstance();
            StringBuilder sb = new StringBuilder();
            for (String line : rawText.split("\n")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) continue;
                try {
                    sb.append(crypto.decryptToString(trimmed)).append("\n");
                } catch (Exception ex) {
                    sb.append(trimmed).append("\n");
                }
            }
            return sb.toString().trim();
        } catch (Exception e) {
            Log.e(TAG, "readAndDecryptContent error", e);
            return null;
        }
    }

    /** logContent 문자열의 SHA-256 hex 해시 계산. */
    private String computeContentHash(String logContent) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            String normalized = String.join("\n",
                    java.util.Arrays.stream(logContent.split("\\r?\n"))
                            .collect(java.util.stream.Collectors.toList()));
            byte[] hashBytes = md.digest(normalized.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            Log.e(TAG, "SHA-256 not available", e);
            return "";
        }
    }

    /**
     * 512KB 초과 시 해당 파일만 트리거.
     */
    public void handleFileSizeEvents(String eventType, String logFileName, String hashFileName) {
        Log.d(TAG, "File size event: " + eventType);
        uploadExecutor.submit(() -> triggerSendFile(logFileName));
    }

    /**
     * logcat -c 감지, Shutdown, Reboot 발생 시 모든 파일 즉시 처리.
     */
    public void handleCriticalEvents(String eventType) {
        Log.d(TAG, "Critical event: " + eventType + " — " + logFileNames.size() + "개 파일 순차 전송 큐 등록");
        List<Future<?>> futures = new ArrayList<>();
        for (String fileName : logFileNames) {
            futures.add(uploadExecutor.submit(() -> triggerSendFile(fileName)));
        }
        // 모든 전송 완료까지 최대 120초 대기 (순차 처리이므로 파일당 ~20초 × 6개)
        for (Future<?> f : futures) {
            try {
                f.get(120, TimeUnit.SECONDS);
            } catch (Exception e) {
                Log.w(TAG, "Critical event 전송 대기 중 예외: " + e.getMessage());
            }
        }
        Log.d(TAG, "Critical event 처리 완료: " + eventType);
    }

    public synchronized void deleteLogFiles(String fileName) {
        File lf = new File(internalDir.getParent() + "/" + extractLogName(fileName), fileName);
        applyWritableToDirectory(lf.getParentFile());
        applyWritable(lf);
        if (lf.exists() && lf.delete()) {
            Log.d(TAG, "Deleted log: " + fileName);
        }
        applyReadOnlyToDirectory(lf.getParentFile());
    }

    public synchronized void deleteHashFiles(String fileName) {
        File hf = new File(internalDir.getParent() + "/" + extractHashName(fileName), fileName);
        applyWritableToDirectory(hf.getParentFile());
        applyWritable(hf);
        if (hf.exists() && hf.delete()) {
            Log.d(TAG, "Deleted hash: " + fileName);
        }
        applyReadOnlyToDirectory(hf.getParentFile());
    }

    private void applyReadOnly(File file) {
        if (file.exists()) {
            file.setReadable(true, false);
            file.setWritable(false, false);
            file.setExecutable(false, false);
        }
    }

    private void applyWritable(File file) {
        if (file.exists()) file.setWritable(true, false);
    }

    private void applyReadOnlyToDirectory(File directory) {
        if (directory != null && directory.exists()) {
            directory.setReadable(true, false);
            directory.setWritable(false, false);
            directory.setExecutable(true, false);
        }
    }

    private void applyWritableToDirectory(File directory) {
        if (directory != null && directory.exists()) {
            directory.setReadable(true, false);
            directory.setWritable(true, false);
            directory.setExecutable(true, false);
        }
    }

    private String extractLogName(String fileName) {
        if (fileName == null) return "";
        int dot = fileName.lastIndexOf(".");
        if (dot > 0) fileName = fileName.substring(0, dot);
        int us = fileName.indexOf("_");
        return us != -1 ? fileName.substring(us + 1) : fileName;
    }

    private String extractHashName(String fileName) {
        if (fileName == null) return "";
        int dot = fileName.lastIndexOf(".");
        if (dot > 0) fileName = fileName.substring(0, dot);
        String[] tokens = fileName.split("_");
        return tokens.length >= 2 ? tokens[1] : fileName;
    }
}
