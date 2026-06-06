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

    public void initializeLogFile() {
        internalDir = new File(context.getFilesDir(), directoryName);
        if (!internalDir.exists() && !internalDir.mkdirs()) {
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
            Log.d(TAG, fileName + " exceeded 512KB, transmitting...");
            String hashFn = fileName.replace(".txt", "_hash.txt");
            handleFileSizeEvents(fileName + " exceeded 512KB", fileName, hashFn);
        }
    }

    private void createNewFile(String fileName, String hashFileName) {
        applyWritableToDirectory(internalDir);
        logFile = new File(internalDir, fileName);
        hashFile = new File(internalDir, hashFileName);
        createFileIfAbsent(logFile);
        createFileIfAbsent(hashFile);
        applyReadOnly(logFile);
        applyReadOnly(hashFile);
        applyReadOnlyToDirectory(internalDir);
        hashChain.reset();
    }

    /**
     * 512KB 초과 시 해당 파일만 전송.
     */
    public void handleFileSizeEvents(String eventType, String logFileName, String hashFileName) {
        Log.d(TAG, "File size event: " + eventType);
        if (serverTransmitter == null) return;

        CountDownLatch latch = new CountDownLatch(1);
        String logFilePath = internalDir.getParent() + "/" + extractLogName(logFileName);
        File lf = new File(logFilePath, logFileName);
        String expectedHash = logFileName.replace(".txt", "_hash.txt");
        String hashFilePath = internalDir.getParent() + "/" + extractHashName(expectedHash);
        File hf = new File(hashFilePath, expectedHash);

        if (lf.exists() && hf.exists()) {
            serverTransmitter.sendFilesAsync(lf, hf, new ServerTransmitter.FileTransferCallback() {
                @Override
                public void onSuccess() {
                    deleteLogFiles(logFileName);
                    deleteHashFiles(expectedHash);
                    createNewFile(logFileName, expectedHash);
                    latch.countDown();
                }
                @Override
                public void onFailure() {
                    latch.countDown();
                }
            });
        } else {
            latch.countDown();
        }
    }

    /**
     * logcat -c 감지, Shutdown, Reboot 발생 시 모든 파일 즉시 전송.
     */
    public void handleCriticalEvents(String eventType) {
        Log.d(TAG, "Critical event: " + eventType);
        if (serverTransmitter == null) return;

        CountDownLatch latch = new CountDownLatch(logFileNames.size());
        for (String fileName : logFileNames) {
            String logFilePath = internalDir.getParent() + "/" + extractLogName(fileName);
            File lf = new File(logFilePath, fileName);
            String expectedHash = fileName.replace(".txt", "_hash.txt");
            String hashFilePath = internalDir.getParent() + "/" + extractHashName(expectedHash);
            File hf = new File(hashFilePath, expectedHash);

            if (lf.exists() && hf.exists()) {
                serverTransmitter.sendFilesAsync(lf, hf, new ServerTransmitter.FileTransferCallback() {
                    @Override
                    public void onSuccess() {
                        deleteLogFiles(fileName);
                        deleteHashFiles(expectedHash);
                        createNewFile(fileName, expectedHash);
                        latch.countDown();
                    }
                    @Override
                    public void onFailure() {
                        latch.countDown();
                    }
                });
            } else {
                latch.countDown();
            }
        }
        try {
            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
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
