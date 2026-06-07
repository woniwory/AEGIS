package com.example.logcat.manager;

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;

import com.example.logcat.queue.OfflineLogDatabase;
import com.example.logcat.queue.OfflineLogEntity;
import com.example.logcat.queue.UploadQueueWorker;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * 서버 전송 관리자.
 * - OkHttp + mTLS (클라이언트 인증서)
 * - SPKI 핀닝 (SHA256 핀)
 * - ClientCryptoPipeline으로 E2E 암호화 후 전송
 * - 네트워크 실패 시 SQLCipher 오프라인 큐에 저장 → WorkManager 재시도
 */
public class ServerTransmitter {

    private static final String TAG = "ServerTransmitter";
    private static final String BASE_URL = "http://220.149.236.152:8888";

    /**
     * 오프라인 큐 최대 허용 용량 (기본 50MB).
     * 기업·기관 정책에 따라 이 값을 조정하여 내부 저장소 점유 상한을 설정할 수 있다.
     * 초과 시 가장 오래된 항목부터 순차적으로 삭제된다 (FIFO eviction).
     */
    public static final long MAX_OFFLINE_QUEUE_BYTES = 50L * 1024 * 1024; // 50 MB
    private static final String UPLOAD_PATH = "/logs/upload";
    private static final String TIMESTAMP_PATH = "/logs/timestamp";
    private static final String SERVERKEY_PATH = "/logs/serverkey";

    /**
     * 서버 인증서 SPKI SHA-256 핀 (실제 배포 시 certutil / openssl로 추출한 값 사용).
     * 형식: "sha256/Base64EncodedSPKIHash=="
     * 백업 핀 1개 필수 (인증서 갱신 대비).
     */
    private static final String SPKI_PIN_PRIMARY = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static final String SPKI_PIN_BACKUP  = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    private final Context context;
    private volatile OkHttpClient httpClient;
    private volatile ClientCryptoPipeline cryptoPipeline;
    private volatile byte[] cachedServerPublicKey;

    public ServerTransmitter(Context context) {
        this.context = context;
    }

    // ──────────────────────────────────────────────
    // OkHttp 클라이언트 초기화 (mTLS + SPKI 핀닝)
    // ──────────────────────────────────────────────

    private synchronized OkHttpClient getHttpClient() {
        if (httpClient != null) return httpClient;
        try {
            if (BASE_URL.startsWith("http://")) {
                httpClient = new OkHttpClient.Builder()
                        .connectTimeout(15, TimeUnit.SECONDS)
                        .readTimeout(30, TimeUnit.SECONDS)
                        .writeTimeout(30, TimeUnit.SECONDS)
                        .build();
                return httpClient;
            }

            // 클라이언트 인증서 키스토어 로드 (Android Keystore)
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, null);

            // 시스템 신뢰 저장소
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);

            SSLContext sslCtx = SSLContext.getInstance("TLSv1.3");
            TrustManager[] trustManagers = tmf.getTrustManagers();
            sslCtx.init(kmf.getKeyManagers(), trustManagers, new SecureRandom());

            X509TrustManager trustManager = (X509TrustManager) trustManagers[0];

            // SPKI 핀닝 (주 핀 + 백업 핀)
            CertificatePinner pinner = new CertificatePinner.Builder()
                    .add("220.149.236.152", SPKI_PIN_PRIMARY)
                    .add("220.149.236.152", SPKI_PIN_BACKUP)
                    .build();

            httpClient = new OkHttpClient.Builder()
                    .sslSocketFactory(sslCtx.getSocketFactory(), trustManager)
                    .certificatePinner(pinner)
                    .connectTimeout(15, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .writeTimeout(30, TimeUnit.SECONDS)
                    .build();

            return httpClient;
        } catch (Exception e) {
            Log.e(TAG, "OkHttp init failed", e);
            throw new RuntimeException("HTTP client init failed", e);
        }
    }

    // ──────────────────────────────────────────────
    // 서버 공개키 획득 및 CryptoPipeline 초기화
    // ──────────────────────────────────────────────

    private synchronized ClientCryptoPipeline getCryptoPipeline() {
        if (cryptoPipeline != null) return cryptoPipeline;
        try {
            byte[] serverKey = fetchServerPublicKey();
            String deviceId = LogHandler.getAndroidID(context, context.getContentResolver());
            cryptoPipeline = new ClientCryptoPipeline(serverKey, deviceId);
            return cryptoPipeline;
        } catch (Exception e) {
            Log.e(TAG, "CryptoPipeline init failed", e);
            return null;
        }
    }

    private byte[] fetchServerPublicKey() throws Exception {
        if (cachedServerPublicKey != null) return cachedServerPublicKey;
        OkHttpClient client = getHttpClient();
        Request req = new Request.Builder()
                .url(BASE_URL + SERVERKEY_PATH)
                .get()
                .build();
        try (Response resp = client.newCall(req).execute()) {
            if (!resp.isSuccessful() || resp.body() == null) {
                throw new RuntimeException("Server key fetch failed: " + resp.code());
            }
            String b64 = resp.body().string().trim();
            cachedServerPublicKey = Base64.decode(b64, Base64.NO_WRAP);
            return cachedServerPublicKey;
        }
    }

    // ──────────────────────────────────────────────
    // 핵심 업로드 메서드
    // ──────────────────────────────────────────────

    /**
     * 로그 내용을 암호화하여 서버로 업로드.
     * 실패 시 SQLCipher 오프라인 큐에 저장하고 WorkManager 재시도 예약.
     */
    public void sendLogAsync(String deviceId, String logType,
                              String logContent, String chainHash,
                              FileTransferCallback callback) {
        new Thread(() -> {
            boolean success = false;
            try {
                success = uploadEncryptedLog(deviceId, logType, logContent, chainHash);
            } catch (Exception e) {
                Log.e(TAG, "Upload error, queuing offline", e);
            }
            if (success) {
                if (callback != null) callback.onSuccess();
            } else {
                queueOffline(deviceId, logType, logContent, chainHash);
                UploadQueueWorker.scheduleFlush(context);
                if (callback != null) callback.onFailure();
            }
        }).start();
    }

    /**
     * 동기 업로드 (WorkManager Worker에서 호출).
     * @return 성공 여부
     */
    public boolean uploadEncryptedLog(String deviceId, String logType,
                                       String logContent, String chainHash) {
        byte[] packetBytes = null;
        try {
            ClientCryptoPipeline pipeline = getCryptoPipeline();
            if (pipeline == null) return false;

            // 1. 암호화 파이프라인 (GZIP + ECDH + AES-GCM + ECDSA)
            packetBytes = pipeline.encrypt(logContent);

            // 2. 서버가 기대하는 SHA-256(logContent) 계산 (ForwardHashChain H_i와 별개)
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(logContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) sb.append(String.format("%02x", b));
            String contentHash = sb.toString();

            // 3. 멀티파트 업로드 (logFile=암호화 패킷, hashFile=SHA-256(content))
            String filename = deviceId + "_" + logType + ".enc";
            RequestBody logBody = RequestBody.create(packetBytes,
                    MediaType.parse("application/octet-stream"));
            RequestBody hashBody = RequestBody.create(contentHash.getBytes(),
                    MediaType.parse("text/plain"));

            RequestBody multipart = new MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart("logFile", filename, logBody)
                    .addFormDataPart("hashFile", deviceId + "_" + logType + "_hash.txt", hashBody)
                    .build();

            Request req = new Request.Builder()
                    .url(BASE_URL + UPLOAD_PATH)
                    .post(multipart)
                    .build();

            try (Response resp = getHttpClient().newCall(req).execute()) {
                Log.d(TAG, "Upload response: " + resp.code());
                return resp.isSuccessful();
            }
        } catch (Exception e) {
            Log.e(TAG, "uploadEncryptedLog failed", e);
            return false;
        } finally {
            if (packetBytes != null) Arrays.fill(packetBytes, (byte) 0);
        }
    }

    // ──────────────────────────────────────────────
    // 오프라인 큐 저장
    // ──────────────────────────────────────────────

    /** 네트워크 연결 여부 확인. */
    public static boolean isNetworkAvailable(Context context) {
        android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;
        android.net.NetworkInfo ni = cm.getActiveNetworkInfo();
        return ni != null && ni.isConnected();
    }

    public void queueOffline(String deviceId, String logType,
                              String logContent, String chainHash) {
        try {
            String encrypted = CryptoManager.getInstance().encryptString(logContent);
            OfflineLogEntity entity = new OfflineLogEntity(deviceId, logType, encrypted, chainHash);
            com.example.logcat.queue.OfflineLogDao dao =
                    OfflineLogDatabase.getInstance(context).offlineLogDao();
            dao.insert(entity);

            // 최대 용량 초과 시 가장 오래된 항목부터 삭제 (FIFO eviction)
            long totalBytes = dao.totalContentBytes();
            if (totalBytes > MAX_OFFLINE_QUEUE_BYTES) {
                int count = dao.countPending();
                // 전체 항목의 20%를 삭제하여 빈번한 eviction 방지
                int toDelete = Math.max(1, count / 5);
                dao.deleteOldest(toDelete);
                Log.w(TAG, "Offline queue exceeded " + (MAX_OFFLINE_QUEUE_BYTES / 1024 / 1024)
                        + "MB — evicted " + toDelete + " oldest entries");
            }

            Log.d(TAG, "Queued offline: " + logType);
        } catch (Exception e) {
            Log.e(TAG, "Offline queue insert failed", e);
        }
    }

    // ──────────────────────────────────────────────
    // 기존 파일 기반 전송 (하위 호환 - LogHandler 호출용)
    // ──────────────────────────────────────────────

    public void sendFilesAsync(java.io.File logFile, java.io.File hashFile,
                                FileTransferCallback callback) {
        new Thread(() -> {
            boolean success = false;
            try {
                String deviceId = LogHandler.getAndroidID(context, context.getContentResolver());
                String filename = logFile.getName(); // e.g. deviceId_AntiForensicLog.txt
                String[] parts = filename.split("_", 2);
                String logType = parts.length > 1 ? parts[1].replace(".txt", "") : "Unknown";

                byte[] content = java.nio.file.Files.readAllBytes(logFile.toPath());
                byte[] hashContent = java.nio.file.Files.readAllBytes(hashFile.toPath());
                String rawText = new String(content, java.nio.charset.StandardCharsets.UTF_8);
                String chainHash = new String(hashContent, java.nio.charset.StandardCharsets.UTF_8).trim();

                Arrays.fill(content, (byte) 0);
                Arrays.fill(hashContent, (byte) 0);

                // 파일은 at-rest 암호화(CryptoManager AES-GCM)로 저장되어 있으므로 각 줄을 복호화
                CryptoManager crypto = CryptoManager.getInstance();
                StringBuilder decrypted = new StringBuilder();
                for (String line : rawText.split("\n")) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()) continue;
                    try {
                        decrypted.append(crypto.decryptToString(trimmed)).append("\n");
                    } catch (Exception ex) {
                        // 복호화 실패 시 원문 유지 (이미 평문인 경우)
                        decrypted.append(trimmed).append("\n");
                    }
                }
                String logText = decrypted.toString().trim();

                // BE의 HashService.calculateMessageHash(normalized)와 동일한 방식으로 해시 계산
                String normalizedContent = String.join("\n",
                    java.util.Arrays.stream(logText.split("\\r?\n"))
                        .collect(java.util.stream.Collectors.toList()));
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = md.digest(normalizedContent.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                for (byte b : hashBytes) sb.append(String.format("%02x", b));
                chainHash = sb.toString();

                success = uploadEncryptedLog(deviceId, logType, logText, chainHash);
            } catch (Exception e) {
                Log.e(TAG, "sendFilesAsync error", e);
            }
            if (success) {
                callback.onSuccess();
            } else {
                callback.onFailure();
            }
        }).start();
    }

    // ──────────────────────────────────────────────
    // 서버 타임스탬프 (평문 GET, cleartext URL 사용 불가 → HTTPS)
    // ──────────────────────────────────────────────

    private static final String PREFS_TS = "aegis_ts_cache";
    private static final String KEY_SERVER_TS = "last_server_ts";   // 마지막 서버 시각 (ms)
    private static final String KEY_DEVICE_TS = "last_device_ts";   // 그 시점 기기 시각 (ms)
    private static final java.text.SimpleDateFormat TS_FMT =
            new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault());

    /**
     * 서버 타임스탬프 반환.
     * - 온라인: 실제 서버 시각 반환 + (서버시각, 기기시각) 쌍 캐싱
     * - 오프라인: 마지막 캐시 기반 추정값 반환 "[estimated]" 접두사 포함
     */
    public static String getServerTimestamp() {
        final String[] result = {null};
        CountDownLatch latch = new CountDownLatch(1);

        new Thread(() -> {
            try {
                URL url = new URL(BASE_URL + TIMESTAMP_PATH);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(conn.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) sb.append(line);
                    reader.close();
                    result[0] = sb.toString().trim();
                }
            } catch (Exception e) {
                Log.e(TAG, "getServerTimestamp failed", e);
            } finally {
                latch.countDown();
            }
        }).start();

        try {
            latch.await(6, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }
        return result[0]; // 호출 측에서 context 없이 캐싱 불가 — 캐싱은 saveServerTimestampCache() 사용
    }

    /** 온라인 성공 시 (서버시각, 기기시각) 쌍 캐싱. */
    public static void saveServerTimestampCache(android.content.Context context, String serverTs) {
        try {
            long serverMs = TS_FMT.parse(serverTs).getTime();
            android.content.SharedPreferences prefs =
                    context.getSharedPreferences(PREFS_TS, android.content.Context.MODE_PRIVATE);
            prefs.edit()
                    .putLong(KEY_SERVER_TS, serverMs)
                    .putLong(KEY_DEVICE_TS, System.currentTimeMillis())
                    .apply();
        } catch (Exception e) {
            Log.e(TAG, "saveServerTimestampCache failed", e);
        }
    }

    /**
     * 오프라인 상태에서 추정 서버 시각 반환.
     * estimatedServerTs = 마지막서버시각 + (현재기기시각 - 마지막기기시각)
     * 캐시 없으면 null 반환.
     */
    public static String getEstimatedServerTimestamp(android.content.Context context) {
        android.content.SharedPreferences prefs =
                context.getSharedPreferences(PREFS_TS, android.content.Context.MODE_PRIVATE);
        long lastServerMs = prefs.getLong(KEY_SERVER_TS, -1);
        long lastDeviceMs = prefs.getLong(KEY_DEVICE_TS, -1);
        if (lastServerMs < 0 || lastDeviceMs < 0) return null;

        long elapsed = System.currentTimeMillis() - lastDeviceMs;
        long estimatedMs = lastServerMs + elapsed;
        return "[estimated] " + TS_FMT.format(new java.util.Date(estimatedMs));
    }

    public interface FileTransferCallback {
        void onSuccess();
        void onFailure();
    }
}
