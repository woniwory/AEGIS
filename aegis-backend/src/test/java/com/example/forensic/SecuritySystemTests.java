package com.example.forensic;

import com.example.forensic.Service.CryptoService;
import com.example.forensic.Service.HashService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.GZIPOutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.example.forensic.Service.LogService;
import com.example.forensic.Repository.LogRepository;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SecuritySystemTests {

    @Autowired private MockMvc mockMvc;
    @Autowired private CryptoService cryptoService;
    @Autowired private HashService hashService;
    @Autowired private LogService logService;
    @Autowired private LogRepository logRepository;

    // ─────────────────────────────────────────────────────────
    // 헬퍼
    // ─────────────────────────────────────────────────────────

    /** Android ClientCryptoPipeline과 동일한 패킷 생성 (서버 X25519 공개키 사용) */
    private byte[] buildEncryptedPacket(String logContent, String deviceId) throws Exception {
        // 1. 서버 X25519 공개키 획득
        byte[] serverPubBytes = cryptoService.getServerPublicKeyBytes();
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey serverPublicKey = kf.generatePublic(new X509EncodedKeySpec(serverPubBytes));

        // 2. 클라이언트 Ephemeral X25519 키쌍 생성 (Java 표준 → DER 인코딩)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair clientEphemeral = kpg.generateKeyPair();
        byte[] ephemeralPubBytes = clientEphemeral.getPublic().getEncoded(); // X.509 DER

        // 3. ECDH 공유 비밀
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(clientEphemeral.getPrivate());
        ka.doPhase(serverPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // 4. HKDF-SHA256 (CryptoService.deriveHKDFKey와 동일)
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(sharedSecret);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update((byte) 1);
        byte[] sessionKeyBytes = mac.doFinal();
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        // 5. GZIP 압축
        byte[] compressed = compressGZIP(logContent);

        // 6. AES-256-GCM 암호화 (AAD = deviceId)
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        cipher.updateAAD(deviceId.getBytes());
        byte[] ciphertext = cipher.doFinal(compressed);

        // 7. ECDSA 서명 (mTLS 없는 환경에서 서버가 fallbackKey로 bypass)
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        PrivateKey signingKey = ecKpg.generateKeyPair().getPrivate();
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(signingKey);
        sig.update(ephemeralPubBytes);
        sig.update(iv);
        sig.update(deviceId.getBytes());
        sig.update(ciphertext);
        byte[] signature = sig.sign();

        // 8. 패킷 조합
        ByteBuffer buf = ByteBuffer.allocate(
                4 + ephemeralPubBytes.length + 12 + 4 + signature.length + ciphertext.length);
        buf.putInt(ephemeralPubBytes.length);
        buf.put(ephemeralPubBytes);
        buf.put(iv);
        buf.putInt(signature.length);
        buf.put(signature);
        buf.put(ciphertext);
        return buf.array();
    }

    private byte[] compressGZIP(String data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(data.getBytes(StandardCharsets.UTF_8));
        }
        return baos.toByteArray();
    }

    private byte[] deriveHKDFKey(byte[] sharedSecret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(sharedSecret);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update((byte) 1);
        return mac.doFinal();
    }

    // ─────────────────────────────────────────────────────────
    // Test 1: 서비스 레이어 직접 — 해시 검증 및 리포트 파일 생성
    // ─────────────────────────────────────────────────────────
    @Test
    void testReportGenerationHashMatch() throws Exception {
        logRepository.deleteAll();

        String deviceId = "test_device_hash_match";
        String logType  = "SecurityTamperLog";
        String decryptedLogContent =
            "2026-06-06 14:10:00 Frida instrumentation tool detected in memory.\n" +
            "2026-06-06 14:10:01 Terminating execution due to security policy violations.";

        String expectedHash = hashService.calculateMessageHash(decryptedLogContent);

        MockMultipartFile hashFile = new MockMultipartFile(
                "hashFile", "hash.txt", "text/plain",
                expectedHash.getBytes(StandardCharsets.UTF_8));

        String appendResult = logService.appendDecryptedLog(deviceId, logType, decryptedLogContent, hashFile);
        assertEquals("SUCCESS", appendResult);

        LocalDateTime start = LocalDateTime.of(2026, 6, 6, 0, 0, 0);
        LocalDateTime end   = LocalDateTime.of(2026, 6, 6, 23, 59, 59);
        String reportPath = logService.analyzeLog(deviceId, start, end);

        java.nio.file.Path pdfPath = java.nio.file.Paths.get(reportPath);
        java.nio.file.Path logFilePath = pdfPath.getParent().resolve("logs_" + expectedHash + ".txt");
        assertNotNull(reportPath, "리포트 경로가 null이면 안 됩니다.");
        assertTrue(java.nio.file.Files.exists(logFilePath), "로그 .txt 파일이 존재해야 합니다: " + logFilePath);

        String calculatedFileHash = hashService.calculateFileHash(logFilePath);
        assertEquals(expectedHash, calculatedFileHash, "재구성된 로그의 해시가 일치해야 합니다.");
    }

    // ─────────────────────────────────────────────────────────
    // Test 2: 실제 시나리오 데이터 — 서비스 레이어 직접
    // ─────────────────────────────────────────────────────────
    @Test
    void testAEGISReportScenario() throws Exception {
        logRepository.deleteAll();

        String deviceId = "240c894c126a902f";
        String logType  = "SecurityTamperLog";

        String decryptedLogContent =
            "2025-06-24 18:53:59 Anti-forensic event detected: android.intent.action.TIME_SET\n" +
            "2025-06-24 18:53:59 SystemClockTime: Setting time of day to sec=1750758839221\n" +
            "2025-06-24 18:53:59 Auto time setting enabled: false\n" +
            "2025-06-24 18:54:41 Log Buffer Cleared Detected. (adb logcat -c)\n" +
            "2025-06-24 18:54:05 Call Type: start an outgoing call Number: 01065749080 Start Time: 2025-06-24 18:54:05 End Time: N/A Duration: 0 seconds\n" +
            "2025-06-24 18:54:17 Call Type: Termination of the call Number: 01065749080 Start Time : 2025-06-24 18:54:05 End Time: 2025-06-24 18:54:17 Duration: 12 seconds\n" +
            "2025-06-24 18:55:43 Call Type: Ringing an incoming call Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n" +
            "2025-06-24 18:55:49 Call Type: Refuse incoming calls or don't answer Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n" +
            "2025-07-01 18:53:25 Call Type: Ringing an incoming call Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n" +
            "2025-07-01 18:53:26 Call Type: start an incoming call Number: 01065749080 Start Time: 2025-07-01 18:53:26 End Time: N/A Duration: 0 seconds\n" +
            "2025-07-01 18:53:32 Call Type: Termination of the call Number: 01065749080 Start Time : 2025-07-01 18:53:26 End Time: 2025-07-01 18:53:32 Duration: 6 seconds\n" +
            "2025-06-24 18:55:37 SMS Sent from: 01065749080 Message: Who are you?\n" +
            "2025-07-01 18:53:41 SMS Received from: 01065749080 Message: Malicious Message\n" +
            "2025-06-24 18:56:18 Bluetooth connected to: AirPods [60:93:16:44:B7:46]\n" +
            "2025-06-24 18:56:21 A2DP streaming stopped on device: AirPods\n" +
            "2025-06-24 18:57:05 A2DP streaming started on device: AirPods\n" +
            "2025-06-24 18:57:16 A2DP streaming stopped on device: AirPods\n" +
            "2025-06-24 18:56:56 File Opened (file_opened): /storage/emulated/0/Music/Samsung/Over_the_Horizon.mp3\n" +
            "2025-07-01 18:53:05 File Created: /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:05 File Revised (written_to): /storage/emulated/0/Download/Attacker File.txt\n" +
            "2025-07-01 18:53:47 File Metadata Changed (metadata_changed): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n" +
            "2025-06-24 18:54:00 Background App: com.android.settings\n" +
            "2025-06-24 18:54:00 Foreground App: com.sec.android.app.launcher\n" +
            "2025-06-24 18:54:02 Background App: com.sec.android.app.launcher\n" +
            "2025-06-24 18:54:02 Foreground App: com.samsung.android.dialer\n" +
            "2025-07-01 18:53:57 Text: Previous month Content Description: Previous month Class Name: android.widget.ImageButton Clickable: true, Enabled: true, Focusable: true";

        String expectedHash = hashService.calculateMessageHash(decryptedLogContent);

        MockMultipartFile hashFile = new MockMultipartFile(
                "hashFile", "hash.txt", "text/plain",
                expectedHash.getBytes(StandardCharsets.UTF_8));

        String appendResult = logService.appendDecryptedLog(deviceId, logType, decryptedLogContent, hashFile);
        assertEquals("SUCCESS", appendResult);

        LocalDateTime start = LocalDateTime.of(2025, 2, 1, 14, 0, 0);
        LocalDateTime end   = LocalDateTime.of(2026, 12, 31, 23, 59, 59);
        String reportPath = logService.analyzeLog(deviceId, start, end);

        assertNotNull(reportPath, "리포트 경로가 null이면 안 됩니다.");
        assertTrue(reportPath.endsWith(".pdf"), "리포트 경로가 .pdf로 끝나야 합니다.");

        java.nio.file.Path pdfPath = java.nio.file.Paths.get(reportPath);
        assertTrue(java.nio.file.Files.exists(pdfPath), "PDF 파일이 존재해야 합니다: " + reportPath);
        assertTrue(java.nio.file.Files.size(pdfPath) > 1024, "PDF 크기가 1KB 이상이어야 합니다.");

        java.nio.file.Path logFilePath = pdfPath.getParent().resolve("logs_" + expectedHash + ".txt");
        assertTrue(java.nio.file.Files.exists(logFilePath), "로그 .txt 파일이 존재해야 합니다.");

        String calculatedFileHash = hashService.calculateFileHash(logFilePath);
        assertEquals(expectedHash, calculatedFileHash, "재구성된 로그의 해시가 일치해야 합니다.");
    }

    // ─────────────────────────────────────────────────────────
    // Test 3: HTTP 업로드 파이프라인 E2E — MockMvc
    //   암호화 패킷 → POST /logs/upload → GET /logs/analyze → GET /logs/report
    // ─────────────────────────────────────────────────────────
    @Test
    void testFullHttpUploadPipeline() throws Exception {
        logRepository.deleteAll();

        String deviceId = "e2ehttptestdevice";

        // 각 로거가 탐지하는 이벤트 타입별 로그
        String[][] scenarios = {
            {"AntiForensicLog",
                "2026-01-15 10:00:00 Anti-forensic event detected: android.intent.action.TIME_SET\n" +
                "2026-01-15 10:00:01 SystemClockTime: Setting time of day to sec=1736931601000\n" +
                "2026-01-15 10:00:02 Auto time setting enabled: false\n" +
                "2026-01-15 10:05:00 Log Buffer Cleared Detected. (adb logcat -c)\n" +
                "2026-01-15 10:10:00 Device Shutdown or Reboot Detected."},

            {"CallingLog",
                "2026-01-15 10:01:00 Call Type: start an outgoing call Number: 01012345678 Start Time: 2026-01-15 10:01:00 End Time: N/A Duration: 0 seconds\n" +
                "2026-01-15 10:03:30 Call Type: Termination of the call Number: 01012345678 Start Time : 2026-01-15 10:01:00 End Time: 2026-01-15 10:03:30 Duration: 150 seconds\n" +
                "2026-01-15 10:15:00 Call Type: Ringing an incoming call Number: 01087654321 Start Time: N/A End Time: N/A Duration: 0 seconds\n" +
                "2026-01-15 10:15:05 Call Type: Refuse incoming calls or don't answer Number: 01087654321 Start Time: N/A End Time: N/A Duration: 0 seconds"},

            {"MessageLog",
                "2026-01-15 10:02:00 SMS Sent from: 01012345678 Message: Test outgoing message\n" +
                "2026-01-15 10:04:00 SMS Received from: 01099999999 Message: Suspicious incoming message"},

            {"BluetoothLog",
                "2026-01-15 10:06:00 Bluetooth connected to: EvilDevice [AA:BB:CC:DD:EE:FF]\n" +
                "2026-01-15 10:06:30 A2DP streaming started on device: EvilDevice\n" +
                "2026-01-15 10:07:00 A2DP streaming stopped on device: EvilDevice\n" +
                "2026-01-15 10:07:30 Bluetooth disconnected from: EvilDevice [AA:BB:CC:DD:EE:FF]"},

            {"FileLog",
                "2026-01-15 10:08:00 File Created: /storage/emulated/0/Download/malware.apk\n" +
                "2026-01-15 10:08:01 File Opened (file_opened): /storage/emulated/0/Download/malware.apk\n" +
                "2026-01-15 10:08:02 File Revised (written_to): /storage/emulated/0/Download/malware.apk\n" +
                "2026-01-15 10:08:03 File Closed after Writing (closed_after_write): /storage/emulated/0/Download/malware.apk\n" +
                "2026-01-15 10:08:05 File Metadata Changed (metadata_changed): /storage/emulated/0/Download/malware.apk\n" +
                "2026-01-15 10:08:10 MediaStore changed: content://media/external/files/123 File Name (DISPLAY_NAME): malware.apkRelative Path: Download/Modifed After Date: 2026-01-15 10:08:10"},

            {"AppExecutionLog",
                "2026-01-15 10:09:00 Foreground App: com.android.settings\n" +
                "2026-01-15 10:09:01 Background App: com.android.settings\n" +
                "2026-01-15 10:09:01 Foreground App: com.malicious.app\n" +
                "2026-01-15 10:09:05 Text: Grant Permission Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n" +
                "2026-01-15 10:09:10 Background App: com.malicious.app\n" +
                "2026-01-15 10:09:10 Foreground App: com.sec.android.app.launcher"},
        };

        // ── 각 로그타입 업로드 ──────────────────────────────
        for (String[] scenario : scenarios) {
            String logType   = scenario[0];
            String logContent = scenario[1];

            String normalized    = String.join("\n", logContent.split("\\r?\\n"));
            String contentHash   = hashService.calculateMessageHash(normalized);
            byte[] packet        = buildEncryptedPacket(logContent, deviceId);

            MockMultipartFile logFile = new MockMultipartFile(
                    "logFile", deviceId + "_" + logType + ".txt",
                    "application/octet-stream", packet);
            MockMultipartFile hashFile = new MockMultipartFile(
                    "hashFile", deviceId + "_" + logType + "_hash.txt",
                    "text/plain", contentHash.getBytes(StandardCharsets.UTF_8));

            mockMvc.perform(multipart("/logs/upload")
                            .file(logFile)
                            .file(hashFile))
                   .andExpect(status().isOk())
                   .andExpect(content().string(org.hamcrest.Matchers.containsString("SUCCESS")));
        }

        // ── analyze → PDF 생성 ─────────────────────────────
        MvcResult analyzeResult = mockMvc.perform(get(
                "/logs/analyze/{deviceId}/{start}/{end}",
                deviceId, "2026-01-01T00:00:00", "2026-12-31T23:59:59"))
                .andExpect(status().isOk())
                .andReturn();

        String reportPath = analyzeResult.getResponse().getContentAsString().trim();
        assertFalse(reportPath.isBlank(), "리포트 경로가 비어있으면 안 됩니다.");
        assertTrue(reportPath.endsWith(".pdf"), "리포트 경로가 .pdf로 끝나야 합니다.");

        java.nio.file.Path pdfPath = java.nio.file.Paths.get(reportPath);
        assertTrue(java.nio.file.Files.exists(pdfPath), "PDF 파일이 생성되어야 합니다.");
        assertTrue(java.nio.file.Files.size(pdfPath) > 1024, "PDF 크기가 1KB 이상이어야 합니다.");

        // ── PDF 다운로드 엔드포인트 ────────────────────────
        mockMvc.perform(get("/logs/report/{deviceId}", deviceId))
               .andExpect(status().isOk())
               .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    // ─────────────────────────────────────────────────────────
    // Test 4: E2E 암호화 복호화 정합성 검증
    // ─────────────────────────────────────────────────────────
    @Test
    void testE2EDecryptionAndVerification() throws Exception {
        String originalLog = "2026-06-06 14:00:00 [INFO] Test Log Content\n2026-06-06 14:01:00 [WARN] Memory Alert";
        String deviceId = "test_device_01";

        byte[] serverPublicKeyBytes = cryptoService.getServerPublicKeyBytes();
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey serverPublicKey = kf.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair clientEphemeralKeyPair = kpg.generateKeyPair();
        byte[] ephemeralPublicKeyBytes = clientEphemeralKeyPair.getPublic().getEncoded();

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(clientEphemeralKeyPair.getPrivate());
        ka.doPhase(serverPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();
        byte[] sessionKeyBytes = deriveHKDFKey(sharedSecret);
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        byte[] compressedPlaintext = compressGZIP(originalLog);

        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        cipher.updateAAD(deviceId.getBytes());
        byte[] ciphertext = cipher.doFinal(compressedPlaintext);

        KeyPairGenerator ecdsaKpg = KeyPairGenerator.getInstance("EC");
        ecdsaKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair clientSigningKeyPair = ecdsaKpg.generateKeyPair();
        PublicKey clientSigningPublicKey = clientSigningKeyPair.getPublic();

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(clientSigningKeyPair.getPrivate());
        sig.update(ephemeralPublicKeyBytes);
        sig.update(iv);
        sig.update(deviceId.getBytes());
        sig.update(ciphertext);
        byte[] signatureBytes = sig.sign();

        ByteBuffer buffer = ByteBuffer.allocate(
                4 + ephemeralPublicKeyBytes.length + 12 + 4 + signatureBytes.length + ciphertext.length);
        buffer.putInt(ephemeralPublicKeyBytes.length);
        buffer.put(ephemeralPublicKeyBytes);
        buffer.put(iv);
        buffer.putInt(signatureBytes.length);
        buffer.put(signatureBytes);
        buffer.put(ciphertext);
        byte[] finalPacket = buffer.array();

        String decryptedContent = cryptoService.decryptAndVerify(finalPacket, clientSigningPublicKey, deviceId);
        assertEquals(originalLog, decryptedContent);
    }

    // ─────────────────────────────────────────────────────────
    // Test 5: 서명 위조 시 SecurityException 발생 검증
    // ─────────────────────────────────────────────────────────
    @Test
    void testInvalidSignatureThrowsSecurityException() throws Exception {
        String originalLog = "2026-06-06 14:00:00 [INFO] Corrupted Signature Test";
        String deviceId = "test_device_02";

        byte[] serverPublicKeyBytes = cryptoService.getServerPublicKeyBytes();
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey serverPublicKey = kf.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair clientEphemeralKeyPair = kpg.generateKeyPair();
        byte[] ephemeralPublicKeyBytes = clientEphemeralKeyPair.getPublic().getEncoded();

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(clientEphemeralKeyPair.getPrivate());
        ka.doPhase(serverPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();
        byte[] sessionKeyBytes = deriveHKDFKey(sharedSecret);
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
        byte[] compressedPlaintext = compressGZIP(originalLog);

        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        cipher.updateAAD(deviceId.getBytes());
        byte[] ciphertext = cipher.doFinal(compressedPlaintext);

        KeyPairGenerator ecdsaKpg = KeyPairGenerator.getInstance("EC");
        ecdsaKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair clientSigningKeyPair = ecdsaKpg.generateKeyPair();
        PublicKey clientSigningPublicKey = clientSigningKeyPair.getPublic();

        // 의도적으로 다른 데이터에 서명 → 검증 실패
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(clientSigningKeyPair.getPrivate());
        sig.update(new byte[5]); // 잘못된 데이터
        byte[] signatureBytes = sig.sign();

        ByteBuffer buffer = ByteBuffer.allocate(
                4 + ephemeralPublicKeyBytes.length + 12 + 4 + signatureBytes.length + ciphertext.length);
        buffer.putInt(ephemeralPublicKeyBytes.length);
        buffer.put(ephemeralPublicKeyBytes);
        buffer.put(iv);
        buffer.putInt(signatureBytes.length);
        buffer.put(signatureBytes);
        buffer.put(ciphertext);
        byte[] finalPacket = buffer.array();

        assertThrows(SecurityException.class, () ->
                cryptoService.decryptAndVerify(finalPacket, clientSigningPublicKey, deviceId));
    }
}
