package com.example.forensic.Controller;

import com.example.forensic.Service.CryptoService;
import com.example.forensic.Service.LogService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

@RestController
@RequestMapping(value = "/logs", produces = "application/json")
public class LogController {

    private static final Logger logger = LoggerFactory.getLogger(LogController.class);
    private static final Pattern PATH_VALIDATION_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    @Autowired
    private LogService logService;

    @Autowired
    private CryptoService cryptoService;

    /**
     * 암호화된 로그 파일 업로드 및 서명 검증
     */
    @PostMapping("/upload")
    public ResponseEntity<String> handleLogUpload(
            @RequestParam("logFile") MultipartFile logFile,
            @RequestParam("hashFile") MultipartFile hashFile,
            HttpServletRequest request) {

        try {
            // 1. 파일명 파싱 및 디바이스 ID, 로그 타입 검증
            String originalFilename = logFile.getOriginalFilename();
            if (originalFilename == null || !originalFilename.contains("_")) {
                return ResponseEntity.badRequest().body("🚨 올바르지 않은 파일명 형식입니다.");
            }

            String[] parts = originalFilename.split("_");
            String deviceId = parts[0];
            String logType = parts[1].replace(".txt", "");

            if (!PATH_VALIDATION_PATTERN.matcher(deviceId).matches() || !PATH_VALIDATION_PATTERN.matcher(logType).matches()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("🚨 허용되지 않는 특수문자가 감지되었습니다. (Path Traversal 방지)");
            }

            // 2. mTLS 클라이언트 인증서 추출 및 공개키 획득
            X509Certificate[] certs = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
            if (certs == null || certs.length == 0) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("🚨 mTLS 클라이언트 인증서가 누락되었습니다.");
            }
            PublicKey clientPublicKey = certs[0].getPublicKey();

            // 3. E2E 암호화 패킷 해독 및 서명 검증
            byte[] packetBytes = logFile.getBytes();
            String decryptedLogContent = cryptoService.decryptAndVerify(packetBytes, clientPublicKey, deviceId);

            // 4. 복호화된 로그 저장 및 해시 대조 (동기 처리)
            String logResult = logService.appendDecryptedLog(deviceId, logType, decryptedLogContent, hashFile);

            return ResponseEntity.ok("✅ 로그 복호화 및 업로드 성공\n" + logResult);

        } catch (SecurityException e) {
            logger.warn("🚨 보안 위협 감지: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        } catch (Exception e) {
            logger.error("🚨 로그 업로드 중 예외 발생: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("🚨 로그 업로드 실패: " + e.getMessage());
        }
    }

    /**
     * 로그 파일 조회
     */
    @GetMapping("/{deviceId}/{logType}")
    public ResponseEntity<String> getLogContents(@PathVariable String deviceId, @PathVariable String logType) {
        if (!PATH_VALIDATION_PATTERN.matcher(deviceId).matches() || !PATH_VALIDATION_PATTERN.matcher(logType).matches()) {
            return ResponseEntity.badRequest().body("🚨 잘못된 형식의 경로 변수입니다.");
        }
        String fileContents = logService.readLog(deviceId, logType);
        return ResponseEntity.ok(fileContents);
    }

    /**
     * 특정 시간 범위 내에서 로그 분석 및 PDF 생성
     */
    @GetMapping("/analyze/{deviceId}/{startTime}/{endTime}")
    public ResponseEntity<String> analyzeLogs(
            @PathVariable String deviceId,
            @PathVariable String startTime,
            @PathVariable String endTime) {

        if (!PATH_VALIDATION_PATTERN.matcher(deviceId).matches()) {
            return ResponseEntity.badRequest().body("🚨 잘못된 형식의 기기 ID입니다.");
        }

        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
            LocalDateTime start = LocalDateTime.parse(startTime, formatter);
            LocalDateTime end = LocalDateTime.parse(endTime, formatter);

            logger.info("📌 로그 분석 요청: Device={}, Start={}, End={}", deviceId, start, end);

            String report = logService.analyzeLog(deviceId, start, end);
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            logger.error("🚨 로그 분석 실패: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("🚨 잘못된 형식 또는 분석 중 오류 발생: " + e.getMessage());
        }
    }

    /**
     * 클라이언트가 ECDH 키 합의에 사용할 서버 X25519 공개키 반환 (Base64).
     * 이 엔드포인트는 PUBLIC 접근 허용 (SecurityConfig 참조).
     */
    @GetMapping("/serverkey")
    public ResponseEntity<String> getServerPublicKey() {
        try {
            byte[] pubKeyBytes = cryptoService.getServerPublicKeyBytes();
            String b64 = java.util.Base64.getEncoder().encodeToString(pubKeyBytes);
            return ResponseEntity.ok(b64);
        } catch (Exception e) {
            logger.error("Server key export failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Key export failed");
        }
    }

    @GetMapping("/timestamp")
    public ResponseEntity<String> getServerTimestamp() {
        String currentTimestamp = LocalDateTime.now()
                .plusHours(9)
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        return ResponseEntity.ok(currentTimestamp);
    }

    @DeleteMapping("/all")
    public ResponseEntity<String> deleteAllLogs() {
        logService.deleteAll();
        return ResponseEntity.ok("✅ 모든 로그가 삭제되었습니다.");
    }
}
