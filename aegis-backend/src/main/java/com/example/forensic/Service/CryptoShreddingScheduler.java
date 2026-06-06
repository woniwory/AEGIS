package com.example.forensic.Service;

import com.example.forensic.Entity.Log;
import com.example.forensic.Repository.LogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 보존 기간(기본 90일) 초과 로그에 대한 Crypto-Shredding 실행.
 *
 * 동작 방식:
 * 1. 각 로그 배치(deviceId + logType)에 대해 암호화 키(DEK)를 별도 보관.
 * 2. 보존 기간 초과 시 DEK를 삭제하여 암호문을 수학적으로 복구 불가 상태로 만든다.
 * 3. 이후 MongoDB에서 해당 문서도 물리 삭제하여 정리.
 *
 * 운영 환경: DEK는 HashiCorp Vault / AWS Secrets Manager에 저장해야 함.
 * 현재 구현은 인메모리 DEK 맵 (프로토타입 수준) — 운영 시 Vault 연동 필요.
 */
@Service
@EnableScheduling
public class CryptoShreddingScheduler {

    private static final Logger log = LoggerFactory.getLogger(CryptoShreddingScheduler.class);

    @Value("${aegis.retention.days:90}")
    private int retentionDays;

    @Autowired
    private LogRepository logRepository;

    /**
     * DEK 저장소 (운영 환경에서는 Vault로 대체).
     * Key = logId, Value = AES-256 DEK
     */
    private final Map<String, SecretKey> dekStore = new ConcurrentHashMap<>();

    /**
     * 새 로그 저장 시 DEK 등록 (LogService에서 호출).
     */
    public void registerDek(String logId) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            dekStore.put(logId, kg.generateKey());
        } catch (Exception e) {
            log.error("DEK generation failed for logId={}", logId, e);
        }
    }

    /**
     * 매일 새벽 2시에 실행: 보존 기간 초과 로그 Crypto-Shred.
     * cron = "0 0 2 * * *"
     */
    @Scheduled(cron = "0 0 2 * * *")
    public void runCryptoShredding() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(retentionDays);
        log.info("Crypto-Shredding: purging logs older than {} ({} days)", cutoff, retentionDays);

        List<Log> expiredLogs = logRepository.findAll().stream()
                .filter(l -> l.getCreatedAt() != null && l.getCreatedAt().isBefore(cutoff))
                .toList();

        if (expiredLogs.isEmpty()) {
            log.info("No expired logs found.");
            return;
        }

        int shredded = 0;
        for (Log l : expiredLogs) {
            try {
                // 1. DEK 삭제 → 암호문 수학적 복구 불가
                dekStore.remove(l.getId());

                // 2. MongoDB 물리 삭제
                logRepository.deleteById(l.getId());
                shredded++;
            } catch (Exception e) {
                log.error("Shredding failed for logId={}", l.getId(), e);
            }
        }
        log.info("Crypto-Shredding complete: {} logs shredded.", shredded);
    }
}
