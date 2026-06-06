# AEGIS Security Implementation

## Architecture

```
[Android Agent] ──mTLS+ECDH──▶ [Nginx Reverse Proxy] ──▶ [Spring Boot] ──▶ [MongoDB]
  AES-256-GCM                    TLS 1.3 only              AES-GCM Decrypt    Field-level AES
  Hash Chain                     SPKI Pinning               ECDSA Verify       Crypto-Shredding
  SQLCipher Queue                                           Hash Chain Check
```

---

## Android Client — 새로 추가된 보안 기능

| 파일 | 역할 |
|------|------|
| `CryptoManager` | Android Keystore AES-256-GCM — 로그 파일 at-rest 암호화 |
| `ForwardHashChain` | `H_i = SHA-256(M_i ∥ H_{i-1})` — 로그 삭제/삽입 위변조 탐지 |
| `ClientCryptoPipeline` | GZIP → X25519 ECDH → AES-256-GCM (AAD) → ECDSA 서명 |
| `AntiTamperGuard` | 디버거·Frida·Xposed 감지 시 즉시 프로세스 종료 |
| `OfflineLogDatabase` | SQLCipher 암호화 Room DB — 오프라인 로그 버퍼 |
| `UploadQueueWorker` | WorkManager — 네트워크 복구 시 자동 재업로드 |

### 업로드 흐름
```
log 발생
  → CryptoManager.encrypt(message)  [at-rest]
  → ForwardHashChain.advance(message) → H_i 갱신
  → ClientCryptoPipeline.encrypt(plaintext)
       1. GZIP 압축
       2. X25519 ephemeral 키쌍 생성
       3. HKDF-SHA256 → K_session (AES-256)
       4. AES-256-GCM 암호화 (AAD = deviceId)
       5. ECDSA-SHA256 서명 (Android Keystore)
  → OkHttp POST /logs/upload  [mTLS + SPKI 핀]
       실패 시 → SQLCipher 오프라인 큐 저장
                → WorkManager 재시도 예약
```

---

## Spring Boot Server — 새로 추가된 보안 기능

| 파일 | 역할 |
|------|------|
| `CryptoService` | X25519 ECDH + HKDF + AES-256-GCM 복호화, ECDSA 검증 |
| `FieldEncryptionConverter` | MongoDB 저장 전 민감 필드 AES-256-GCM 암호화 |
| `CryptoShreddingScheduler` | 매일 02:00 — 90일 초과 로그 DEK 삭제 후 물리 제거 |
| `GET /logs/serverkey` | 클라이언트 ECDH용 서버 X25519 공개키 반환 |

---

## 체크리스트 (Spec §5 기준)

| 항목 | 상태 |
|------|------|
| 오프라인 큐 → 네트워크 복구 시 자동 전송 | ✅ WorkManager |
| Hash Chain 위변조 탐지 | ✅ H_i 체인, 서버 재계산 검증 |
| 세션 키 전방향 안전성 (PFS) | ✅ 매 업로드마다 새 X25519 임시 키 |
| 메모리 민감 데이터 즉시 소거 | ✅ `Arrays.fill(..., (byte)0)` |
| 디버거/Frida 탐지 → 앱 종료 | ✅ AntiTamperGuard |
| Cleartext HTTP 차단 | ✅ `usesCleartextTraffic=false` |
| TLS 1.3 전용 | ✅ OkHttp SSLContext TLSv1.3 |
| mTLS 클라이언트 인증 | ✅ Android Keystore KeyManager |
| SPKI 핀닝 (주+백업) | ✅ CertificatePinner (핀값 교체 필요) |
| MongoDB 필드 암호화 | ✅ FieldEncryptionConverter |
| 90일 보존 + Crypto-Shredding | ✅ CryptoShreddingScheduler |
| ProGuard R8 난독화 | ✅ release minify 활성화 |

---

## 운영 전 필수 작업

```
1. SPKI 핀 교체
   openssl s_client -connect 220.149.236.152:52346 | \
   openssl x509 -pubkey -noout | \
   openssl pkey -pubin -outform DER | \
   openssl dgst -sha256 -binary | base64
   → ServerTransmitter.java SPKI_PIN_PRIMARY 값 교체

2. MongoDB 필드 암호화 키 설정
   AEGIS_FIELD_ENC_KEY=<32바이트 Base64 키> (환경변수 또는 Vault)

3. CryptoShreddingScheduler DEK 저장소
   현재: 인메모리 ConcurrentHashMap (재시작 시 소실)
   운영: HashiCorp Vault / AWS Secrets Manager 연동 필요
```
