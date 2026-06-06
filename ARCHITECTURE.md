# AEGIS 아키텍처 전체 설명

AEGIS는 Android 포렌식 시스템으로, 기기의 6가지 이벤트를 탐지·암호화·전송하고, 서버에서 무결성을 검증한 뒤 PDF 보고서를 생성한다.

```
[Android 기기]  →  [Spring Boot BE + MongoDB]  →  [PDF Report]
```

---

## 1. Android 측 — 이벤트 탐지 (6개 로거)

각 로거는 `Service`로 백그라운드에서 상시 실행된다.

| 로거 | 탐지 방법 | 탐지 이벤트 |
|------|-----------|------------|
| `AntiForensicLogger` | `logcat` 스트림 모니터링 | 시간 조작, `logcat -c`, 리부트 |
| `CallingLogger` | `TelephonyCallback` | 전화 수·발신, 통화 상태 변경 |
| `MessageLogger` | `BroadcastReceiver` (`SMS_RECEIVED`, `SMS_SENT`) | SMS 수신·발신 |
| `BluetoothLogger` | `BroadcastReceiver` (`ACL_CONNECTED`, `A2DP`) | BT 연결·해제, 스트리밍 |
| `FileSystemLogger` | `MediaStore` ContentObserver + inotify | 파일 생성·삭제·수정 |
| `AppExecutionLogger` | `AccessibilityService` | 앱 포·백그라운드 전환, UI 클릭 |

---

## 2. Android 측 — 로그 저장 (이중 암호화)

이벤트 발생 시 `LogHandler.appendToLogFile(message)` 호출.

```
평문 메시지
    ↓
CryptoManager.encryptString()      ← AES-256-GCM (at-rest 암호화)
    ↓
파일에 한 줄씩 저장 (Base64 ciphertext)
    ↓
ForwardHashChain.advance(message)  ← H_i = SHA-256(M_i ‖ H_{i-1})
    ↓
hash.txt 업데이트
```

- **at-rest 암호화**: 기기가 탈취되어도 로그 파일을 읽을 수 없음
- **전방향 해시 체인**: 과거 로그를 소급해서 조작하면 체인이 끊어짐
- **파일 권한**: 쓰기 후 즉시 `chmod read-only` → 다른 앱이 로그를 수정 불가

---

## 3. Android 측 — 업로드 트리거 및 오프라인 큐 (SQLCipher)

두 가지 조건에서 업로드 실행:

- **512KB 초과** (`checkFileSizeAndHandle`): 해당 로그 파일만 즉시 전송
- **긴급 이벤트** (`handleCriticalEvents`): `logcat -c` / 종료 / 리부트 감지 시 **모든 로그 파일** 동시 전송

### 비행기 모드 / 네트워크 단절 시 — SQLCipher 오프라인 큐

전송 실패 시 데이터를 유실하지 않도록 암호화된 로컬 SQLite DB에 버퍼링한다.

```
전송 실패 (네트워크 없음)
    ↓
ServerTransmitter.queueOffline()
    ↓
CryptoManager.encryptString(logContent)   ← 컬럼 수준 AES-256-GCM 암호화
    ↓
OfflineLogDatabase (SQLCipher)에 INSERT
  테이블: offline_log_queue
  컬럼: device_id, log_type, encrypted_log_content, chain_hash, retry_count
    ↓
UploadQueueWorker.scheduleFlush()         ← WorkManager에 재시도 예약
  제약: NetworkType.CONNECTED (Wi-Fi/데이터 연결 시에만 실행)
  정책: KEEP (중복 예약 방지)
    ↓
네트워크 복구 시 Worker 자동 실행
  → CryptoManager.decryptToString(encrypted_log_content)
  → ServerTransmitter.uploadEncryptedLog() 재시도
  → 성공: DB에서 삭제 / 실패: retry_count 증가 (MAX 5회 초과 시 영구 삭제)
```

**DB 파일 위치 (실기기/에뮬레이터)**

```
/data/data/com.example.logcat/databases/aegis_offline_queue.db
```

> 확장자는 `.db` (Room 기본값), 디렉터리는 `databases` (복수).  
> `.sqlite` / `database` (단수)가 아님에 주의.

**이중 암호화 구조**

| 계층 | 방식 | 범위 |
|------|------|------|
| 1계층 | SQLCipher AES-256-CBC | DB 파일 전체 (페이지 단위 암호화) |
| 2계층 | CryptoManager AES-256-GCM | `encrypted_log_content` 컬럼 개별 암호화 |

SQLCipher 패스프레이즈 도출 과정:
```
최초 실행: SecureRandom 32바이트 생성
    → CryptoManager.encryptString() (Android Keystore 키로 암호화)
    → SharedPreferences에 Base64로 저장

이후 실행: SharedPreferences에서 읽어 복호화 후 패스프레이즈로 사용
```

→ 패스프레이즈 자체가 Android Keystore에 묶여 있어 기기 외부에서 DB 파일을 추출해도 열 수 없다.

**왜 추출해도 못 여는가?**

```
SQLCipher DB를 열려면 패스프레이즈가 필요
    ↓
패스프레이즈는 SharedPreferences에 저장되어 있지만 AES-256-GCM으로 암호화된 상태
    ↓
그 암호화 키는 Android Keystore 안에만 존재
    ↓
Android Keystore 키는 하드웨어(TEE/StrongBox)에 묶여 있어
물리적으로 해당 기기에서만 복호화 연산이 가능
    ↓
adb backup, 루팅 후 파일 복사 등으로 DB + SharedPreferences를
다른 PC나 다른 기기로 옮겨도 키가 없으므로 복호화 불가
```

즉 **"DB 파일 + 암호화된 패스프레이즈 + Keystore 키"** 세 가지가 모두 같은 기기에 있어야만 열린다.  
공격자가 기기를 물리적으로 탈취해서 파일만 뽑아가도 DB 내용을 읽을 수 없다.

---

## 4. Android 측 — E2E 암호화 전송 (ClientCryptoPipeline)

`ServerTransmitter.sendFilesAsync()` 호출 시:

```
① at-rest 복호화
   각 줄: CryptoManager.decryptToString(encrypted_line) → 평문

② 평문 해시 계산
   SHA-256(join("\n", lines)) → chainHash
   (서버의 HashService.calculateFileHash와 동일한 방식)

③ E2E 암호화 파이프라인 (ClientCryptoPipeline.encrypt)
   GZIP 압축
     ↓
   X25519 ECDH 키 합의
     서버 공개키 (X.509 DER 44바이트 → 12~44바이트 추출 = raw 32바이트)
     임시(ephemeral) 키쌍 생성
     sharedSecret = ECDH(ephemeralPriv, serverPub)
     ↓
   HKDF-SHA256 → 32바이트 세션 키 도출
     ↓
   AES-256-GCM 암호화
     AAD = deviceId (인증에 deviceId 묶음)
     ↓
   ECDSA-SHA256 서명
     서명 대상: ephemeralPub ‖ IV ‖ deviceId ‖ ciphertext
     ↓
   패킷 조립:
   [ephemeralKeyLen(4)] [ephemeralKey(32)] [IV(12)] [sigLen(4)] [sig] [ciphertext]

④ Multipart POST /logs/upload
   logFile = 암호화 패킷 (.enc)
   hashFile = chainHash (평문 SHA-256 hex)
```

---

## 5. 서버 측 — 수신·복호화·저장

`LogController.uploadLog()` → `LogService.appendDecryptedLog()`

```
① E2E 복호화 (CryptoService.decryptAndVerify)
   패킷에서 ephemeralKey, IV, sig, ciphertext 파싱
   ECDSA 서명 검증
   ECDH + HKDF → 세션 키 재도출
   AES-256-GCM 복호화 → 평문

② 해시 검증
   SHA-256(join("\n", lines)) 재계산
   hashFile의 chainHash와 비교
   불일치 시 IllegalArgumentException → 업로드 거부

③ 로그 파싱
   각 줄: "yyyy-MM-dd HH:mm:ss <content> ; serverTimestamp: ..." 형식
   → Message 객체 (deviceTimestamp, content, serverTimestamp)

④ 저장용 해시 계산 (reportService와 동일한 방식)
   재조합 문자열 → split("\r?\n") → join("\n") (trailing newline 제거)
   SHA-256 → reconstructedHash

⑤ MongoDB 저장
   Log { deviceId, logType, messages[], hash: reconstructedHash }
```

---

## 6. 서버 측 — PDF 보고서 생성

`GET /logs/analyze/{deviceId}/{startTime}/{endTime}`

```
① MongoDB에서 시간 범위 내 Log 조회

② Hash 무결성 검증 (핵심)
   각 Log의 message[] → 재조합 문자열 → 파일 작성
   calculateFileHash(파일) == log.getHash() ?
     ✓ → [Success] Hash integrity verification completed
     ✗ → [Warning] Hash mismatch! Expected: ... Found: ...

③ PDF 생성 (iText 7)
   로그 타입별 컬러 테이블
   AntiForensicLog / CallingLog / MessageLog
   BluetoothLog / FileLog / AppExecutionLog

④ Reconstructing Timeline
   모든 메시지를 deviceTimestamp 기준 오름차순 정렬
   Estimated Time Value = serverTimestamp 기반 보정 시간
   (기기 시간 조작 탐지에 핵심 — 디바이스 시계 vs 서버 시계 비교)
```

---

## 핵심 보안 설계 포인트

| 위협 | 대응 |
|------|------|
| 기기 탈취 | at-rest AES-256-GCM — 로그 파일 직접 읽기 불가 |
| 네트워크 도청 | E2E X25519+AES-256-GCM — 전송 중 복호화 불가 |
| 로그 위변조 | ForwardHashChain + 서버 hash 검증 |
| 소급 조작 | `H_i = SHA-256(M_i ‖ H_{i-1})` — 과거 조작 시 전체 체인 붕괴 |
| 재전송 공격 | ephemeral 키 — 매 전송마다 새 세션 키 |
| 신원 위조 | ECDSA 서명 — 기기 고유 Android Keystore 개인키 |
| 시간 조작 탐지 | deviceTimestamp vs serverTimestamp 비교 → PDF에 시각화 |
| 네트워크 단절 중 로그 유실 | SQLCipher 오프라인 큐 — 이중 암호화 후 WorkManager 재시도 |

---

## 전체 데이터 흐름

```
이벤트 발생
  → AES-GCM 암호화 파일 저장 + ForwardHashChain 갱신
    → 업로드 트리거 (512KB 초과 or 긴급 이벤트)
      → at-rest 복호화 → 해시 재계산 → X25519+AES-GCM E2E 암호화 → POST
          ├─ 성공 → 서버 E2E 복호화 → hash 검증 → MongoDB 저장
          │            → 분석 요청 → hash 재검증 → PDF 생성
          └─ 실패 (비행기 모드 등)
               → SQLCipher DB에 AES-GCM 암호화 후 큐잉
                    → WorkManager (네트워크 복구 감지 시 자동 재전송, 최대 5회)
```
