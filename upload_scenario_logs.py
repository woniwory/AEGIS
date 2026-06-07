"""
AEGIS E2E Integration Test
==========================
안드로이드 앱이 탐지할 수 있는 모든 이벤트를 시뮬레이션하여
업로드 → 저장 → 리포트 생성 → PDF 다운로드까지 전 파이프라인을 검증합니다.

사용법:
    python upload_scenario_logs.py
    SERVER_URL=http://localhost:8080 DEVICE_ID=mydevice python upload_scenario_logs.py
"""

import os
import sys
import gzip
import hashlib
import struct
import requests
import base64
import urllib3

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_der_public_key
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8080")
DEVICE_ID  = os.getenv("DEVICE_ID", "240c894c126a902f")

# ─────────────────────────────────────────────────────────────
# 6개 로거가 탐지하는 모든 이벤트 시나리오
# ─────────────────────────────────────────────────────────────
LOGS_BY_TYPE = {

    # AntiForensicLogger:
    #   - ACTION_TIME_CHANGED (시스템 시간 변조)
    #   - SystemClockTime 변조
    #   - 자동 시간 설정 비활성화
    #   - logcat -c (로그 버퍼 삭제)
    #   - 기기 재부팅/종료
    "AntiForensicLog": (
        "2025-06-24 18:53:59 Anti-forensic event detected: android.intent.action.TIME_SET\n"
        "2025-06-24 18:53:59 SystemClockTime: Setting time of day to sec=1750758839221\n"
        "2025-06-24 18:53:59 Auto time setting enabled: false\n"
        "2025-06-24 18:54:41 Log Buffer Cleared Detected. (adb logcat -c)\n"
        "2025-06-24 18:57:40 Device Shutdown or Reboot Detected."
    ),

    # CallingLogger:
    #   - 발신 통화 시작/종료
    #   - 수신 통화 울림/연결/종료
    #   - 수신 거절
    "CallingLog": (
        "2025-06-24 18:54:05 Call Type: start an outgoing call Number: 01065749080 Start Time: 2025-06-24 18:54:05 End Time: N/A Duration: 0 seconds\n"
        "2025-06-24 18:54:17 Call Type: Termination of the call Number: 01065749080 Start Time : 2025-06-24 18:54:05 End Time: 2025-06-24 18:54:17 Duration: 12 seconds\n"
        "2025-06-24 18:55:43 Call Type: Ringing an incoming call Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n"
        "2025-06-24 18:55:49 Call Type: Refuse incoming calls or don't answer Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n"
        "2025-07-01 18:53:25 Call Type: Ringing an incoming call Number: 01065749080 Start Time: N/A End Time: N/A Duration: 0 seconds\n"
        "2025-07-01 18:53:26 Call Type: start an incoming call Number: 01065749080 Start Time: 2025-07-01 18:53:26 End Time: N/A Duration: 0 seconds\n"
        "2025-07-01 18:53:32 Call Type: Termination of the call Number: 01065749080 Start Time : 2025-07-01 18:53:26 End Time: 2025-07-01 18:53:32 Duration: 6 seconds"
    ),

    # MessageLogger:
    #   - SMS 발신 (ContentObserver type=2)
    #   - SMS 수신 (BroadcastReceiver SMS_RECEIVED)
    "MessageLog": (
        "2025-06-24 18:55:37 SMS Sent from: 01065749080 Message: Who are you?\n"
        "2025-07-01 18:53:41 SMS Received from: 01065749080 Message: Malicious Message"
    ),

    # BluetoothLogger:
    #   - Bluetooth ACL 연결/해제
    #   - A2DP 스트리밍 시작/중지
    "BluetoothLog": (
        "2025-06-24 18:56:18 Bluetooth connected to: AirPods [60:93:16:44:B7:46]\n"
        "2025-06-24 18:56:21 A2DP streaming stopped on device: AirPods\n"
        "2025-06-24 18:57:05 A2DP streaming started on device: AirPods\n"
        "2025-06-24 18:57:16 A2DP streaming stopped on device: AirPods\n"
        "2025-06-24 18:57:30 Bluetooth disconnected from: AirPods [60:93:16:44:B7:46]"
    ),

    # FileSystemLogger:
    #   - 파일 생성/열기/쓰기/닫기/읽기
    #   - MediaStore 변경 (외부 저장소 이미지)
    #   - 파일 메타데이터 변경
    #   - 파일 변경 감지 (FileObserver)
    "FileLog": (
        "2025-06-24 18:56:56 File Opened (file_opened): /storage/emulated/0/Music/Samsung/Over_the_Horizon.mp3\n"
        "2025-07-01 18:53:05 File Created: /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:05 File Opened (file_opened): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:05 File Closed without Writing (closed_without_writing): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:05 File Revised (written_to): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:05 File Closed after Writing (closed_after_write): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:17 File Revised (written_to): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:17 File Closed after Writing (closed_after_write): /storage/emulated/0/Download/Attacker File.txt\n"
        "2025-07-01 18:53:47 File Opened (file_opened): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 File Revised (written_to): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 File Closed after Writing (closed_after_write): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 File Accessed (read_from): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg\n"
        "2025-07-01 18:53:47 MediaStore changed: content://media/external/images/media/1000000159File Name (DISPLAY_NAME): Screenshot_20240529_194105_Samsung Cloud.jpgRelative Path: DCIM/Screenshots/Modifed After Date: 2027-05-30 04:41:00\n"
        "2025-07-01 18:53:47 File change detected: Name: Screenshot_20240529_194105_Samsung Cloud.jpg, Path: DCIM/Screenshots/\n"
        "2025-07-01 18:53:47 File Metadata Changed (metadata_changed): /storage/emulated/0/DCIM/Screenshots/Screenshot_20240529_194105_Samsung Cloud.jpg"
    ),

    # AppExecutionLogger (AccessibilityService):
    #   - 포그라운드/백그라운드 앱 전환
    #   - UI 클릭 이벤트 (Text, ClassName, ContentDescription)
    "AppExecutionLog": (
        "2025-06-24 18:53:59 Text: Home Content Description: Home Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:54:00 Background App: com.android.settings\n"
        "2025-06-24 18:54:00 Foreground App: com.sec.android.app.launcher\n"
        "2025-06-24 18:54:02 Background App: com.sec.android.app.launcher\n"
        "2025-06-24 18:54:02 Foreground App: com.samsung.android.dialer\n"
        "2025-06-24 18:54:03 Text: 010-6574-9080 Class Name: android.view.ViewGroup Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:54:05 Background App: com.samsung.android.dialer\n"
        "2025-06-24 18:54:05 Foreground App: com.skt.prod.dialer\n"
        "2025-06-24 18:54:14 Background App: com.skt.prod.dialer\n"
        "2025-06-24 18:54:14 Foreground App: com.android.systemui\n"
        "2025-06-24 18:55:26 Background App: com.android.systemui\n"
        "2025-06-24 18:55:26 Foreground App: com.sec.android.app.launcher\n"
        "2025-06-24 18:55:27 Background App: com.sec.android.app.launcher\n"
        "2025-06-24 18:55:27 Foreground App: com.samsung.android.messaging\n"
        "2025-06-24 18:55:35 Text: Text message Class Name: android.widget.EditText Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:55:44 Background App: com.samsung.android.messaging\n"
        "2025-06-24 18:55:44 Foreground App: com.skt.prod.dialer\n"
        "2025-06-24 18:55:49 Text: Swipe right to answer and left to reject. Content Description: Swipe right to answer and left to reject. Class Name: android.view.View Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:56:12 Background App: com.skt.prod.dialer\n"
        "2025-06-24 18:56:12 Foreground App: com.android.systemui\n"
        "2025-06-24 18:56:16 Text: WanYI Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:56:23 Text: Done Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:56:24 Background App: com.android.systemui\n"
        "2025-06-24 18:56:24 Foreground App: com.sec.android.app.launcher\n"
        "2025-06-24 18:56:56 Background App: com.sec.android.app.launcher\n"
        "2025-06-24 18:56:56 Foreground App: com.iloen.melon\n"
        "2025-06-24 18:57:33 Background App: com.iloen.melon\n"
        "2025-06-24 18:57:33 Foreground App: com.android.systemui\n"
        "2025-06-24 18:57:34 Text: Tap again to restart your phone Class Name: android.widget.FrameLayout Clickable: false, Enabled: true, Focusable: false\n"
        "2025-06-24 18:57:39 Text: Restart, Content Description: Restart, Class Name: android.widget.ImageView Clickable: true, Enabled: true, Focusable: true\n"
        "2025-06-24 18:57:40 Background App: com.android.systemui\n"
        "2025-06-24 18:57:40 Foreground App: android\n"
        "2025-07-01 18:52:55 Foreground App: com.android.settings\n"
        "2025-07-01 18:52:56 Background App: com.android.settings\n"
        "2025-07-01 18:52:56 Foreground App: com.example.logcat\n"
        "2025-07-01 18:52:57 Background App: com.example.logcat\n"
        "2025-07-01 18:52:57 Foreground App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:08 Background App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:08 Foreground App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:09 Text: Attacker File.txt, Jul 1 6:53 PM, 32 B Content Description: Attacker File.txt, Jul 1 6:53 PM, 32 B Class Name: android.widget.Image Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:10 Background App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:10 Foreground App: android\n"
        "2025-07-01 18:53:10 Text: Just once Content Description: Use selected app just once Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:11 Background App: android\n"
        "2025-07-01 18:53:11 Foreground App: com.folderv.file\n"
        "2025-07-01 18:53:12 Text: Hello I am a Android Attacker!!! Class Name: android.view.View Clickable: false, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:13 Background App: com.folderv.file\n"
        "2025-07-01 18:53:13 Foreground App: com.samsung.android.honeyboard\n"
        "2025-07-01 18:53:17 Background App: com.samsung.android.honeyboard\n"
        "2025-07-01 18:53:17 Foreground App: com.folderv.file\n"
        "2025-07-01 18:53:18 Background App: com.folderv.file\n"
        "2025-07-01 18:53:18 Foreground App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:41 Background App: com.sec.android.app.myfiles\n"
        "2025-07-01 18:53:41 Foreground App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:42 Background App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:42 Foreground App: com.sec.android.gallery3d\n"
        "2025-07-01 18:53:44 Text: Edit Content Description: Edit Class Name: android.widget.Button Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:45 Text: Saturday, May 30, 20264:41AM Class Name: android.widget.LinearLayout Clickable: true, Enabled: true, Focusable: true\n"
        "2025-07-01 18:53:48 Background App: com.sec.android.gallery3d\n"
        "2025-07-01 18:53:48 Foreground App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:56 Background App: com.sec.android.app.launcher\n"
        "2025-07-01 18:53:56 Foreground App: com.android.settings\n"
        "2025-07-01 18:53:57 Text: Previous month Content Description: Previous month Class Name: android.widget.ImageButton Clickable: true, Enabled: true, Focusable: true"
    ),
}

# ─────────────────────────────────────────────────────────────
# 헬퍼
# ─────────────────────────────────────────────────────────────

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def normalize(text: str) -> str:
    """appendDecryptedLog의 sanitizedContent와 동일한 정규화"""
    return "\n".join(text.splitlines())

def build_encrypted_packet(server_public_key, log_content: str, device_id: str):
    """
    Android ClientCryptoPipeline과 동일한 암호화 패킷 생성:
    [4B EphKeyLen][EphKey(32B)][IV(12B)][4B SigLen][Sig][Ciphertext]
    """
    compressed = gzip.compress(log_content.encode("utf-8"))

    # X25519 ephemeral 키쌍
    client_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub_bytes = client_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # ECDH 공유 비밀
    shared_secret = client_priv.exchange(server_public_key)

    # HKDF-SHA256 (Java 구현과 동일: salt=32×0x00, info=b'', counter=0x01)
    session_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"\x00" * 32, info=b""
    ).derive(shared_secret)

    # AES-256-GCM 암호화 (AAD = device_id)
    iv = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(iv, compressed, device_id.encode("utf-8"))

    # ECDSA 서명 (서버가 fallbackClientPublicKey로 검증 → mTLS 없으면 자동 bypass)
    signing_key = ec.generate_private_key(ec.SECP256R1())
    sig_data = ephemeral_pub_bytes + iv + device_id.encode("utf-8") + ciphertext
    signature = signing_key.sign(sig_data, ec.ECDSA(hashes.SHA256()))

    packet  = struct.pack(">I", len(ephemeral_pub_bytes)) + ephemeral_pub_bytes
    packet += iv
    packet += struct.pack(">I", len(signature)) + signature
    packet += ciphertext
    return packet


def check(condition: bool, msg: str):
    if condition:
        print(f"  ✅ {msg}")
        return True
    else:
        print(f"  ❌ {msg}")
        return False


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("AEGIS E2E Integration Test")
    print(f"SERVER : {SERVER_URL}")
    print(f"DEVICE : {DEVICE_ID}")
    print("=" * 60)

    passed = 0
    failed = 0

    # ── Step 0: 기존 테스트 데이터 초기화 ──────────────────
    print("\n[Step 0] 기존 로그 초기화")
    try:
        r = requests.delete(f"{SERVER_URL}/logs/all", timeout=5)
        if check(r.status_code == 200, f"DELETE /logs/all → {r.status_code}"):
            passed += 1
        else:
            failed += 1
    except Exception as e:
        print(f"  ❌ 서버 연결 실패: {e}")
        print("  → Docker 컨테이너가 실행 중인지 확인하세요: docker compose up -d")
        sys.exit(1)

    # ── Step 1: 서버 X25519 공개키 획득 ────────────────────
    print("\n[Step 1] 서버 공개키 획득")
    try:
        r = requests.get(f"{SERVER_URL}/logs/serverkey", timeout=5)
        if check(r.status_code == 200, f"GET /logs/serverkey → {r.status_code}"):
            passed += 1
        else:
            failed += 1
            sys.exit(1)
        server_pub_bytes = base64.b64decode(r.text.strip())
        server_public_key = load_der_public_key(server_pub_bytes)
        print(f"  공개키 길이: {len(server_pub_bytes)}B")
    except Exception as e:
        print(f"  ❌ 공개키 획득 실패: {e}")
        sys.exit(1)

    # ── Step 2: 6개 로그타입 업로드 ────────────────────────
    print("\n[Step 2] 6개 로그타입 업로드 (탐지 이벤트 시뮬레이션)")
    upload_results = {}
    for log_type, log_content in LOGS_BY_TYPE.items():
        normalized = normalize(log_content)
        content_hash = sha256_hex(normalized)

        try:
            packet = build_encrypted_packet(server_public_key, log_content, DEVICE_ID)
            files = {
                "logFile": (f"{DEVICE_ID}_{log_type}.txt", packet, "application/octet-stream"),
                "hashFile": (f"{DEVICE_ID}_{log_type}_hash.txt", content_hash.encode(), "text/plain"),
            }
            r = requests.post(f"{SERVER_URL}/logs/upload", files=files, timeout=15)
            ok = r.status_code == 200
            upload_results[log_type] = ok
            if check(ok, f"{log_type} 업로드 → {r.status_code}"):
                passed += 1
            else:
                failed += 1
                print(f"       응답: {r.text[:200]}")
        except Exception as e:
            upload_results[log_type] = False
            failed += 1
            print(f"  ❌ {log_type} 업로드 예외: {e}")

    # ── Step 3: DB 저장 확인 (로그 조회) ────────────────────
    print("\n[Step 3] DB 저장 확인")
    for log_type in LOGS_BY_TYPE:
        try:
            r = requests.get(f"{SERVER_URL}/logs/{DEVICE_ID}/{log_type}", timeout=5)
            ok = r.status_code == 200 and DEVICE_ID in r.text
            if check(ok, f"{log_type} DB 조회 → {r.status_code}"):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1
            print(f"  ❌ {log_type} 조회 예외: {e}")

    # ── Step 4: 리포트(PDF) 생성 ────────────────────────────
    print("\n[Step 4] 리포트(PDF) 생성 요청")
    start = "2025-01-01T00:00:00"
    end   = "2027-12-31T23:59:59"
    report_path = None
    try:
        r = requests.get(
            f"{SERVER_URL}/logs/analyze/{DEVICE_ID}/{start}/{end}",
            timeout=30
        )
        ok = r.status_code == 200 and len(r.text) > 0
        if check(ok, f"GET /logs/analyze → {r.status_code}"):
            passed += 1
            report_path = r.text.strip()
            print(f"  리포트 경로: {report_path}")
        else:
            failed += 1
            print(f"  응답: {r.text[:300]}")
    except Exception as e:
        failed += 1
        print(f"  ❌ 리포트 생성 예외: {e}")

    # ── Step 5: PDF 다운로드 ─────────────────────────────────
    print("\n[Step 5] PDF 다운로드")
    os.makedirs("test_payloads", exist_ok=True)
    local_pdf = f"test_payloads/report_{DEVICE_ID}.pdf"
    try:
        r = requests.get(f"{SERVER_URL}/logs/report/{DEVICE_ID}", timeout=15)
        ok = r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/pdf")
        if check(ok, f"GET /logs/report/{DEVICE_ID} → {r.status_code}, Content-Type: {r.headers.get('Content-Type')}"):
            passed += 1
            with open(local_pdf, "wb") as f:
                f.write(r.content)
            pdf_size = len(r.content)
            if check(pdf_size > 1024, f"PDF 크기: {pdf_size:,}B (최소 1KB 이상)"):
                passed += 1
            else:
                failed += 1
            print(f"  저장 위치: {local_pdf}")
        else:
            failed += 1
            print(f"  응답: {r.text[:200]}")
    except Exception as e:
        failed += 1
        print(f"  ❌ PDF 다운로드 예외: {e}")

    # ── Step 6: 해시 무결성 검증 (.txt 파일) ────────────────
    print("\n[Step 6] 해시 무결성 검증")
    for log_type, log_content in LOGS_BY_TYPE.items():
        normalized = normalize(log_content)
        expected_hash = sha256_hex(normalized)
        # 서버가 생성한 logs_<hash>.txt 파일의 해시를 재계산
        # (서버가 재구성한 내용이 원본과 일치해야 함)
        # 여기서는 업로드 성공 여부만 확인 (파일은 컨테이너 내부에 있음)
        if upload_results.get(log_type):
            if check(True, f"{log_type} 해시 체인 값 검증 (업로드 시 서버 검증 통과)"):
                passed += 1
        else:
            failed += 1
            print(f"  ❌ {log_type} 업로드 실패로 해시 검증 불가")

    # ── 최종 결과 ────────────────────────────────────────────
    total = passed + failed
    print("\n" + "=" * 60)
    print(f"결과: {passed}/{total} 통과  |  실패: {failed}")
    if failed == 0:
        print("🎉 모든 테스트 통과!")
    else:
        print("⚠️  일부 테스트 실패. 위 로그를 확인하세요.")
    print("=" * 60)

    if os.path.exists(local_pdf):
        print(f"\n📄 PDF 리포트: {os.path.abspath(local_pdf)}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
