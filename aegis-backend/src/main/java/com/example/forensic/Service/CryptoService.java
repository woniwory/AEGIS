package com.example.forensic.Service;

import org.springframework.stereotype.Service;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.zip.GZIPInputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@Service
public class CryptoService {

    private final KeyPair serverKeyPair;

    public CryptoService() {
        try {
            // 서버 고정 X25519 키 쌍 생성 (실 운영 시 Vault 또는 Keystore에서 로드해야 함)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            this.serverKeyPair = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("X25519 KeyPairGenerator 초기화 실패", e);
        }
    }

    public byte[] getServerPublicKeyBytes() {
        return serverKeyPair.getPublic().getEncoded();
    }

    /**
     * 클라이언트로부터 전달받은 하이브리드 암호화 패킷을 복호화하고 서명을 검증합니다.
     */
    public String decryptAndVerify(byte[] packetBytes, PublicKey clientPublicKey, String deviceId) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(packetBytes);

        // 1. 클라이언트 Ephemeral Public Key (X.509 인코딩 바이트) 읽기
        int ephemeralKeyLen = buffer.getInt();
        byte[] ephemeralKeyBytes = new byte[ephemeralKeyLen];
        buffer.get(ephemeralKeyBytes);

        // 2. IV (12 bytes) 읽기
        byte[] iv = new byte[12];
        buffer.get(iv);

        // 3. Signature 읽기
        int sigLen = buffer.getInt();
        byte[] signatureBytes = new byte[sigLen];
        buffer.get(signatureBytes);

        // 4. Ciphertext 읽기
        int ciphertextLen = buffer.remaining();
        byte[] ciphertext = new byte[ciphertextLen];
        buffer.get(ciphertext);

        // 5. ECDSA 서명 검증 (데이터 무결성 및 인증)
        // 서명 대상: EphemeralKeyBytes + IV + DeviceId + Ciphertext
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(clientPublicKey);
        sig.update(ephemeralKeyBytes);
        sig.update(iv);
        sig.update(deviceId.getBytes());
        sig.update(ciphertext);

        if (!sig.verify(signatureBytes)) {
            throw new SecurityException("🚨 ECDSA 서명 검증 실패: 패킷 위변조 감지!");
        }

        // 6. ECDH 키 합의 (X25519)
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey clientEphemeralPubKey = kf.generatePublic(new X509EncodedKeySpec(ephemeralKeyBytes));

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(serverKeyPair.getPrivate());
        ka.doPhase(clientEphemeralPubKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // 7. HKDF-SHA256을 통한 세션 키 유도 (AES-256 용 32바이트)
        byte[] sessionKeyBytes = deriveHKDFKey(sharedSecret);
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        // 8. AES-256-GCM 복호화
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, spec);
        
        // AAD로 deviceId 설정하여 결합 검증
        cipher.updateAAD(deviceId.getBytes());
        byte[] compressedPlaintext = cipher.doFinal(ciphertext);

        // 9. GZIP 압축 해제
        return decompressGZIP(compressedPlaintext);
    }

    private byte[] deriveHKDFKey(byte[] sharedSecret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec salt = new SecretKeySpec(new byte[32], "HmacSHA256"); // 단순화를 위한 zero salt
        mac.init(salt);
        byte[] prk = mac.doFinal(sharedSecret);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update((byte) 1);
        byte[] okm = mac.doFinal();
        return okm; // 32바이트 AES 키 반환
    }

    private String decompressGZIP(byte[] compressed) throws IOException {
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gis.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            return baos.toString("UTF-8");
        }
    }
}
