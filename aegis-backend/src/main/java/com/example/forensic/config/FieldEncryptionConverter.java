package com.example.forensic.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * MongoDB 필드 레벨 AES-256-GCM 암호화/복호화.
 * 민감 필드(message content, deviceId 등)를 DB 저장 전 암호화.
 *
 * 운영 환경: AEGIS_FIELD_ENC_KEY 환경변수(또는 Vault)에서 32바이트 Base64 키 로드.
 */
@Component
public class FieldEncryptionConverter {

    private static final Logger log = LoggerFactory.getLogger(FieldEncryptionConverter.class);
    private static final String ALGO = "AES/GCM/NoPadding";
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey secretKey;

    public FieldEncryptionConverter(@Value("${aegis.field.enc.key:}") String b64Key) {
        byte[] keyBytes = null;
        try {
            if (b64Key == null || b64Key.isBlank()) {
                // 개발 환경 fallback: 런타임 임시 키 (운영 금지)
                log.warn("AEGIS field encryption key not set — using ephemeral key (DEV ONLY)");
                keyBytes = new byte[32];
                new SecureRandom().nextBytes(keyBytes);
            } else {
                keyBytes = Base64.getDecoder().decode(b64Key);
                if (keyBytes.length != 32) throw new IllegalArgumentException("Key must be 32 bytes");
            }
            this.secretKey = new SecretKeySpec(keyBytes, "AES");
        } finally {
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /** 평문 문자열 → AES-256-GCM 암호화 → Base64 반환 */
    public String encrypt(String plaintext) {
        if (plaintext == null) return null;
        byte[] pt = null;
        byte[] iv = null;
        byte[] ct = null;
        try {
            pt = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            iv = new byte[IV_LEN];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_BITS, iv));
            ct = cipher.doFinal(pt);

            ByteBuffer buf = ByteBuffer.allocate(IV_LEN + ct.length);
            buf.put(iv);
            buf.put(ct);
            return Base64.getEncoder().encodeToString(buf.array());
        } catch (Exception e) {
            log.error("Field encryption failed", e);
            throw new RuntimeException("Field encryption failed", e);
        } finally {
            if (pt != null) Arrays.fill(pt, (byte) 0);
            if (iv != null) Arrays.fill(iv, (byte) 0);
            if (ct != null) Arrays.fill(ct, (byte) 0);
        }
    }

    /** Base64 암호문 → AES-256-GCM 복호화 → 평문 반환 */
    public String decrypt(String b64Ciphertext) {
        if (b64Ciphertext == null) return null;
        byte[] decoded = null;
        try {
            decoded = Base64.getDecoder().decode(b64Ciphertext);
            ByteBuffer buf = ByteBuffer.wrap(decoded);

            byte[] iv = new byte[IV_LEN];
            buf.get(iv);
            byte[] ct = new byte[buf.remaining()];
            buf.get(ct);

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_BITS, iv));
            byte[] pt = cipher.doFinal(ct);

            Arrays.fill(iv, (byte) 0);
            Arrays.fill(ct, (byte) 0);
            return new String(pt, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Field decryption failed — returning ciphertext as-is", e);
            return b64Ciphertext;
        } finally {
            if (decoded != null) Arrays.fill(decoded, (byte) 0);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Spring Data MongoDB Read/Write Converters (메시지 content 필드용)
    // 실제 적용은 MongoConfig에서 CustomConversions에 등록.
    // ────────────────────────────────────────────────────────────────

    @WritingConverter
    public class EncryptingWriteConverter implements Converter<String, String> {
        @Override
        public String convert(String source) {
            return encrypt(source);
        }
    }

    @ReadingConverter
    public class DecryptingReadConverter implements Converter<String, String> {
        @Override
        public String convert(String source) {
            return decrypt(source);
        }
    }
}
