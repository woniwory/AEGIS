package com.example.logcat.manager;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 전방향 안전 암호화 파이프라인:
 * 1. GZIP 압축
 * 2. X25519 ECDH + HKDF-SHA256 → 세션 키 도출
 * 3. AES-256-GCM 암호화 (AAD = deviceId)
 * 4. ECDSA-SHA256 서명
 *
 * 패킷 포맷 (서버 CryptoService.decryptAndVerify와 동일):
 * [ephemeralKeyLen(4)][ephemeralKey][IV(12)][sigLen(4)][sig][ciphertext]
 */
public class ClientCryptoPipeline {

    private static final String TAG = "ClientCryptoPipeline";
    private static final String SIGNING_KEY_ALIAS = "aegis_device_signing_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    private final byte[] serverX25519PublicKeyRaw; // 서버의 X25519 공개키 32바이트 원시값
    private final String deviceId;

    public ClientCryptoPipeline(byte[] serverX25519PublicKeyRaw, String deviceId) {
        this.serverX25519PublicKeyRaw = serverX25519PublicKeyRaw.clone();
        this.deviceId = deviceId;
        ensureSigningKeyExists();
    }

    private void ensureSigningKeyExists() {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (!ks.containsAlias(SIGNING_KEY_ALIAS)) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
                kpg.initialize(new KeyGenParameterSpec.Builder(SIGNING_KEY_ALIAS,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build());
                kpg.generateKeyPair();
                Log.d(TAG, "ECDSA signing key created in Keystore");
            }
        } catch (Exception e) {
            Log.e(TAG, "Signing key init failed", e);
            throw new RuntimeException("Signing key init failed", e);
        }
    }

    /** 기기의 ECDSA 공개키를 반환 (서버 등록용). */
    public PublicKey getDevicePublicKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        return ks.getCertificate(SIGNING_KEY_ALIAS).getPublicKey();
    }

    /**
     * 평문 로그 문자열을 전체 암호화 파이프라인으로 처리하여 바이트 패킷 반환.
     * 이 패킷을 그대로 서버 /logs/upload로 전송.
     */
    public byte[] encrypt(String plaintext) throws Exception {
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] compressed = null;
        byte[] ephemeralPrivRaw = new byte[32];
        byte[] sessionKeyBytes = null;
        byte[] iv = null;
        byte[] ciphertext = null;

        try {
            // Step 1: GZIP 압축
            compressed = gzip(plaintextBytes);

            // Step 2: X25519 임시 키 쌍 생성 (BouncyCastle)
            SecureRandom rng = new SecureRandom();
            rng.nextBytes(ephemeralPrivRaw);
            X25519PrivateKeyParameters ephemeralPriv = new X25519PrivateKeyParameters(ephemeralPrivRaw, 0);
            X25519PublicKeyParameters ephemeralPub = ephemeralPriv.generatePublicKey();
            byte[] ephemeralPubRaw = ephemeralPub.getEncoded(); // 32 bytes

            // X25519 키 합의
            X25519Agreement agreement = new X25519Agreement();
            agreement.init(ephemeralPriv);
            byte[] sharedSecret = new byte[agreement.getAgreementSize()];
            X25519PublicKeyParameters serverPub = new X25519PublicKeyParameters(serverX25519PublicKeyRaw, 0);
            agreement.calculateAgreement(serverPub, sharedSecret, 0);

            // HKDF-SHA256으로 세션 키 도출 (32 bytes AES-256)
            sessionKeyBytes = hkdfSha256(sharedSecret);
            Arrays.fill(sharedSecret, (byte) 0);

            // Step 3: AES-256-GCM 암호화
            iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(deviceId.getBytes(StandardCharsets.UTF_8));
            ciphertext = cipher.doFinal(compressed);

            // Step 4: ECDSA 서명 (ephemeralPub + iv + deviceId + ciphertext)
            byte[] signature = sign(ephemeralPubRaw, iv, ciphertext);

            // Step 5: 패킷 조립
            // [ephemeralKeyLen(4)][ephemeralKey(32)][IV(12)][sigLen(4)][sig][ciphertext]
            ByteBuffer packet = ByteBuffer.allocate(
                    4 + ephemeralPubRaw.length + GCM_IV_LENGTH + 4 + signature.length + ciphertext.length);
            packet.putInt(ephemeralPubRaw.length);
            packet.put(ephemeralPubRaw);
            packet.put(iv);
            packet.putInt(signature.length);
            packet.put(signature);
            packet.put(ciphertext);
            return packet.array();

        } finally {
            Arrays.fill(plaintextBytes, (byte) 0);
            if (compressed != null) Arrays.fill(compressed, (byte) 0);
            Arrays.fill(ephemeralPrivRaw, (byte) 0);
            if (sessionKeyBytes != null) Arrays.fill(sessionKeyBytes, (byte) 0);
            if (iv != null) Arrays.fill(iv, (byte) 0);
            if (ciphertext != null) Arrays.fill(ciphertext, (byte) 0);
        }
    }

    private byte[] sign(byte[] ephemeralPubRaw, byte[] iv, byte[] ciphertext) throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        PrivateKey signingKey = (PrivateKey) ks.getKey(SIGNING_KEY_ALIAS, null);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(signingKey);
        sig.update(ephemeralPubRaw);
        sig.update(iv);
        sig.update(deviceId.getBytes(StandardCharsets.UTF_8));
        sig.update(ciphertext);
        return sig.sign();
    }

    private byte[] hkdfSha256(byte[] ikm) throws Exception {
        // HKDF-Extract (zero salt)
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        // HKDF-Expand (T(1) = HMAC-SHA256(PRK, 0x01))
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update((byte) 1);
        byte[] okm = mac.doFinal();
        Arrays.fill(prk, (byte) 0);
        return okm; // 32바이트
    }

    private byte[] gzip(byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gos = new GZIPOutputStream(baos)) {
            gos.write(data);
        }
        return baos.toByteArray();
    }
}
