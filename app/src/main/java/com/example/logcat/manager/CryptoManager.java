package com.example.logcat.manager;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Android Keystore AES-256-GCM 기반 로컬 로그 암호화/복호화.
 * 키는 하드웨어 보안 모듈(TEE/StrongBox)에서 생성·보관되며 절대 추출 불가.
 */
public class CryptoManager {

    private static final String TAG = "CryptoManager";
    private static final String KEY_ALIAS = "aegis_local_keystore_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    private static CryptoManager instance;

    private CryptoManager() {
        ensureKeyExists();
    }

    public static synchronized CryptoManager getInstance() {
        if (instance == null) {
            instance = new CryptoManager();
        }
        return instance;
    }

    private void ensureKeyExists() {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (!ks.containsAlias(KEY_ALIAS)) {
                KeyGenerator keyGen = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
                keyGen.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true)
                        .build());
                keyGen.generateKey();
                Log.d(TAG, "AES-256-GCM Keystore key generated: " + KEY_ALIAS);
            }
        } catch (Exception e) {
            Log.e(TAG, "Key generation failed", e);
            throw new RuntimeException("Keystore init failed", e);
        }
    }

    private SecretKey getKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
        ks.load(null);
        return (SecretKey) ks.getKey(KEY_ALIAS, null);
    }

    /**
     * 평문 바이트를 AES-256-GCM으로 암호화.
     * 출력 형식: [IV(12 bytes)][ciphertext+tag]  → Base64 인코딩 문자열 반환.
     */
    public String encrypt(byte[] plaintext) {
        byte[] iv = null;
        byte[] ciphertext = null;
        try {
            SecretKey key = getKey();
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            iv = cipher.getIV();
            ciphertext = cipher.doFinal(plaintext);

            ByteBuffer buf = ByteBuffer.allocate(iv.length + ciphertext.length);
            buf.put(iv);
            buf.put(ciphertext);
            return Base64.encodeToString(buf.array(), Base64.NO_WRAP);
        } catch (Exception e) {
            Log.e(TAG, "Encryption failed", e);
            throw new RuntimeException("Encryption failed", e);
        } finally {
            if (iv != null) Arrays.fill(iv, (byte) 0);
            if (ciphertext != null) Arrays.fill(ciphertext, (byte) 0);
        }
    }

    /**
     * Base64 인코딩된 암호문을 복호화하여 평문 바이트 반환.
     */
    public byte[] decrypt(String base64Ciphertext) {
        byte[] decoded = null;
        byte[] result = null;
        try {
            decoded = Base64.decode(base64Ciphertext, Base64.NO_WRAP);
            ByteBuffer buf = ByteBuffer.wrap(decoded);

            byte[] iv = new byte[GCM_IV_LENGTH];
            buf.get(iv);
            byte[] ciphertext = new byte[buf.remaining()];
            buf.get(ciphertext);

            SecretKey key = getKey();
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            result = cipher.doFinal(ciphertext);

            Arrays.fill(iv, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Decryption failed", e);
            throw new RuntimeException("Decryption failed", e);
        } finally {
            if (decoded != null) Arrays.fill(decoded, (byte) 0);
        }
    }

    public String encryptString(String plaintext) {
        byte[] bytes = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        try {
            return encrypt(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    public String decryptToString(String base64Ciphertext) {
        byte[] bytes = decrypt(base64Ciphertext);
        try {
            return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
