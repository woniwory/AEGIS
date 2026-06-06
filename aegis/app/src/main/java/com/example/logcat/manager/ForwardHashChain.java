package com.example.logcat.manager;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Schneier-Kelsey 모델 기반 전방향 안전 해시 체인 구현.
 * H_i = SHA-256(M_i || H_{i-1})
 * H_0 는 초기화 시 SecureRandom으로 생성된 genesis hash.
 * 체인 상태는 암호화된 SharedPreferences에 저장되어 재부팅 후에도 유지.
 */
public class ForwardHashChain {

    private static final String TAG = "ForwardHashChain";
    private static final String PREFS_NAME = "aegis_hash_chain";
    private static final int GENESIS_BYTES = 32;

    private final String prefKey;
    private final SharedPreferences prefs;
    private byte[] currentHash;

    public ForwardHashChain(Context context, String logType) {
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        this.prefKey = "chain_" + logType;
        this.currentHash = loadOrInitChain();
    }

    private byte[] loadOrInitChain() {
        String stored = prefs.getString(prefKey, null);
        if (stored != null) {
            return hexToBytes(stored);
        }
        // 최초 실행: SecureRandom genesis hash 생성
        byte[] genesis = new byte[GENESIS_BYTES];
        new SecureRandom().nextBytes(genesis);
        prefs.edit().putString(prefKey, bytesToHex(genesis)).apply();
        Log.d(TAG, "Genesis hash created for: " + prefKey);
        return genesis;
    }

    /**
     * 새 로그 메시지를 체인에 추가하고 H_i = SHA-256(M_i || H_{i-1})를 반환.
     * 반환된 hash hex 문자열을 hash file에 기록해야 함.
     */
    public synchronized String advance(String logMessage) {
        byte[] messageBytes = logMessage.getBytes(StandardCharsets.UTF_8);
        byte[] combined = null;
        try {
            combined = new byte[messageBytes.length + currentHash.length];
            System.arraycopy(messageBytes, 0, combined, 0, messageBytes.length);
            System.arraycopy(currentHash, 0, combined, messageBytes.length, currentHash.length);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] newHash = digest.digest(combined);

            Arrays.fill(currentHash, (byte) 0);
            currentHash = newHash;
            prefs.edit().putString(prefKey, bytesToHex(currentHash)).apply();
            return bytesToHex(currentHash);
        } catch (Exception e) {
            Log.e(TAG, "Hash chain advance failed", e);
            throw new RuntimeException("Hash chain failed", e);
        } finally {
            if (combined != null) Arrays.fill(combined, (byte) 0);
            Arrays.fill(messageBytes, (byte) 0);
        }
    }

    /** 현재 체인의 최신 해시(hex)를 반환. 업로드 시 서버로 전달. */
    public synchronized String getCurrentHash() {
        return bytesToHex(currentHash);
    }

    /** 업로드 성공 후 체인을 리셋 (새 genesis 생성). */
    public synchronized void reset() {
        Arrays.fill(currentHash, (byte) 0);
        byte[] genesis = new byte[GENESIS_BYTES];
        new SecureRandom().nextBytes(genesis);
        currentHash = genesis;
        prefs.edit().putString(prefKey, bytesToHex(currentHash)).apply();
        Log.d(TAG, "Hash chain reset for: " + prefKey);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
