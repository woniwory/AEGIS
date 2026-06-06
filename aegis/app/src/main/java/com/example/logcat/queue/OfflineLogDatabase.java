package com.example.logcat.queue;

import android.content.Context;
import android.util.Log;

import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

import com.example.logcat.manager.CryptoManager;

import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SupportFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * SQLCipher 기반 암호화 오프라인 큐 DB.
 * 암호화 패스프레이즈는 Android Keystore에서 동적으로 도출.
 */
@Database(entities = {OfflineLogEntity.class}, version = 1, exportSchema = false)
public abstract class OfflineLogDatabase extends RoomDatabase {

    private static final String TAG = "OfflineLogDatabase";
    private static final String DB_NAME = "aegis_offline_queue.db";
    private static final String PASSPHRASE_SENTINEL = "aegis_db_passphrase_v1";

    private static volatile OfflineLogDatabase instance;

    public abstract OfflineLogDao offlineLogDao();

    public static synchronized OfflineLogDatabase getInstance(Context ctx) {
        if (instance == null) {
            instance = buildDatabase(ctx.getApplicationContext());
        }
        return instance;
    }

    private static OfflineLogDatabase buildDatabase(Context ctx) {
        byte[] passphraseBytes = null;
        try {
            // Android Keystore로 암호화된 패스프레이즈 도출
            CryptoManager cm = CryptoManager.getInstance();
            String encryptedPassphrase = getOrCreatePassphrase(ctx, cm);
            String passphrase = cm.decryptToString(encryptedPassphrase);
            passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);

            SQLiteDatabase.loadLibs(ctx);
            SupportFactory factory = new SupportFactory(passphraseBytes);

            return Room.databaseBuilder(ctx, OfflineLogDatabase.class, DB_NAME)
                    .openHelperFactory(factory)
                    .fallbackToDestructiveMigration()
                    .build();
        } finally {
            if (passphraseBytes != null) Arrays.fill(passphraseBytes, (byte) 0);
        }
    }

    private static String getOrCreatePassphrase(Context ctx, CryptoManager cm) {
        android.content.SharedPreferences prefs =
                ctx.getSharedPreferences("aegis_db_prefs", Context.MODE_PRIVATE);
        String stored = prefs.getString("db_pass_enc", null);
        if (stored != null) return stored;

        // 최초: SecureRandom 패스프레이즈 생성 후 Keystore 암호화
        byte[] raw = new byte[32];
        new java.security.SecureRandom().nextBytes(raw);
        String rawStr = android.util.Base64.encodeToString(raw, android.util.Base64.NO_WRAP);
        Arrays.fill(raw, (byte) 0);
        String encrypted = cm.encryptString(rawStr);
        prefs.edit().putString("db_pass_enc", encrypted).apply();
        return encrypted;
    }
}
