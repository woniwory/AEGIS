package com.example.logcat.queue;

import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

/**
 * 오프라인 상태일 때 SQLCipher 암호화 DB에 버퍼링되는 로그 큐 항목.
 * logContent 및 chainHash는 CryptoManager로 암호화된 Base64 문자열.
 */
@Entity(tableName = "offline_log_queue")
public class OfflineLogEntity {

    @PrimaryKey(autoGenerate = true)
    public long id;

    @ColumnInfo(name = "device_id")
    public String deviceId;

    @ColumnInfo(name = "log_type")
    public String logType;

    /** AES-256-GCM 암호화된 로그 내용 (Base64). */
    @ColumnInfo(name = "encrypted_log_content")
    public String encryptedLogContent;

    /** 해당 시점의 hash chain 상태 (hex). */
    @ColumnInfo(name = "chain_hash")
    public String chainHash;

    @ColumnInfo(name = "created_at")
    public long createdAt;

    @ColumnInfo(name = "retry_count")
    public int retryCount;

    public OfflineLogEntity(String deviceId, String logType,
                             String encryptedLogContent, String chainHash) {
        this.deviceId = deviceId;
        this.logType = logType;
        this.encryptedLogContent = encryptedLogContent;
        this.chainHash = chainHash;
        this.createdAt = System.currentTimeMillis();
        this.retryCount = 0;
    }
}
