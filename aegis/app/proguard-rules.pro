# AEGIS ProGuard/R8 Security Configuration

# ─── 디버그 메타데이터 제거 ───────────────────────────────
-dontwarn **
-optimizationpasses 5
-allowaccessmodification
-mergeinterfacesaggressively
-repackageclasses ''

# 소스 파일명 및 라인 번호 정보 제거 (리버스 엔지니어링 방지)
-renamesourcefileattribute SourceFile

# ─── 필수 Keep 규칙 ─────────────────────────────────────

# Android 기본 컴포넌트 유지
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# WorkManager Worker 클래스 유지 (리플렉션으로 인스턴스화)
-keep class * extends androidx.work.Worker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# Room Entity / DAO 유지 (Room 어노테이션 프로세서 필요)
-keep @androidx.room.Entity class *
-keep @androidx.room.Dao interface *
-keep @androidx.room.Database class *

# SQLCipher 유지
-keep class net.sqlcipher.** { *; }
-keep class net.sqlcipher.database.** { *; }

# BouncyCastle 유지
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# OkHttp 유지
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**

# Gson 유지
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.google.gson.** { *; }

# Android Keystore 관련 클래스 유지
-keep class android.security.keystore.** { *; }

# ─── 문자열 암호화 (R8 전용) ────────────────────────────
# R8 full mode에서 문자열 난독화 활성화
-assumevalues class android.os.Build {
    public static java.lang.String MODEL return "";
}

# ─── 불필요한 로그 제거 (릴리즈) ────────────────────────
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
    public static int i(...);
}
