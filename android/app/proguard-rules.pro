# kotlinx-serialization is used only through the JsonElement tree API (no reflection, no @Serializable).
-dontwarn org.slf4j.**
# zxing-android-embedded ships its own consumer rules; CaptureActivity is referenced from its manifest.
-keep class com.journeyapps.barcodescanner.** { *; }
