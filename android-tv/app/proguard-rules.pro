# Keep native methods and classes used by JNI
-keepclassmembers class * {
    native <methods>;
}

-keep class com.corvofeng.fakeatv.AtvNative** { *; }
-keep interface com.corvofeng.fakeatv.AtvNative$** { *; }
-keep class com.corvofeng.fakeatv.DeviceInfo** { *; }
-keep class com.corvofeng.fakeatv.AtvService** { *; }
-keep class com.corvofeng.fakeatv.AtvAccessibilityService** { *; }
-keep class com.corvofeng.fakeatv.BootReceiver** { *; }
-keep class com.corvofeng.fakeatv.MainActivity** { *; }
-keep class com.corvofeng.fakeatv.PersistentInput { *; }

# Keep annotations & signature
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# Leanback / AndroidX
-dontwarn androidx.leanback.**
