ndk-build -B NDK_PROJECT_PATH=. APP_PLATFORM=android-22

# cd libs/arm64-v8a/
# adb push afl-fuzz /data/local/tmp
# adb push libandroid-ashmem.so /data/local/tmp
# cd -