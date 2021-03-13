fuzz-arm64:
	@frida-compile test_arm64.js -o fuzzer-agent.js
	@cp ../../afl+U-android/libs/arm64-v8a/afl-fuzz ./afl-fuzz
	@cp ../../afl+U-android/libs/arm64-v8a/libandroid-ashmem.so ./libandroid-ashmem.so
	@patchelf --add-needed libandroid-ashmem.so ./libs/arm64-v8a/afl_test_local
	@patchelf --set-rpath /data/local/tmp ./libs/arm64-v8a/afl_test_local
	@adb push fuzzer-agent.js /data/local/tmp/
	@adb push ./libs/arm64-v8a/afl_test_local /data/local/tmp/
	@adb push ./afl-fuzz /data/local/tmp
	@adb push ./libandroid-ashmem.so /data/local/tmp
	@adb push ./fuzz.sh /data/local/tmp
	@adb push ../../frida-afl-fuzzer /data/local/tmp
	
all-arm64:
	ndk-build -B NDK_PROJECT_PATH=. APP_PLATFORM=android-22 NDK_DEBUG=1

clean:
	@rm -rf libs obj
	@rm fuzzer-agent.js libandroid-ashmem.so