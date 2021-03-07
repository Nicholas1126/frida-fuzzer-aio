fuzz-arm64:
	@adb push libs/arm64-v8a/afl_test /data/local/tmp/
	@frida-compile test_arm64.js -o fuzzer-agent.js
	@mkdir -p fuzz_in fuzz_out
	@rm -rf fuzz_in fuzz_out
	@mkdir -p fuzz_in fuzz_out
	@echo "aaa" > fuzz_in/testcase
	@afl-fuzz -U -i fuzz_in -o fuzz_out -m none -- /home/nicholas/.pyenv/versions/3.6.10/bin/python3.6 ../../frida-afl-fuzzer -U -spawn -C /data/local/tmp/afl_test

all-arm64:
	ndk-build -B NDK_PROJECT_PATH=. APP_PLATFORM=android-22 NDK_DEBUG=1

clean:
	@rm -rf fuzz_in fuzz_out libs obj
	@rm fuzzer-agent.js