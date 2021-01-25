fuzz-arm64:
	@frida-compile test_arm64.js -o fuzzer-agent.js
	@mkdir -p fuzz_in fuzz_out
	@rm -rf fuzz_in fuzz_out
	@mkdir -p fuzz_in fuzz_out
	@echo "aaa" > fuzz_in/testcase
	afl-fuzz -U -i fuzz_in -o fuzz_out -m none -- /home/nicholas/.pyenv/versions/3.6.10/bin/python3.6 ../../frida-afl-fuzzer -U -spawn -arch arm64 /data/local/tmp/afl_test

all-arm64:
	#gcc -g -o afl_test test.c
	ndk-build -B NDK_PROJECT_PATH=. APP_PLATFORM=android-22 NDK_DEBUG=1

clean:
	@rm -rf fuzz_in fuzz_out
	@rm frida_script.js afl_test