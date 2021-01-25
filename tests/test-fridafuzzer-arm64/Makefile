fuzz-arm64:
	@frida-compile test_ndk_aarch.js -o fuzzer-agent.js
	@mkdir -p fuzz_in fuzz_out
	@rm -rf fuzz_in fuzz_out
	@mkdir -p fuzz_in fuzz_out
	@echo "hello" > fuzz_in/testcase
	@../../frida-fuzzer -spawn -U -i fuzz_in/ -o fuzz_out/ /data/local/tmp/fridafuzzer_test
all-arm64:
	#gcc -g -o afl_test test.c
	ndk-build -B NDK_PROJECT_PATH=. APP_PLATFORM=android-22 NDK_DEBUG=1

clean:
	@rm -rf fuzz_in fuzz_out
	@rm fuzzer-agent.js fridafuzzer_test