fuzz-x64:
	@frida-compile test_x64.js -o fuzzer-agent.js
	@mkdir -p fuzz_in fuzz_out
	@rm -rf fuzz_in fuzz_out
	@mkdir -p fuzz_in fuzz_out
	@echo "aaa" > fuzz_in/testcase
	afl-fuzz -U -i fuzz_in -o fuzz_out -m none -- /home/nicholas/.pyenv/versions/3.6.10/bin/python3.6 ../../frida-afl-fuzzer -spawn ./afl_test

all-x64:
	gcc -g -o afl_test test.c

clean:
	@rm -rf fuzz_in fuzz_out
	@rm fuzzer-agent.js afl_test