fuzz:
	afl-fuzz -i fuzz_in -o fuzz_out ./afl_test @@

all:
	@afl-gcc -g -o afl_test test.c
	@mkdir -p fuzz_in fuzz_out
	@echo "aaa" > fuzz_in/testcase

