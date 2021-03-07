# 设置ALF UI窗口显示
stty rows 160 cols 160
# ALF 运行命令
cd /data/local/tmp/python3.9
. ./env.sh
cd ..
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
cd -
export LD_PRELOAD=/data/local/tmp/libandroid-ashmem.so
./afl-fuzz -U -i ./in -o ./out -m none -- /data/local/tmp/python3.9/usr/bin/python3.9 ./frida-afl-fuzzer -spawn /data/local/tmp/afl_test_local