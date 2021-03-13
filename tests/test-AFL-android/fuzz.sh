# 设置ALF UI窗口显示
stty rows 160 cols 160
# ALF 运行命令
cd /data/local/tmp/python3.9
. ./env.sh
cd ..
chmod 777 afl-fuzz 
chmod 777 afl_test_local
chmod 777 libandroid-ashmem.so
chmod 777 fuzz.sh
chmod 777 frida-afl-fuzzer
mkdir in out
echo "helloworld!" > in/seed
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
cd -
export LD_PRELOAD=/data/local/tmp/libandroid-ashmem.so
export LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH
./afl-fuzz -U -i ./in -o ./out -m none -- /data/local/tmp/python3.9/usr/bin/python3.9 ./frida-afl-fuzzer -spawn /data/local/tmp/afl_test_local