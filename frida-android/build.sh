#/bin/bash

# 1.进入python3-android目录，交叉编译构建android python3.9环境
# cd ../python3-android
# ARCH=arm64 ANDROID_API=21 ./build.sh --enable-shared
# mv build python3.9
# tar -czf ../frida-android/python3.9-arm64.tar.gz python3.9

# 2.编译完成后拷贝到手机的/data/local/tmp目录
cd ../frida-android/
unzip frida-14.2.13-py3.8-android-aarch64.egg -d frida-14.2.13-py3.8-android-aarch64
tar -czf frida-14.2.13-py3.8-android-aarch64.tar.gz frida-14.2.13-py3.8-android-aarch64
rm -rf frida-14.2.13-py3.8-android-aarch64
cp ../python3-android/python3.9-arm64.tar.gz .
cp ../python3-android/python3.9-arm.tar.gz .
adb push frida-server-14.2.13-android-arm64 /data/local/tmp
adb push frida-14.2.13-py3.8-android-aarch64.tar.gz /data/local/tmp
adb push python3.9-arm64.tar.gz /data/local/tmp
adb push get-pip.py /data/local/tmp
adb push run.sh /data/local/tmp

echo "Build Done! Please execute run.sh in /data/local/tmp "