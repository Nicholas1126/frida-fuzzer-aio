# 0. 手机需要联网
# 安装python3.9 环境
cd /data/local/tmp/
tar -xvzf python3.9-arm64.tar.gz
cd python3.9/
. ./env.sh
cd ..
# 安装python3.9 包管理器
python3 get-pip.py

# 安装frida库
tar -xvzf frida-14.2.13-py3.8-android-aarch64.tar.gz
cd frida-14.2.13-py3.8-android-aarch64/
# 直接拷贝egg的库到python3.9环境
cp -r frida _frida.py _frida.cpython-38-darwin.so /data/local/tmp/python3.9/usr/lib/python3.9/site-packages/

cd /data/local/tmp/python3.9/usr/lib/
ln -s /data/local/tmp/python3.9/usr/lib/libpython3.9.so ./libpython3.9.so.1.0
