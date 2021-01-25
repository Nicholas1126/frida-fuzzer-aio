#!/usr/bin/env python3

__version__ = "1.0"

import frida
import base64
import os
import sys
import time
import signal
import argparse
import tempfile
import random
import shutil




def on_message(message, data):
    pass

def main():
    DESCR = """Frida Fuzzer All In One [%s] base on frida-fuzzer
    """ % __version__

    opt = argparse.ArgumentParser(
        description=DESCR, formatter_class=argparse.RawTextHelpFormatter)
    opt.add_argument("-i", action="store", help="Folder with initial seeds")
    opt.add_argument("-o", action="store",
                    help="Output folder with intermediate seeds and crashes")
    opt.add_argument("-U", action="store_true", help="Connect to USB")
    opt.add_argument("-debug", action="store_true", help="Enable javascript debugger")
    opt.add_argument("-N", action="store",
                    help="Connect to Network (e.g.: 192.168.111.34:27042, frida-server -l 192.168.111.34:27042)")
    opt.add_argument("-spawn", action="store_true", help="Spawn instead of attach")
    opt.add_argument("-script", action="store", default="fuzzer-agent.js",
                    help="Script filename (default is fuzzer-agent.js)")
    opt.add_argument("-runtime", action="store", default="v8",
                    help="Runtime for javascript (default is v8)")
    opt.add_argument('target', nargs=argparse.REMAINDER,
                    help="Target program/pid (and arguments if spwaning)")

    args = opt.parse_args()

    if len(args.target) == 0:
        print(" >> Target not specified!")
        exit(1)

    if args.o is None:
        output_folder = tempfile.mkdtemp(prefix="frida_fuzz_out_")
        print(" >> Temporary output folder :", output_folder)
    else:
        output_folder = args.o
        if os.path.exists(output_folder):
            print(" >> %s already exists!" % output_folder)

        shutil.rmtree(output_folder)
        os.mkdir(output_folder)

    if args.i and not os.path.exists(args.i):
        print(" >> args.in doesn't exists!" )
        exit(1)

    if args.script and not os.path.exists(args.script):
        print(" >> args.script doesn't exists!" )
        exit(1)

    app_name = args.target[0]
    try:
        app_name = int(app_name)
        pid = app_name
    except:
        pass  # not a PID
    
    with open(args.script) as f:
        code = f.read()

    if args.U:  # for usb channel
        device = frida.get_usb_device()
        if args.spawn:
            pid = device.spawn(args.target)
            session = device.attach(pid)
        else:
            session = device.attach(app_name)
    elif args.N:
        device = frida.get_device_manager().add_remote_device(args.N)
        if args.spawn:
            pid = device.spawn(args.target)
            session = device.attach(pid)
        else:
            session = device.attach(app_name)
    else:
        if args.spawn:
            if os.getenv("FRIDA_FUZZER_CHILD_OUT"):
                pid = frida.spawn(args.target)
            else:
                pid = frida.spawn(args.target, stdio="pipe")
            session = frida.attach(pid)
        else:
            session = frida.attach(app_name)

    def signal_handler(sig, frame):
        print (" >> Exiting...")
        if args.spawn and not args.U and not args.N:
            print (" >> Killing", pid)
            os.kill(pid, signal.SIGKILL)
        try:
            script.unload()
            session.detach()
        except: 
            pass
        os._exit (0)
    signal.signal(signal.SIGINT, signal_handler)
    
    #https://bbs.pediy.com/thread-254695.htm
    if args.debug:
        session.enable_debugger()
    
    script = session.create_script(code, runtime=args.runtime)

    script.on('message', on_message)
    script.load()
    script.exports.interceptortarget()
    import sys
    sys.stdin.read()

    script.exports.allocmutatormemory(4096)
    payload = "test!"
    mutator_hex = script.exports.mutatorbypayload(payload.encode().hex())
    #mutator_hex = script.exports.execute(b'cat jswrite | ./radamsa'.hex(), b'r'.hex())
    print(mutator_hex)
    #script.exports.execute(b'echo $(cat jswrite | ./radamsa -s 8) > jswrite'.hex(), b'r'.hex())
    #sys.stdin.read() #不停接收不结束进程
    

if __name__ == "__main__":
    main()
    