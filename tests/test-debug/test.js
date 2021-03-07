var debug_flag = true;

function debuglog(type, msg) {
  if (debug_flag === true) {
    switch (type) {
      case 0: // error
        console.error("[JS:E] " + msg);
        break;
      case 1:  // warn
        console.warn("[JS:W] " + msg);
        break;
      case 2:  // log
        console.log("[JS:L] " + msg);
        break;
      default: // debug
        console.log("[JS:D] " + msg);
        break;
    }
  }

}

var hex_to_arrbuf = function (hexstr) {

  var buf = [];
  for (var i = 0; i < hexstr.length; i += 2)
    buf.push(parseInt(hexstr.substring(i, i + 2), 16));

  buf = new Uint8Array(buf);
  return buf.buffer;

}

var system = function (payload_hex) {
  var system_addr = Module.findExportByName(null, "system");
  var system = new NativeFunction(system_addr, 'int', ['pointer']);

  var buf = hex_to_arrbuf(payload_hex);

  var cmd = buf.unwrap();
  return system(cmd);
};

function popen (payload_hex, mode_hex) {
  var popen_addr = Module.findExportByName(null, "popen");
  var f = new NativeFunction(popen_addr, 'pointer', ['pointer', 'pointer']);

  var cmdbuf = hex_to_arrbuf(payload_hex);
  var cmd = cmdbuf.unwrap();

  var modebuf = hex_to_arrbuf(mode_hex);
  var mode = modebuf.unwrap();
  return f(cmd, mode);
};

function pclose (fp) {
  var pclose_addr = Module.findExportByName(null, "pclose");
  var f = new NativeFunction(pclose_addr, 'int', ['pointer']);

  return f(fp);
};

function fread (buf, size, nmemb, fp) {
  var fread_addr = Module.findExportByName(null, "fread");
  var f = new NativeFunction(fread_addr, 'uint', ['pointer', 'uint', 'uint', 'pointer']);

  return f(buf, size, nmemb, fp);
};

var mutator_buf = ptr(0);
var mutator_size = 1024;



function buf2hex(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}
function str2ab(str) {
  var buf = new ArrayBuffer(str.length*2);
  var bufView = new Uint8Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

// var shmat_addr = Module.findExportByName(null, "shmat");
// var shmat = new NativeFunction(shmat_addr, 'pointer', ['int', 'pointer', 'int']);
// addr = shmat(3, ptr(0), 0);

//size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
rpc.exports = {
  allocmutatormemory: function (size){
    mutator_buf = Memory.alloc(size);
    mutator_size = size;
  },

  mutatorbycommand: function (cmd_hex, mode_hex) {
    var fp = popen(cmd_hex, mode_hex);
    fread(mutator_buf, 1, mutator_size, fp);
    pclose(fp);
    return buf2hex(mutator_buf.readByteArray(mutator_size));
  },
  mutatorbypayload: function (payload_hex) {
    payload_hex = "6563686f20" + payload_hex + "207c202e2f726164616d7361";
    var fp = popen(payload_hex, "72");
    var readbytes = fread(mutator_buf, 1, mutator_size, fp);
    pclose(fp);
    return buf2hex(mutator_buf.readByteArray(readbytes));
  },
  interceptortarget: function () {
    
    var TARGET_FUNCTION = DebugSymbol.fromName("handleClient").address;
    console.log((TARGET_FUNCTION));
    Interceptor.attach(TARGET_FUNCTION, {
      // This is a performance problem, wait for https://github.com/frida/frida/issues/1036
      onEnter: function (args)
      {
        console.log(args);
        
        console.log(args[0]);
        console.log(args[1]);
        
        console.log("argv[0] : " + args[0].readPointer())
        console.log("argv[1] : " + args[1].readPointer())
      }
    });
    var RET_TYPE = "void";
    var ARGS_TYPES = ['pointer'];
    var func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES, { traps: 'all' });
    var payload = Memory.alloc(8);
    func_handle(payload);
  },
};