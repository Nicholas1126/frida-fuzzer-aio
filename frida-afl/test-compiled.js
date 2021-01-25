(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
var debug_flag = true;
exports.consolelog = function (type, msg)
{
    if (debug_flag === true)
    {
        switch (type) {
            case 0: // error
                console.error ("[JS:E] " + msg);
                break;
            case 1:  // warn
                console.warn ("[JS:W] " + msg);
                break;
            case 2:  // log
                console.log ("[JS:L] " + msg);
                break;
            case 3:// debug
                console.log ("[JS:D] " + msg);
                break;

            default:
                send(msg);
                break;
          }
    }
    
}
},{}],2:[function(require,module,exports){
var log = require("./log.js");
var utils = require("./utils.js");
var typedef = require("./typedef.js");

function entrypoint() {
  var x = 18446744073709551615n;
  var k = 1n;
  var c = typedef.uint64_t(BigInt(18446744073709551615)).getValue();
  var d = typedef.uint64_t(k).getValue();
  c = c << d;

  var a = new typedef.uint64_t();
  a.data.setBigUint64(0, 1n, true);
  var val = a.data.getBigUint64(0, true);
  val = val << BigInt(2);
  val = val >> BigInt(2);
  

  var b = new typedef.uint32_t();
  b.setValue(8);
  var vvv = b.getValue();
}

rpc.exports = {
  interceptortarget: function (){
    entrypoint();
  },
};
},{"./log.js":1,"./typedef.js":3,"./utils.js":4}],3:[function(require,module,exports){

function UInt64_t(val) {
    
    if (!(this instanceof UInt64_t)) {
        return new UInt64_t((val));
    }

    this.data = new DataView(new ArrayBuffer(8));

    this.data.setBigUint64(0, (val) > 0n ? (val): 0n, true);

    this.setValue = function (val) {
        this.data.setBigUint64(0, (val), true);
    };

    this.getValue = function () {
        return this.data.getBigUint64(0, true);
    }
};

function UInt32_t (val) {
    
    if (!(this instanceof UInt32_t)) {
        return new UInt32_t(val);
    }

    this.data = new DataView(new ArrayBuffer(4));

    this.data.setUint32(0, val > 0 ? val: 0, true);

    this.setValue = function (val) {
        this.data.setUint32(0, val, true);
    };

    this.getValue = function () {
        return this.data.getUint32(0, true);
    }
};

function UInt16_t (val) {
    
    if (!(this instanceof UInt16_t)) {
        return new UInt16_t(val);
    }

    this.data = new DataView(new ArrayBuffer(2));

    this.data.setUint16(0, val > 0 ? val: 0, true);

    this.setValue = function (val) {
        this.data.setUint16(0, val, true);
    };

    this.getValue = function () {
        return this.data.getUint16(0, true);
    }
};

function UInt8_t (val) {
    
    if (!(this instanceof UInt8_t)) {
        return new UInt8_t(val);
    }

    this.data = new DataView(new ArrayBuffer(1));

    this.data.setUint8(0, val > 0 ? val: 0, true);

    this.setValue = function (val) {
        this.data.setUint8(0, val, true);
    };

    this.getValue = function () {
        return this.data.getUint8(0, true);
    }
};

module.exports = {
    uint64_t: UInt64_t,
    uint32_t: UInt32_t,
    uint16_t: UInt16_t,
    uint8_t: UInt8_t,
}
},{}],4:[function(require,module,exports){
/*

   frida-fuzzer - frida agent instrumentation
   ------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>
   Based on American Fuzzy Lop by Michal Zalewski

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */
var typedef = require('./typedef.js')

exports.rotl = function (x, k) {
    
    //return ( typedef.uint64_t(x).getValue() )
    return (x << k) | (x >> (64 - k));
}


exports.rand_below = function(limit) {
    if (limit <= 1) 
        return 0;

    return Math.floor(Math.random() * limit);
}

exports.hex_to_arrbuf = function(hexstr) {

  var buf = [];
  for(var i = 0; i < hexstr.length; i+=2)
      buf.push(parseInt(hexstr.substring(i, i + 2), 16));

  buf = new Uint8Array(buf);
  return buf.buffer;

}

exports.arrbuf_to_hex = function(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

exports.popen = function(payload_hex, mode_hex) {
    var popen_addr = Module.findExportByName(null, "popen");
    var f = new NativeFunction(popen_addr, 'pointer', ['pointer', 'pointer']);
  
    var cmdbuf = exports.hex_to_arrbuf(payload_hex);
    var cmd = cmdbuf.unwrap();
  
    var modebuf = exports.hex_to_arrbuf(mode_hex);
    var mode = modebuf.unwrap();
    return f(cmd, mode);
}
  
exports.pclose = function (fp) {
    var pclose_addr = Module.findExportByName(null, "pclose");
    var f = new NativeFunction(pclose_addr, 'int', ['pointer']);
    return f(fp);
}
  
exports.fread = function (buf, size, nmemb, fp) {
    var fread_addr = Module.findExportByName(null, "fread");
    var f = new NativeFunction(fread_addr, 'uint', ['pointer', 'uint', 'uint', 'pointer']);
    return f(buf, size, nmemb, fp);
}

exports.system = function(payload_hex) {
    var system_addr = Module.findExportByName(null, "system");
    var f = new NativeFunction(system_addr, 'int', ['pointer']);

    var buf = exports.hex_to_arrbuf(payload_hex);

    var cmd = buf.unwrap();
    return f(cmd);
};

exports.str_to_uint8arr = function (str) {
    // from https://gist.github.com/lihnux/2aa4a6f5a9170974f6aa

    var utf8 = [];
    for (var i = 0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6),
                      0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
            i++;
            // UTF-16 encodes 0x10000-0x10FFFF by
            // subtracting 0x10000 and splitting the
            // 20 bits of 0x0-0xFFFFF into two halves
            charcode = 0x10000 + (((charcode & 0x3ff)<<10)
                      | (str.charCodeAt(i) & 0x3ff));
            utf8.push(0xf0 | (charcode >>18),
                      0x80 | ((charcode>>12) & 0x3f),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
    }

    return new Uint8Array(utf8);

}

exports.uint8arr_to_str = (function () {
    // from https://stackoverflow.com/questions/8936984/uint8array-to-string-in-javascript

    var char_cache = new Array(128);  // Preallocate the cache for the common single byte chars
    var char_from_codept = String.fromCharCode;
    var result = [];

    return function (array) {
        var codept, byte1;
        var buff_len = array.length;

        result.length = 0;

        for (var i = 0; i < buff_len;) {
            byte1 = array[i++];

            if (byte1 <= 0x7F) {
                codept = byte1;
            } else if (byte1 <= 0xDF) {
                codept = ((byte1 & 0x1F) << 6) | (array[i++] & 0x3F);
            } else if (byte1 <= 0xEF) {
                codept = ((byte1 & 0x0F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
            } else if (String.fromCodePoint) {
                codept = ((byte1 & 0x07) << 18) | ((array[i++] & 0x3F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
            } else {
                codept = 63;    // Cannot convert four byte code points, so use "?" instead
                i += 3;
            }

            result.push(char_cache[codept] || (char_cache[codept] = char_from_codept(codept)));
        }

        return result.join('');
    };
})();

exports.locate_diffs = function (buf1, buf2) {

    var a = new Uint8Array(buf1);
    var b = new Uint8Array(buf2);

    var f_loc = null;
    var l_loc = null;
    var range = Math.min(a.byteLength, b.byteLength);

    for (var i = 0; i < range; i++) {
        if (a[i] !== b[i]) {
            if (f_loc === null) f_loc = i;
            l_loc = i;
        }
    }

    return [f_loc, l_loc];

}

},{"./typedef.js":3}]},{},[2])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NvdXJjZXMvbm9kZS12MTMuMTMuMC1saW51eC14NjQvbGliL25vZGVfbW9kdWxlcy9mcmlkYS1jb21waWxlL25vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJsb2cuanMiLCJ0ZXN0LmpzIiwidHlwZWRlZi5qcyIsInV0aWxzLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0FDQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN6QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDM0JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbEZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
