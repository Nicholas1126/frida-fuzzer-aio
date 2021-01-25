(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
var aflinstr = require("./aflinstrumentor.js");

exports.init_callback = null;
exports.fuzzer_test_one_input = null;
exports.target_module = null;
exports.target_function = ptr(0);
var shmat_addr = Module.findExportByName(null, "shmat");

// TODO Android does not have shmat
var shmat = new NativeFunction(shmat_addr, 'pointer', ['int', 'pointer', 'int']);

var STALKER_QUEUE_CAP = 100000000;
var STALKER_QUEUE_DRAIN_INT = 1000 * 1000;


// Stalker tuning
Stalker.trustThreshold = 0;
Stalker.queueCapacity = STALKER_QUEUE_CAP;
Stalker.queueDrainInterval = STALKER_QUEUE_DRAIN_INT;

rpc.exports = {

    setupshmremote: function (shm_id) {
        aflinstr.afl_area_ptr = shm_id;
    },


    setupshmlocal: function (shm_id) {
        aflinstr.afl_area_ptr = shmat(shm_id, ptr(0), 0);
    },

    settargetremote: function () {
        // trace whole target_module
        //aflinstr.start_tracing_remote(Process.getCurrentThreadId(), exports.target_module);
        exports.init_callback();
        aflinstr.start_tracing_remote(exports.target_function, exports.target_module);
    },

    settargetlocal: function () {
        // trace whole target_module
        //aflinstr.start_tracing_local(Process.getCurrentThreadId(), exports.target_module);
        exports.init_callback();
        aflinstr.start_tracing_local(exports.target_function, exports.target_module);
    },

    fuzzingloop: function (payload_hex) {
        if (exports.fuzzer_test_one_input === null) {
            throw "ERROR: fuzzer_test_one_input not set! Cannot start the fuzzing loop!";
        }
        var payload = [];
        for(var i = 0; i < payload_hex.length; i+=2)
        {
            payload.push(parseInt(payload_hex.substring(i, i + 2), 16));
        }

        payload = new Uint8Array(payload);

        exports.fuzzer_test_one_input(payload);

        return 0;
    },

};


},{"./aflinstrumentor.js":2}],2:[function(require,module,exports){
var logger = require("./log.js");

exports.afl_area_ptr = null;

var MAP_SIZE = 65536;
var prev_loc_ptr = null;
var start_addr = null;
var end_addr = null;

exports.vmmap = function () {

  var maps = Process.enumerateModulesSync();
  var i = 0;
  
  maps.map(function(o) { o.id = i++; });
  maps.map(function(o) { o.end = o.base.add(o.size); });

  return maps;

}

exports.filter = function (target)
{
  var maps = exports.vmmap();

  if (target !== null) {
    maps.forEach(function(m) {

      if (m.name == target) {
        start_addr = m.base;
        end_addr = m.end;
      } else {
        Stalker.exclude(m);
      }

    });
  } else {
    maps.forEach(function(m) {

      if (m.name.startsWith("libpthread-") || 
        m.name.startsWith("librt-") || m.name.startsWith("frida") || 
        m.name.startsWith("libm-") || m.name.startsWith("libdl-") || 
        m.name.startsWith("ld-") || m.name.startsWith("libresolv-") || 
        m.name.startsWith("liblog")) {
          Stalker.exclude(m);
        }

    });
  }
}

exports.start_tracing_remote = function(target_function, target_module) {
  prev_loc_ptr = Memory.alloc(32);
  start_addr = ptr(0);
  end_addr = ptr("-1");

  exports.filter(target_module);

  var cur_pc = 0;
  var prev_loc = 0;
  function afl_maybe_log (context) {
    
    var cur_loc = cur_pc;
    
    cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;

    var x = exports.afl_area_ptr + (cur_loc ^ prev_loc);
    var obj = {cmd:"coverage", addr:x};
    send(obj);
    prev_loc = cur_loc >> 1;

  }
  
  var generic_transform = function (iterator) {
  
    var i = iterator.next();
    
    var cur_loc = i.address;
    
    if (cur_loc.compare(start_addr) > 0 && cur_loc.compare(end_addr) < 0)
    {
      cur_pc = cur_loc;
      iterator.putCallout(afl_maybe_log);
    }
      

    do iterator.keep()
    while ((i = iterator.next()) !== null);

  }
  

  var generic_transform_x64 = function (iterator) {
    var i = iterator.next();
    var cur_loc = i.address;
    if (cur_loc.compare(start_addr) > 0 &&
        cur_loc.compare(end_addr) < 0) {
    
      cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
      cur_loc = cur_loc.and(MAP_SIZE - 1);
      
      iterator.putPushfx();
      iterator.putPushReg("rdx");
      iterator.putPushReg("rcx");
      iterator.putPushReg("rbx");

      // rdx = cur_loc
      iterator.putMovRegAddress("rdx", cur_loc);
      // rbx = &prev_loc
      iterator.putMovRegAddress("rbx", prev_loc_ptr);
      // rcx = *rbx
      iterator.putMovRegRegPtr("rcx", "rbx");
      // rcx ^= rdx
      iterator.putXorRegReg("rcx", "rdx");
      // rdx = cur_loc >> 1
      iterator.putMovRegAddress("rdx", cur_loc.shr(1));
      // *rbx = rdx
      iterator.putMovRegPtrReg("rbx", "rdx");
      // rbx = afl_area_ptr
      iterator.putMovRegAddress("rbx", exports.afl_area_ptr);
      // rbx += rcx
      iterator.putAddRegReg("rbx", "rcx");
      // (*rbx)++
      iterator.putU8(0xfe); // inc byte ptr [rbx]
      iterator.putU8(0x03);
   
      iterator.putPopReg("rbx");
      iterator.putPopReg("rcx");
      iterator.putPopReg("rdx");
      iterator.putPopfx();
    
    }

    do iterator.keep()
    while ((i = iterator.next()) !== null);

  }

  var generic_transform_ia32 = function (iterator) {
    var i = iterator.next();
    var cur_loc = i.address;
    if (cur_loc.compare(start_addr) > 0 &&
        cur_loc.compare(end_addr) < 0) {
    
      cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
      cur_loc = cur_loc.and(MAP_SIZE - 1);
      
      iterator.putPushfx();
      iterator.putPushReg("edx");
      iterator.putPushReg("ecx");
      iterator.putPushReg("ebx");
      // edx = cur_loc
      iterator.putMovRegAddress("edx", cur_loc);
      // ebx = &prev_loc
      iterator.putMovRegAddress("ebx", prev_loc_ptr);
      // ecx = *ebx
      iterator.putMovRegRegPtr("ecx", "ebx");
      // ecx ^= edx
      iterator.putXorRegReg("ecx", "edx");
      // edx = cur_loc >> 1
      iterator.putMovRegAddress("edx", cur_loc.shr(1));
      // *ebx = edx
      iterator.putMovRegPtrReg("ebx", "edx");
      // ebx = afl_area_ptr
      iterator.putMovRegAddress("ebx", exports.afl_area_ptr);
      // ebx += ecx
      iterator.putAddRegReg("ebx", "ecx");
      // (*ebx)++
      iterator.putU8(0xfe); // inc byte ptr [ebx]
      iterator.putU8(0x03);
  
      iterator.putPopReg("ebx");
      iterator.putPopReg("ecx");
      iterator.putPopReg("edx");
      iterator.putPopfx();
    
    }
    do iterator.keep()
    while ((i = iterator.next()) !== null);
  }

  var transforms = {
    "x64": generic_transform,
    "ia32": generic_transform,
    "arm": generic_transform,
    "arm64": generic_transform
  };
  
  //var gc_cnt = 0;
        
  Interceptor.attach(target_function, {
      // This is a performance problem, wait for https://github.com/frida/frida/issues/1036
      onEnter: function (args) {
        
          Stalker.follow(Process.getCurrentThreadId(), {
            events: {
                call: false,
                ret: false,
                exec: false,
                block: false,
                compile: true
            },
            
          transform: transforms[Process.arch],
        });
      },
      onLeave: function (retval) {
          Stalker.unfollow(Process.getCurrentThreadId())
          Stalker.flush()
          //if(gc_cnt % 100 == 0){
              Stalker.garbageCollect();
          //}
          //gc_cnt++;
      }
  });
}


exports.start_tracing_local = function(target_function, target_module) {
    prev_loc_ptr = Memory.alloc(32);
    start_addr = ptr(0);
    end_addr = ptr("-1");
  
    exports.filter(target_module);
  
    var cur_pc = 0;
    var prev_loc = 0;
    function afl_maybe_log (context) {
        var cur_loc = context.pc.toInt32();
          
        cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
        cur_loc &= MAP_SIZE - 1;

        //afl_area[cur_loc ^ prev_loc]++;
        var x = exports.afl_area_ptr.add(cur_loc ^ prev_loc);
        x.writeU8((x.readU8() +1) & 0xff);

        prev_loc = cur_loc >> 1;
  
    }
    
    var generic_transform = function (iterator) {
    
      var i = iterator.next();
      
      var cur_loc = i.address;
      
      if (cur_loc.compare(start_addr) > 0 && cur_loc.compare(end_addr) < 0)
      {
        cur_pc = cur_loc;
        iterator.putCallout(afl_maybe_log);
      }
        
  
      do iterator.keep()
      while ((i = iterator.next()) !== null);
  
    }
    
  
    var generic_transform_x64 = function (iterator) {
      
      var i = iterator.next();
      var cur_loc = i.address;
      if (cur_loc.compare(start_addr) > 0 &&
          cur_loc.compare(end_addr) < 0) {
            
        cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
        cur_loc = cur_loc.and(MAP_SIZE - 1);
        
        iterator.putPushfx();
        iterator.putPushReg("rdx");
        iterator.putPushReg("rcx");
        iterator.putPushReg("rbx");
  
        // rdx = cur_loc
        iterator.putMovRegAddress("rdx", cur_loc);
        // rbx = &prev_loc
        iterator.putMovRegAddress("rbx", prev_loc_ptr);
        // rcx = *rbx
        iterator.putMovRegRegPtr("rcx", "rbx");
        // rcx ^= rdx
        iterator.putXorRegReg("rcx", "rdx");
        // rdx = cur_loc >> 1
        iterator.putMovRegAddress("rdx", cur_loc.shr(1));
        // *rbx = rdx
        iterator.putMovRegPtrReg("rbx", "rdx");
        // rbx = afl_area_ptr
        iterator.putMovRegAddress("rbx", exports.afl_area_ptr);
        // rbx += rcx
        iterator.putAddRegReg("rbx", "rcx");
        // (*rbx)++
        iterator.putU8(0xfe); // inc byte ptr [rbx]
        iterator.putU8(0x03);
     
        iterator.putPopReg("rbx");
        iterator.putPopReg("rcx");
        iterator.putPopReg("rdx");
        iterator.putPopfx();
      }
  
      do iterator.keep()
      while ((i = iterator.next()) !== null);
    }
  
    var generic_transform_ia32 = function (iterator) {
      var i = iterator.next();
      var cur_loc = i.address;
      if (cur_loc.compare(start_addr) > 0 &&
          cur_loc.compare(end_addr) < 0) {
      
        cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
        cur_loc = cur_loc.and(MAP_SIZE - 1);
        
        iterator.putPushfx();
        iterator.putPushReg("edx");
        iterator.putPushReg("ecx");
        iterator.putPushReg("ebx");
        // edx = cur_loc
        iterator.putMovRegAddress("edx", cur_loc);
        // ebx = &prev_loc
        iterator.putMovRegAddress("ebx", prev_loc_ptr);
        // ecx = *ebx
        iterator.putMovRegRegPtr("ecx", "ebx");
        // ecx ^= edx
        iterator.putXorRegReg("ecx", "edx");
        // edx = cur_loc >> 1
        iterator.putMovRegAddress("edx", cur_loc.shr(1));
        // *ebx = edx
        iterator.putMovRegPtrReg("ebx", "edx");
        // ebx = afl_area_ptr
        iterator.putMovRegAddress("ebx", exports.afl_area_ptr);
        // ebx += ecx
        iterator.putAddRegReg("ebx", "ecx");
        // (*ebx)++
        iterator.putU8(0xfe); // inc byte ptr [ebx]
        iterator.putU8(0x03);
    
        iterator.putPopReg("ebx");
        iterator.putPopReg("ecx");
        iterator.putPopReg("edx");
        iterator.putPopfx();
      
      }
      do iterator.keep()
      while ((i = iterator.next()) !== null);
    }
  
    var transforms = {
      "x64": generic_transform,
      "ia32": generic_transform,
      "arm": generic_transform,
      "arm64": generic_transform
    };

    //var gc_cnt = 0;
    Interceptor.attach(target_function, {
      // This is a performance problem, wait for https://github.com/frida/frida/issues/1036
      onEnter: function (args) {
          Stalker.follow(Process.getCurrentThreadId(), {
            events: {
                call: false,
                ret: false,
                exec: false,
                block: false,
                compile: true
            },
          transform: transforms[Process.arch],
        });
      },
      onLeave: function (retval) {
          Stalker.unfollow(Process.getCurrentThreadId())
          Stalker.flush()
          //if(gc_cnt % 100 == 0){
              Stalker.garbageCollect();
          //}
          //gc_cnt++;
      }
    });

    // Stalker.follow(thread_id, {
    //     events: {
    //         call: false,
    //         ret: false,
    //         exec: false,
    //         block: false,
    //         compile: true
    //     },
        
    //   transform: transforms[Process.arch],
    // });
  }
},{"./log.js":3}],3:[function(require,module,exports){
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
},{}],4:[function(require,module,exports){
var fuzz = require("../../frida-js/afl.js");

var TARGET_MODULE = "afl_test";
var RET_TYPE = "void";
var ARGS_TYPES = ['pointer'];
var func_handle = null;

fuzz.target_module = TARGET_MODULE;

fuzz.init_callback = function () {
  var TARGET_FUNCTION = DebugSymbol.fromName("handleClient").address;
  fuzz.target_function = TARGET_FUNCTION;
  func_handle = new NativeFunction(fuzz.target_function, RET_TYPE, ARGS_TYPES, { traps: 'all' });
}

fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload) {
  var payload_memory = payload.buffer.unwrap();

  func_handle(payload_memory);

}

},{"../../frida-js/afl.js":1}]},{},[4])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NvdXJjZXMvbm9kZS12MTMuMTMuMC1saW51eC14NjQvbGliL25vZGVfbW9kdWxlcy9mcmlkYS1jb21waWxlL25vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCIuLi8uLi9mcmlkYS1qcy9hZmwuanMiLCIuLi8uLi9mcmlkYS1qcy9hZmxpbnN0cnVtZW50b3IuanMiLCIuLi8uLi9mcmlkYS1qcy9sb2cuanMiLCJ0ZXN0X3g2NC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaEVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN4WUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN6QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
