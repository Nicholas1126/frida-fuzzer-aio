exports.afl_area_ptr = null;
exports.target_been_trigger = false;

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

exports.start_tracing_remote = function(target_module, target_function, target_args) {
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
          if (target_args.length > 0 && exports.target_been_trigger == false) {
            for (var e = 0; e < target_args.length; e++)
            {
              target_args[e] = args[e];
            }
            exports.target_been_trigger = true;
          }
          
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


exports.start_tracing_local = function(target_module, target_function, target_args) {
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
        var x = exports.afl_area_ptr.add((cur_loc ^ prev_loc));
        x.writeU8((x.readU8() + 1) & 0xff);

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
          if (target_args.length > 0 && exports.target_been_trigger == false) {
            for (var e = 0; e < target_args.length; e++)
            {
              target_args[e] = args[e];
            }
            exports.target_been_trigger = true;
          }
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