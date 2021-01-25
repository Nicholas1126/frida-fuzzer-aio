(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
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

var config  = require("./config.js");
var queue = require("./queue.js");

exports.trace_bits  = Memory.alloc(config.MAP_SIZE);
exports.virgin_bits = Memory.alloc(config.MAP_SIZE);
for (var i = 0; i < config.MAP_SIZE; i += 4)
  exports.virgin_bits.add(i).writeU32(0xffffffff);

exports.top_rated = Memory.alloc(config.MAP_SIZE * Process.pointerSize);
exports.score_changed = false;

exports.map_rate = 0;

/* Init count class lookup */

var count_class_lookup8 = new Uint8Array(256);
count_class_lookup8[0] = 0;
count_class_lookup8[1] = 1;
count_class_lookup8[2] = 2;
count_class_lookup8[4] = 3;
for (var i = 4; i <= 7; ++i)
  count_class_lookup8[i] = 8;
for (var i = 8; i <= 15; ++i)
  count_class_lookup8[i] = 16;
for (var i = 16; i <= 31; ++i)
  count_class_lookup8[i] = 32;
for (var i = 32; i <= 127; ++i)
  count_class_lookup8[i] = 64;
for (var i = 128; i <= 255; ++i)
  count_class_lookup8[i] = 128;

var count_class_lookup16_ptr = Memory.alloc(65536 * 2);

for (var b1 = 0; b1 < 256; b1++) {
  for (var b2 = 0; b2 < 256; b2++) {
    count_class_lookup16_ptr.add(((b1 << 8) + b2) * 2).writeU16(
      (count_class_lookup8[b1] << 8) | count_class_lookup8[b2]
    );
  }
}

exports.count_class_lookup16 = count_class_lookup16_ptr;

exports.__cm = new CModule(`

#include <stdint.h>
#include <stdio.h>
#include <glib.h>

#define MAP_SIZE __MAP_SIZE__

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;

struct __attribute__((packed)) QEntry {

  u8* buf;
  u8* trace_mini;
  u32 size;
  u32 exec_ms;
  u32 tc_ref;
  u8 favored;
  u8 was_fuzzed;

};

void classify_counts(u32* mem, u16* count_class_lookup16) {

  u32 i = MAP_SIZE >> 2;
  
  while (i--) {
  
    /* Optimize for sparse bitmaps. */

    if (*mem) {
      
      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    ++mem;

  }

}

int has_new_bits(u8* trace_bits, u8* virgin_map) {

  u32* current = (u32*)trace_bits;
  u32* virgin = (u32*)virgin_map;

  u32 i = MAP_SIZE >> 2;

  int ret = 0;

  while (i--) {

    if (*current && (*current & *virgin)) {

      if (ret < 2) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
          ret = 2;
        else
          ret = 1;

      }

      *virgin &= ~*current;

    }

    ++current;
    ++virgin;

  }

  return ret;

}

static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}

s32 update_bitmap_score_body(struct QEntry* q, struct QEntry** top_rated, u8* trace_bits, u8* virgin_bits) {

  u32 fav_factor = q->exec_ms * q->size;
  s32 cnt = 0;
  u8 score_changed = 0;
  u32 i;

  for (i = 0; i < MAP_SIZE; ++i) {
  
    if (trace_bits[i]) {

      if (top_rated[i]) {

        /* Faster-executing or smaller test cases are favored. */
  
        if (fav_factor > top_rated[i]->exec_ms * top_rated[i]->size)
          continue;
  
        if (!--top_rated[i]->tc_ref) {
          g_free(top_rated[i]->trace_mini);
          top_rated[i]->trace_mini = NULL;
        }
  
      }
  
      /* Insert ourselves as the new winner. */
  
      top_rated[i] = q;
      q->tc_ref++;
      
      if (q->trace_mini == NULL) {
  
        q->trace_mini = g_malloc0(MAP_SIZE >> 3);
        minimize_bits(q->trace_mini, trace_bits);
  
      }
  
      score_changed = 1;

    }
    
    if (virgin_bits[i] != 0xff)
      ++cnt;
  
  }
  
  if (score_changed) // dirty hack to return 2 values
    return -cnt;
  return cnt;

}

  `.replace("__MAP_SIZE__", ""+config.MAP_SIZE)
);

exports.classify_counts = new NativeFunction(
  exports.__cm.classify_counts,
  "void",
  ["pointer", "pointer"]
);

exports.has_new_bits = new NativeFunction(
  exports.__cm.has_new_bits,
  "int",
  ["pointer", "pointer"]
);

var update_bitmap_score_body = new NativeFunction(
  exports.__cm.update_bitmap_score_body,
  "int",
  ["pointer", "pointer", "pointer", "pointer"]
);

exports.update_bitmap_score = function (q) {

  if (config.SKIP_SCORE_FAV) return;

  var cnt = update_bitmap_score_body(q.ptr, exports.top_rated, exports.trace_bits, exports.virgin_bits);
  if (cnt < 0) {
    exports.score_changed = true;
    cnt = -cnt;
  }

  exports.map_rate = cnt * 100 / config.MAP_SIZE;

}

exports.save_if_interesting = function (buf, exec_ms) {
  
  var hnb = exports.has_new_bits(exports.trace_bits, exports.virgin_bits);
  if (hnb == 0)
    return true;
  
  queue.add(buf, exec_ms, (hnb == 2));
  exports.update_bitmap_score(queue.last());

  return false;  
  
}

},{"./config.js":2,"./queue.js":7}],2:[function(require,module,exports){
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

exports.mutator_size = 4096;

exports.MAP_SIZE = 65536; // 2^16, AFL default
//exports.MAP_SIZE = 32768; // 2^15, small APIs doesn't require a large map
//exports.MAP_SIZE = 16384; // 2^14, small APIs doesn't require a large map

exports.MAX_FILE = 1024*6;
// after timeout abort fuzzing
exports.TIMEOUT = 10*1000; // 10 seconds

exports.HAVOC_STACK_POW2 = 7;

exports.HAVOC_CYCLES = 256;
exports.SPLICE_HAVOC = 32;

exports.SPLICE_CYCLES = 15;

exports.HAVOC_BLK_SMALL  = 32;
exports.HAVOC_BLK_MEDIUM = 128;
exports.HAVOC_BLK_LARGE  = 1500;
exports.HAVOC_BLK_XL     = 32768;

exports.INTERESTING_8  = [-128, -1, 0, 1, 16, 32, 64, 100, 127];
exports.INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767];
exports.INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647];

exports.ARITH_MAX = 35;

exports.SKIP_TO_NEW_PROB   = 99;
exports.SKIP_NFAV_OLD_PROB = 95;
exports.SKIP_NFAV_NEW_PROB = 75;

// The favorite testcases scoring, slowdown the fuzzer but make also it more effective
exports.SKIP_SCORE_FAV = false;

exports.QUEUE_CACHE_MAX_SIZE = 512*1024*1024; // 512 MB

exports.UPDATE_TIME = 5*1000; // 5 seconds

},{}],3:[function(require,module,exports){
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

var queue = require("./queue.js");
var stages = require("./stages.js");
var config = require("./config.js");
var mutator = require("./mutator.js");
var instr = require("./instrumentor.js");
var bitmap = require("./bitmap.js");
var utils = require("./utils.js");
var log = require("./log.js");
exports.queue = queue;
exports.stages = stages;
exports.config = config;
exports.mutator = mutator;
exports.instr = instr;
exports.bitmap = bitmap;
exports.utils = utils;

/* Define this to exclude other modules from instrumentation */
exports.target_module = null;
/* MANDATORY: harness function */
exports.fuzzer_test_one_input = null;
/* If true, the user has to call fuzzing_loop() manually in a callback
   (see Java example, fuzzing_loop cannot be called during script loading) */
exports.manual_loop_start = false;
exports.init_callback = function () {}

// by default stages are from FidgetyAFL
exports.stages_list = [
  stages.havoc_stage,
  stages.splice_stage,
];

exports.dictionary = [];

function normalize_dict () {

  var d = exports.dictionary;
  // Accepted types are: Array Uint8Array ArrayBuffer String
  for (var i = 0; i < d.length; ++i) {
  
    if (Array.isArray(d[i]) || (d[i] instanceof ArrayBuffer))
      d[i] = new Uint8Array(d[i]);

    else if (typeof d[i] === 'string' || (d[i] instanceof String))
      d[i] = utils.str_to_uint8arr(d[i]);

    else if (!(d[i] instanceof Uint8Array))
      throw "ERROR: unsupported type for a fuzzer dictionary";
  
  }

}

exports.fuzzing_loop = function () {

  if (exports.fuzzer_test_one_input === null) {
    throw "ERROR: fuzzer_test_one_input not set! Cannot start the fuzzing loop!";
  }

  var payload = null; // Uint8Array

  if (ArrayBuffer.transfer === undefined) {
  
    var runner = function(/* ArrayBuffer */ arr_buf) {
    
      if (arr_buf.byteLength > config.MAX_FILE)
        payload = new Uint8Array(arr_buf.slice(0, config.MAX_FILE));
      else
        payload = new Uint8Array(arr_buf);

      exports.fuzzer_test_one_input(payload);

    }
  
  } else {
  
    var runner = function(/* ArrayBuffer */ arr_buf) {
  
      if (arr_buf.byteLength > config.MAX_FILE)
        payload = new Uint8Array(arr_buf.transfer(arr_buf, config.MAX_FILE));
      else
        payload = new Uint8Array(arr_buf);

      exports.fuzzer_test_one_input(payload);

    }
  
  }
  
  normalize_dict();
  
  Process.setExceptionHandler(function (details) {
    send({
      "event": "crash",
      "err": details,
      "stage": stages.stage_name,
      "cur": queue.cur_idx,
      "total_execs": stages.total_execs,
      "pending_fav": queue.pending_favored,
      "favs": queue.favoreds,
      "map_rate": bitmap.map_rate,
    }, payload);
    return false;
  });
  
  instr.start_tracing(Process.getCurrentThreadId(), exports.target_module);

  log.consolelog(4, " >> Dry run...");

  stages.dry_run(runner);
  queue.cull();

  log.consolelog(4, " >> Starting fuzzing loop...");

  while (true) {

    var buf = queue.next();
    
    queue.cull();

    if (queue.pending_favored > 0) {

      if ((queue.cur.was_fuzzed || !queue.cur.favored) &&
          utils.UR(100) < config.SKIP_TO_NEW_PROB)
        continue;

    } else if (!queue.cur.favored && queue.size() > 10) {

      if (!queue.cur.was_fuzzed)
        if (utils.UR(100) < config.SKIP_NFAV_NEW_PROB)
          continue;
      else
        if (utils.UR(100) < config.SKIP_NFAV_OLD_PROB)
          continue;

    }
    
    bitmap.update_bitmap_score(queue.cur);

    for(var stage of exports.stages_list)
      stage(buf, runner);

    if (!queue.cur.was_fuzzed) {
    
      queue.cur.was_fuzzed = true;
      if (queue.cur.favored)
        queue.pending_favored--;
    
    }

  }

}

rpc.exports.loop = function () {

  exports.init_callback();

  if (exports.manual_loop_start) return;

  exports.fuzzing_loop();

}

},{"./bitmap.js":1,"./config.js":2,"./instrumentor.js":4,"./log.js":5,"./mutator.js":6,"./queue.js":7,"./stages.js":8,"./utils.js":9}],4:[function(require,module,exports){
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

var config = require("./config.js");
var bitmap = require("./bitmap.js");

// trustThreshold must be 0, don't change it and especially don't set it to -1
Stalker.trustThreshold = 0;

exports.prev_loc_map = {}

exports.start_tracing = function(thread_id, target_module) {
    
  var start_addr = ptr(0);
  var end_addr = ptr("-1");

  var maps = function() {

      var maps = Process.enumerateModulesSync();
      var i = 0;
      
      maps.map(function(o) { o.id = i++; });
      maps.map(function(o) { o.end = o.base.add(o.size); });

      return maps;

  }();

  if (target_module !== null) {
    maps.forEach(function(m) {

      if (m.name == target_module || m == target_module) {
        start_addr = m.base;
        end_addr = m.end;
      } else {
        Stalker.exclude(m);
      }

    });
  } else {
    maps.forEach(function(m) {

      if (m.name.startsWith("libc.") || m.name.startsWith("libSystem.") || m.name.startsWith("frida")) {
        Stalker.exclude(m);
      }

    });
  }

  var prev_loc_ptr = exports.prev_loc_map[thread_id];
  if (prev_loc_ptr === undefined) {
    prev_loc_ptr = Memory.alloc(32);
    exports.prev_loc_map[thread_id] = prev_loc_ptr;
  }

  var transform = undefined;
  if (Process.arch == "ia32") {

    // Fast inline instrumentation for x86
    exports.transform_ia32 = function (iterator) {
      
      var i = iterator.next();
      
      var cur_loc = i.address;
      
      if (cur_loc.compare(start_addr) > 0 &&
          cur_loc.compare(end_addr) < 0) {
      
        cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
        cur_loc = cur_loc.and(config.MAP_SIZE - 1);
        
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
        // ebx = bitmap.trace_bits
        iterator.putMovRegAddress("ebx", bitmap.trace_bits);
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

    };

    transform = exports.transform_ia32;

  } else if (Process.arch == "x64") {

    // Fast inline instrumentation for x86_64
    exports.transform_x64 = function (iterator) {
      
      var i = iterator.next();
      
      var cur_loc = i.address;
      
      if (cur_loc.compare(start_addr) > 0 &&
          cur_loc.compare(end_addr) < 0) {
      
        cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
        cur_loc = cur_loc.and(config.MAP_SIZE - 1);
        
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
        // rbx = bitmap.trace_bits
        iterator.putMovRegAddress("rbx", bitmap.trace_bits);
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

    };

    transform = exports.transform_x64;
  
  } else {
  
    exports.__cm = new CModule(`

    #include <stdint.h>
    #include <gum/gumstalker.h>
  
    typedef uint8_t u8;
    typedef uint16_t u16;
    typedef uint32_t u32;
  
    static void afl_maybe_log (GumCpuContext * cpu_context, gpointer user_data) {
  
      u8 * trace_bits = (u8*)(__TRACE_BITS__);
      uintptr_t * prev_loc_ptr = (uintptr_t*)(__PREV_LOC__);
      
      uintptr_t cur_loc = (uintptr_t)user_data;
      
      trace_bits[cur_loc ^ (*prev_loc_ptr)]++;
      *prev_loc_ptr = cur_loc >> 1;
  
    }
  
    void transform (GumStalkerIterator * iterator, GumStalkerWriter * output, gpointer user_data) {
  
      cs_insn * i;
      gum_stalker_iterator_next (iterator, &i);
      
      uintptr_t cur_loc = i->address;
      
      if (cur_loc >= (__START__) && cur_loc < (__END__)) {
      
        cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
        cur_loc &= (__MAP_SIZE__) - 1;
      
        gum_stalker_iterator_put_callout (iterator, afl_maybe_log, (gpointer)cur_loc, NULL);
      
      }
  
      do gum_stalker_iterator_keep (iterator);
      while (gum_stalker_iterator_next (iterator, &i));
  
    }
  
    `.replace("__TRACE_BITS__", bitmap.trace_bits.toString())
     .replace("__PREV_LOC__", prev_loc_ptr.toString())
     .replace("__START__", start_addr.toString())
     .replace("__END__", end_addr.toString())
     .replace("__MAP_SIZE__", config.MAP_SIZE.toString())
    );

    transform = exports.__cm.transform;

  }
  
  Stalker.follow(thread_id, {
      events: {
          call: false,
          ret: false,
          exec: false,
          block: false,
          compile: true
      },
      
    transform: transform
  });

}

},{"./bitmap.js":1,"./config.js":2}],5:[function(require,module,exports){
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
},{}],6:[function(require,module,exports){
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

var config = require("./config.js");
var utils = require("./utils.js");
var index = require("./index.js");
var log = require("./log.js");

var interesting_8  = config.INTERESTING_8;
var interesting_16 = interesting_8.concat(config.INTERESTING_16);
var interesting_32 = interesting_16.concat(config.INTERESTING_32);

var UR = utils.UR;

function choose_block_len(limit) {

  var min_value;
  var max_value;
  var rlim = 3; //MIN(queue_cycle, 3);

  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = config.HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = config.HAVOC_BLK_SMALL;
             max_value = config.HAVOC_BLK_MEDIUM;
             break;

    default: 

             if (UR(10)) {

               min_value = config.HAVOC_BLK_MEDIUM;
               max_value = config.HAVOC_BLK_LARGE;

             } else {

               min_value = config.HAVOC_BLK_LARGE;
               max_value = config.HAVOC_BLK_XL;

             }

  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(Math.min(max_value, limit) - min_value + 1);

}

var mutator_buf = null;
var mutator_size = config.mutator_size;

exports.mutate_radamsa = function (buf) { // ArrayBuffer
  var tmp = new File("/data/local/tmp/jswrite", "wb");
  tmp.write(buf)
  tmp.flush();
  tmp.close();
  if (mutator_buf === null)
  {
    mutator_buf = Memory.alloc(mutator_size);
  }

  var payload_hex = "2f646174612f6c6f63616c2f746d702f726164616d7361202d6e2032202f646174612f6c6f63616c2f746d702f6a73777269746500";
  var readbytes = 0;
  var fp = null;

  while (readbytes == 0)
  {
    fp = utils.popen(payload_hex, '72');
    readbytes = utils.fread(mutator_buf, 1, mutator_size, fp);
    utils.pclose(fp);
  }

  return mutator_buf.readByteArray(readbytes);
}

exports.mutate_radamsa_rpc = function (buf) { // ArrayBuffer
  var bufout = undefined;
  send({
    "event": "mutate",
    "mutate":utils.arrbuf_to_hex(buf)
  });

  var op = recv("input", function (val) {
    if (val.mutate === null) {
      bufout = null;
      return buf;
    }
    bufout = utils.hex_to_arrbuf(val.mutate);
  });

  op.wait();

  return bufout;
}

exports.mutate_havoc = function (buf) { // ArrayBuffer
  //log.consolelog(2, utils.arrbuf_to_hex(buf));
  var out_buf = new DataView(buf);
  var temp_len = out_buf.byteLength;

  var pos = undefined;
  var endian = true;
  var use_stacking = 1 << (1 + UR(exports.HAVOC_STACK_POW2));

  for (var i = 0; i < use_stacking; i++) {

    switch (UR(15 + ((index.dictionary.length > 0) ? 2 : 0))) {

      case 0:

        /* Flip a single bit somewhere. Spooky! */

        pos = UR(temp_len << 3);
        out_buf.setUint8(pos >> 3, out_buf.getUint8(pos >> 3) ^ (128 >> (pos & 7)));

        break;

      case 1: 

        /* Set byte to interesting value. */

        out_buf.setUint8(UR(temp_len), interesting_8[UR(interesting_8.length)]);
        break;

      case 2:

        /* Set word to interesting value, randomly choosing endian. */

        if (temp_len < 2) break;

        out_buf.setUint16(UR(temp_len - 1), interesting_16[UR(interesting_16.length >> 1)], UR(2) == 0);

        break;

      case 3:

        /* Set dword to interesting value, randomly choosing endian. */

        if (temp_len < 4) break;

        out_buf.setUint32(UR(temp_len - 3), interesting_32[UR(interesting_32.length >> 1)], UR(2) == 0);

        break;

      case 4:

        /* Randomly subtract from byte. */

        pos = UR(temp_len);
        out_buf.setUint8(pos, out_buf.getUint8(pos) - 1 - UR(config.ARITH_MAX));

        break;

      case 5:

        /* Randomly add to byte. */

        pos = UR(temp_len);
        out_buf.setUint8(pos, out_buf.getUint8(pos) + 1 + UR(config.ARITH_MAX));
        
        break;

      case 6:

        /* Randomly subtract from word, random endian. */

        if (temp_len < 2) break;

        endian = UR(2) == 0;
        pos = UR(temp_len - 1);

        out_buf.setUint16(pos, out_buf.getUint16(pos, endian) - 1 - UR(config.ARITH_MAX), endian);

        break;

      case 7:

        /* Randomly add to word, random endian. */

        if (temp_len < 2) break;
        
        endian = UR(2) == 0;
        pos = UR(temp_len - 1);

        out_buf.setUint16(pos, out_buf.getUint16(pos, endian) + 1 + UR(config.ARITH_MAX), endian);

        break;

      case 8:

        /* Randomly subtract from dword, random endian. */

        if (temp_len < 4) break;

        endian = UR(2) == 0;
        pos = UR(temp_len - 3);

        out_buf.setUint32(pos, out_buf.getUint32(pos, endian) - 1 - UR(config.ARITH_MAX), endian);

        break;

      case 9:

        /* Randomly add to dword, random endian. */

        if (temp_len < 4) break;
        
        endian = UR(2) == 0;
        pos = UR(temp_len - 3);

        out_buf.setUint32(pos, out_buf.getUint32(pos, endian) + 1 + UR(config.ARITH_MAX), endian);


        break;

      case 10:

        /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */

        pos = UR(temp_len);
        out_buf.setUint8(pos, out_buf.getUint8(pos) ^ (1 + UR(255)));

        break;

      case 11: case 12: {

          /* Delete bytes. We're making this a bit more likely
             than insertion (the next option) in hopes of keeping
             files reasonably small. */

          var del_from;
          var del_len;

          if (temp_len < 2) break;

          /* Don't delete too much. */

          del_len = choose_block_len(temp_len - 1);

          del_from = UR(temp_len - del_len + 1);

          for (var j = del_from; j < (temp_len - del_len); ++j)
            out_buf.setUint8(j, out_buf.getUint8(j + del_len));

          temp_len -= del_len;

          break;

        }

      case 13:

        if (temp_len + config.HAVOC_BLK_XL < config.MAX_FILE) {

          /* Clone bytes (75%) or insert a block of constant bytes (25%). */

          var actually_clone = UR(4);
          var clone_from;
          var clone_len;

          if (actually_clone) {

            clone_len  = choose_block_len(temp_len);
            clone_from = UR(temp_len - clone_len + 1);

          } else {

            clone_len = choose_block_len(config.HAVOC_BLK_XL);
            clone_from = 0;

          }

          var clone_to = UR(temp_len);

          buf = new ArrayBuffer(temp_len + clone_len);
          var new_buf = new DataView(buf);

          /* Head */

          for (var j = 0; j < clone_to; ++j)
            new_buf.setUint8(j, out_buf.getUint8(j));

          /* Inserted part */

          if (actually_clone)
            for (var j = 0; j < clone_len; ++j)
              new_buf.setUint8(clone_to + j, out_buf.getUint8(clone_from + j));
          else
            for (var j = 0; j < clone_len; ++j)
              new_buf.setUint8(clone_to + j, UR(2) ? UR(256) : out_buf.getUint8(UR(temp_len)));

          /* Tail */
          for (var j = clone_to; j < temp_len; ++j)
            new_buf.setUint8(j + clone_len, out_buf.getUint8(j));

          out_buf = new_buf;
          temp_len += clone_len;

        }

        break;

      case 14: {

          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          var copy_from;
          var copy_to;
          var copy_len;

          if (temp_len < 2) break;

          copy_len  = choose_block_len(temp_len - 1);

          copy_from = UR(temp_len - copy_len + 1);
          copy_to   = UR(temp_len - copy_len + 1);

          if (UR(4)) {

            if (copy_from != copy_to) {
            
              var sl = new Uint8Array(buf.slice(copy_from, copy_from + copy_len));
              for (var j = 0; j < copy_len; ++j)
                out_buf.setUint8(copy_to + j, sl[j]);
                
            }
              

          } else {
          
            var b = UR(2) ? UR(256) : out_buf.getUint8(UR(temp_len));
            for (var j = 0; j < copy_len; ++j)
              out_buf.setUint8(copy_to + j, b);

          }

          break;

        }

      /* Values 15 and 16 can be selected only if there are any extras
         present in the dictionaries. */

      case 15: {

          /* Overwrite bytes with an extra. */

          var use_extra = UR(index.dictionary.length);
          var extra_len = index.dictionary[use_extra].byteLength;

          if (extra_len > temp_len) break;

          var insert_at = UR(temp_len - extra_len + 1);
          for (var j = 0; j < extra_len; ++j)
            out_buf.setUint8(insert_at + j, index.dictionary[use_extra][j]);

          break;

        }

      case 16: {

          var insert_at = UR(temp_len + 1);

          /* Insert an extra. */

          var use_extra = UR(index.dictionary.length);
          var extra_len = index.dictionary[use_extra].byteLength;

          if (temp_len + extra_len >= config.MAX_FILE) break;

          buf = new ArrayBuffer(temp_len + extra_len);
          var new_buf = new DataView(buf);

          /* Head */
          for (var j = 0; j < insert_at; ++j)
            new_buf.setUint8(j, out_buf.getUint8(j));

          /* Inserted part */
          for (var j = 0; j < extra_len; ++j)
            new_buf.setUint8(insert_at + j, index.dictionary[use_extra][j]);

          /* Tail */
          for (var j = insert_at; j < temp_len; ++j)
            new_buf.setUint8(extra_len + j, out_buf.getUint8(j));

          out_buf   = new_buf;
          temp_len += extra_len;

          break;

        }

        default: throw "ERROR: havoc switch oob, something is really wrong here!";

    }

  }
  
  //log.consolelog(3, utils.arrbuf_to_hex(buf));
  if (temp_len != buf.byteLength)
    return buf.slice(0, temp_len);
  return buf;

}


},{"./config.js":2,"./index.js":3,"./log.js":5,"./utils.js":9}],7:[function(require,module,exports){
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

var config  = require("./config.js");
var bitmap = require("./bitmap.js");
var utils  = require("./utils.js");
var stages = require("./stages.js");

/* struct QEntry {
  u8* buf;
  u8* trace_mini;
  u32 size;
  u32 exec_ms;
  u32 tc_ref;
  u8 favored;
  u8 was_fuzzed;
}; */
var QENTRY_FIELD_BUF = 0;
var QENTRY_FIELD_TRACE_MINI = QENTRY_FIELD_BUF + Process.pointerSize;
var QENTRY_FIELD_SIZE = QENTRY_FIELD_TRACE_MINI + Process.pointerSize;
var QENTRY_FIELD_EXEC_MS = QENTRY_FIELD_SIZE + 4;
var QENTRY_FIELD_TC_REF = QENTRY_FIELD_EXEC_MS + 4;
var QENTRY_FIELD_FAVORED = QENTRY_FIELD_TC_REF + 4;
var QENTRY_FIELD_WAS_FUZZED = QENTRY_FIELD_FAVORED + 1;
var QENTRY_BYTES = ((QENTRY_FIELD_WAS_FUZZED + 1) + 7) & (-8);

function QEntry(buf, size, exec_ms) {

  var _ptr = Memory.alloc(QENTRY_BYTES);
  this.ptr = _ptr;

  // Beware! Assigning buf does not maintaint the reference, the caller must hold it
  var props = {

    get buf() { 
      return _ptr.readPointer();
    },
    set buf(val) {
      _ptr.writePointer(val);
    },
    get trace_mini() {
      return _ptr.add(QENTRY_FIELD_TRACE_MINI).readPointer();
    },
    set trace_mini(val) {
      _ptr.add(QENTRY_FIELD_TRACE_MINI).writePointer(val);
    },
    get size() {
      return _ptr.add(QENTRY_FIELD_SIZE).readU32();
    },
    set size(val) {
      _ptr.add(QENTRY_FIELD_SIZE).writeU32(val);
    },
    get exec_ms() {
      return _ptr.add(QENTRY_FIELD_EXEC_MS).readU32();
    },
    set exec_ms(val) {
      _ptr.add(QENTRY_FIELD_EXEC_MS).writeU32(val);
    },
    get tc_ref() {
      return _ptr.add(QENTRY_FIELD_TC_REF).readU32();
    },
    set tc_ref(val) {
      _ptr.add(QENTRY_FIELD_TC_REF).writeU32(val);
    },
    get favored() {
      return _ptr.add(QENTRY_FIELD_FAVORED).readU32();
    },
    set favored(val) {
      val = +val; // to int
      _ptr.add(QENTRY_FIELD_FAVORED).writeU32(val);
    },
    get was_fuzzed() {
      return _ptr.add(QENTRY_FIELD_WAS_FUZZED).readU32();
    },
    set was_fuzzed(val) {
      val = +val; // to int
      _ptr.add(QENTRY_FIELD_WAS_FUZZED).writeU32(val);
    },

  };

  if (buf instanceof Uint8Array)
    buf = buf.buffer;
  if (buf instanceof ArrayBuffer) {
    this._bufref = buf; // maintain a reference while using the backing ptr
    buf = buf.unwrap();
  } else if (buf instanceof NativePointer) {
    this._bufref = buf; // maintain a reference to avoid gc
  } else {
    throw "Invalid type for buf";
  }

  props.buf = buf;
  props.size = size;
  props.exec_ms = exec_ms;
  props.favored = false;
  props.was_fuzzed = false;
  // You should never touch trace_mini, see update_bitmap_score_body
  props.trace_mini = ptr(0);
  props.tc_ref = 0;

  Object.assign(this, props);

}

var temp_v_size = config.MAP_SIZE >> 3;
var temp_v = Memory.alloc(temp_v_size);

var queue = [];

var bytes_size = 0;

/* cur.buf is not guaranteed to be !== null, use always the buf provided as
   argument to functions */
exports.cur = null;
exports.cur_idx = -1;

exports.pending_favored = 0;
exports.favoreds = 0;

exports.size = function () {

  return queue.length;

};

exports.last = function () {

  return queue[queue.length -1];

};

exports.next = function () {

  if (exports.cur_idx === queue.length -1)
    exports.cur_idx = 0;
  else
    exports.cur_idx++;
  
  var q = queue[exports.cur_idx];
  var buf = undefined;
  
  if (q.buf.isNull()) {

    send({
      "event": "get",
      "num": exports.cur_idx,
      "stage": stages.stage_name,
      "cur": exports.cur_idx,
      "total_execs": stages.total_execs,
      "pending_fav": exports.pending_favored,
      "favs": exports.favoreds,
      "map_rate": bitmap.map_rate,
    });
    
    var op = recv("input", function (val) {
      buf = utils.hex_to_arrbuf(val.buf);
    });

    op.wait();
    
    if (bytes_size + buf.byteLength < config.QUEUE_CACHE_MAX_SIZE) {

      // cache it if it fills in cache
      bytes_size += buf.byteLength;
      q.buf = buf;

    }
    
  } else {

    buf = ArrayBuffer.wrap(q.buf, q.size);
  
  }

  exports.cur = q;
  // note that prune_memory does not delete cur.buf so this operation is safe
  // for any other stuffs, buf must be copied
  return buf;

}

exports.get = function (idx) {

  return queue[idx];

}

/*
exports.download = function (idx) {

  var q = queue[idx];
  if (q.buf.isNull()) {

    send({
      "event": "get",
      "num": idx,
      "stage": stages.stage_name,
      "cur": exports.cur_idx,
      "total_execs": stages.total_execs,
    });
    
    var buf = undefined;
    var op = recv("input", function (val) {
      q.buf = utils.hex_to_arrbuf(val.buf);
    });

    op.wait();
    
  }
  
  return q;

}
*/

// Delete half of the occupied memory
function prune_memory() {

  var c = 0;
  for (; c < queue.length && bytes_size >= (config.QUEUE_CACHE_MAX_SIZE / 2); ++c) {
  
    var r = UR(queue.length);
    var not_del = true;

    for(var i = r; not_del && i < queue.length; ++i) {
      if (i == exports.cur_idx || queue[i].buf.isNull())
        continue;
      queue[i].buf = ptr(0);
      queue[i]._bufref = undefined;
      not_del = false;
    }
    
    for(var i = 0; not_del && i < r; ++i) {
      if (i == exports.cur_idx || queue[i].buf.isNull())
        continue;
      queue[i].buf = ptr(0);
      queue[i]._bufref = undefined;
      not_del = false;
    }
  
  }

}

exports.add = function (/* ArrayBuffer */ buf, exec_ms, has_new_cov) {

  if (buf.byteLength >= config.QUEUE_CACHE_MAX_SIZE) {
    
    queue.push(new QEntry(ptr(0), buf.byteLength, exec_ms));
    
  } else {

    bytes_size += buf.byteLength;
    
    if (bytes_size >= config.QUEUE_CACHE_MAX_SIZE)
      prune_memory();
    
    if (bytes_size >= config.QUEUE_CACHE_MAX_SIZE) {
      // prune_memory was ineffective
      bytes_size -= buf.byteLength;
      queue.push(new QEntry(ptr(0), buf.byteLength, exec_ms));
    } else {
      queue.push(new QEntry(buf.slice(0), buf.byteLength, exec_ms));
    }

  }

  send({
    "event": "interesting",
    "num": (queue.length -1),
    "exec_ms": exec_ms,
    "new_cov": has_new_cov,
    "stage": stages.stage_name,
    "cur": exports.cur_idx,
    "total_execs": stages.total_execs,
    "pending_fav": exports.pending_favored,
    "favs": queue.favoreds,
    "map_rate": bitmap.map_rate,
  }, buf);

}

/* As always, cur.buf is not guaranteed to be !== null */
exports.splice_target = function (buf) {

  var tid = utils.UR(queue.length);
  var t = queue[tid];
  
  while (tid < queue.length && (queue[tid].size < 2 || tid === exports.cur_idx))
    ++tid;
  
  if (tid === queue.length)
    return null;
  
  t = queue[tid];
  var new_buf = null;

  if (t.buf.isNull()) { // fallback to the python fuzz driver 
  
    send({
      "event": "splice",
      "num": exports.cur_idx,
      "cycle": stages.splice_cycle,
      "stage": stages.stage_name,
      "cur": exports.cur_idx,
      "total_execs": stages.total_execs,
      "pending_fav": exports.pending_favored,
      "favs": queue.favoreds,
      "map_rate": bitmap.map_rate,
    });
    
    var op = recv("splice", function (val) {
      if (val.buf !== null && val.buf !== undefined)
        new_buf = utils.hex_to_arrbuf(val.buf);
      stages.splice_cycle = val.cycle; // important to keep
    });

    op.wait();
    
    return new_buf;
  
  } else {
  
    new_buf = ArrayBuffer.wrap(t.buf, t.size).slice(0);
    stages.splice_cycle++;
    
  }
  
  /*send({
    "event": "status",
    "stage": stages.stage_name,
    "cur": exports.cur_idx,
    "total_execs": stages.total_execs,
  });*/
  
  var diff = utils.locate_diffs(buf, new_buf);
  if (diff[0] === null || diff[1] < 2 || diff[0] === diff[1])
      return null;

  var split_at = diff[0] + utils.UR(diff[1] - diff[0]);
  new Uint8Array(new_buf).set(new Uint8Array(buf.slice(0, split_at)), 0);
  return new_buf;

}

exports.__cm = new CModule(`

#include <stdint.h>
#include <stdio.h>

#define MAP_SIZE __MAP_SIZE__

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct __attribute__((packed)) QEntry {

  u8* buf;
  u8* trace_mini;
  u32 size;
  u32 exec_ms;
  u32 tc_ref;
  u8 favored;
  u8 was_fuzzed;

};

u64 cull_body(struct QEntry** top_rated, u8* temp_v) {

  u32 pending_favored = 0;
  u32 favoreds = 0;
  
  u32 i;
  for (i = 0; i < (MAP_SIZE >> 3); ++i) {
    temp_v[i] = 0xff;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */
  
  for (i = 0; i < MAP_SIZE; ++i) {
    
    if (top_rated[i] != NULL && (temp_v[i >> 3] & (1 << (i & 7))) != 0) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) {
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];
      }

      if (!top_rated[i]->was_fuzzed)
        pending_favored++;

      top_rated[i]->favored = 1;
      favoreds++;

    }

  }

  return (pending_favored << 32) | favoreds;

}

`.replace("__MAP_SIZE__", ""+config.MAP_SIZE)
);

var cull_body = new NativeFunction(
  exports.__cm.cull_body,
  "uint",
  ["pointer", "pointer"]
);

exports.cull = function () {

  if (!bitmap.score_changed) return;
  bitmap.score_changed = false;

  for (var i = 0; i < queue.length; ++i)
    queue[i].favored = 0;

  var r = cull_body(bitmap.top_rated, temp_v);
  exports.favoreds = r & 0xffffffff;
  exports.pending_favored = (r >> 32) & 0xffffffff;

}


},{"./bitmap.js":1,"./config.js":2,"./stages.js":8,"./utils.js":9}],8:[function(require,module,exports){
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

var config  = require("./config.js");
var mutator = require("./mutator.js");
var utils = require("./utils.js");
var bitmap = require("./bitmap.js");
var queue = require("./queue.js");

exports.stage_name = "init";
exports.stage_cur  = 0;
exports.stage_max  = 0;

exports.total_execs = 0;
exports.exec_speed = 0;

exports.splice_cycle = 0;

var zeroed_bits = new Uint8Array(config.MAP_SIZE); // TODO memset(..., 0, ...)
var last_status_ts = 0;

function common_fuzz_stuff(/* ArrayBuffer */ buf, callback) {

  Memory.writeByteArray(bitmap.trace_bits, zeroed_bits);

  var ts_0 = (new Date()).getTime();

  try {
    callback(buf);
  } catch (err) {
    
    if (err.type !== undefined) {
      send({
        "event": "crash",
        "err": err,
        "stage": exports.stage_name,
        "cur": queue.cur_idx,
        "total_execs": exports.total_execs,
        "pending_fav": queue.pending_favored,
        "favs": queue.favoreds,
        "map_rate": bitmap.map_rate,
      }, buf);
    } else if (err.$handle != undefined) {
      send({
        "event": "exception",
        "err": err.message,
        "stage": exports.stage_name,
        "cur": queue.cur_idx,
        "total_execs": exports.total_execs,
        "pending_fav": queue.pending_favored,
        "favs": queue.favoreds,
        "map_rate": bitmap.map_rate,
      }, buf);
    }
    throw err;
  }

  var ts_1 = (new Date()).getTime();

  var exec_ms = ts_1 - ts_0;
  if (exec_ms > config.TIMEOUT) {
    send({
      "event": "crash",
      "err": {"type": "timeout"},
      "stage": exports.stage_name,
      "cur": queue.cur_idx,
      "total_execs": exports.total_execs,
      "pending_fav": queue.pending_favored,
      "favs": queue.favoreds,
      "map_rate": bitmap.map_rate,
    }, buf);
    throw "timeout";
  }
  
  bitmap.classify_counts(bitmap.trace_bits, bitmap.count_class_lookup16);
  
  exports.exec_speed = exec_ms;
  ++exports.total_execs;
  
  if (bitmap.save_if_interesting(buf, exec_ms)) {
  
    if ((ts_1 - last_status_ts) > config.UPDATE_TIME) {
      last_status_ts = ts_1;
      send({
        "event": "status",
        "stage": exports.stage_name,
        "cur": queue.cur_idx,
        "total_execs": exports.total_execs,
        "pending_fav": queue.pending_favored,
        "favs": queue.favoreds,
        "map_rate": bitmap.map_rate,
      });
    }
    
    return exec_ms; // return exec_ms when not saved
      
  }
  
  return null;
  
}


exports.dry_run = function (callback) {

  var buf = undefined;
  
  while (true) {

    send({
      "event": "dry",
      "stage": exports.stage_name,
      "cur": queue.cur_idx,
      "total_execs": exports.total_execs,
      "pending_fav": queue.pending_favored,
      "favs": queue.favoreds,
      "map_rate": bitmap.map_rate,
    });

    var op = recv("input", function (val) {
      if (val.buf === null) {
        buf = null;
        return;
      }
      buf = utils.hex_to_arrbuf(val.buf);
      exports.queue_cur = val.num;
    });

    op.wait();
    if (buf === null) break;
    
    var exec_ms = common_fuzz_stuff(buf, callback);
    if (exec_ms !== null) { // always save initial seeds
    
      queue.add(buf, exec_ms, false);
      bitmap.update_bitmap_score(queue.last());

    }

  }

  send({
    "event": "status",
    "stage": exports.stage_name,
    "cur": queue.cur_idx,
    "total_execs": exports.total_execs,
    "pending_fav": queue.pending_favored,
    "favs": queue.favoreds,
    "map_rate": bitmap.map_rate,
  });

}


function fuzz_havoc(/* ArrayBuffer */ buf, callback, is_splice) {

  if (!is_splice)  {
    exports.stage_name = "havoc";
    exports.stage_max = config.HAVOC_CYCLES * 40; // TODO perf_score & co
  } else {
    exports.stage_name = "splice-" + exports.splice_cycle;
    exports.stage_max = config.SPLICE_HAVOC * 40; // TODO perf_score & co
  }

  for (exports.stage_cur = 0; exports.stage_cur < exports.stage_max;
       exports.stage_cur++) {

    var muted = buf.slice(0);
    //muted = mutator.mutate_havoc(muted);
    muted = mutator.mutate_radamsa(muted);
    //muted = mutator.mutate_radamsa_rpc(muted);
    common_fuzz_stuff(muted, callback);
 
  }

}

exports.havoc_stage = function (/* ArrayBuffer */ buf, callback) {

  fuzz_havoc(buf, callback, false);

}

exports.splice_stage = function (/* ArrayBuffer */ buf, callback) {

  exports.splice_cycle = 0;

  if (buf.byteLength <= 1 || queue.size() <= 1) return;

  while (exports.splice_cycle < config.SPLICE_CYCLES) {

    var new_buf = queue.splice_target(buf);

    if (new_buf !== null)
      fuzz_havoc(new_buf, callback, true);

  }

}


},{"./bitmap.js":1,"./config.js":2,"./mutator.js":6,"./queue.js":7,"./utils.js":9}],9:[function(require,module,exports){
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



exports.UR = function(n) {

  return Math.floor(Math.random() * n);

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

},{}],10:[function(require,module,exports){
var config = require("../../frida-js/config.js");

// if you want to modify config vars you need to do it before including the fuzz module
config.MAP_SIZE = 128;

var fuzz = require("../../frida-js");

var TARGET_MODULE = "fridafuzzer_test";
var TARGET_FUNCTION = DebugSymbol.fromName("handleClient").address;;
var RET_TYPE = "void";
var ARGS_TYPES = ['pointer'];

// { traps: 'all' } is needed for stalking
var func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES, { traps: 'all' });

fuzz.target_module = TARGET_MODULE;

fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload) {

  var payload_mem = payload.buffer.unwrap();
  var p = new NativePointer(payload_mem);
  //console.log (p.readByteArray(payload.length+4));
  func_handle(payload_mem);

}

console.log (" >> Agent loaded!");

},{"../../frida-js":3,"../../frida-js/config.js":2}]},{},[10])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NvdXJjZXMvbm9kZS12MTMuMTMuMC1saW51eC14NjQvbGliL25vZGVfbW9kdWxlcy9mcmlkYS1jb21waWxlL25vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCIuLi8uLi9mcmlkYS1qcy9iaXRtYXAuanMiLCIuLi8uLi9mcmlkYS1qcy9jb25maWcuanMiLCIuLi8uLi9mcmlkYS1qcy9pbmRleC5qcyIsIi4uLy4uL2ZyaWRhLWpzL2luc3RydW1lbnRvci5qcyIsIi4uLy4uL2ZyaWRhLWpzL2xvZy5qcyIsIi4uLy4uL2ZyaWRhLWpzL211dGF0b3IuanMiLCIuLi8uLi9mcmlkYS1qcy9xdWV1ZS5qcyIsIi4uLy4uL2ZyaWRhLWpzL3N0YWdlcy5qcyIsIi4uLy4uL2ZyaWRhLWpzL3V0aWxzLmpzIiwidGVzdF9uZGtfYWFyY2guanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7QUNBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdlFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN4REE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDcExBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdlBBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDekJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM1YUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoY0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3ZOQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNyS0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
