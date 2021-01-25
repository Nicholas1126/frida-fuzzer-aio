var fuzz = require("../../frida-js/afl.js");


var TARGET_MODULE = "afl_test";
var TARGET_OFFSET = 0x820;
var func_handle = null; 

fuzz.target_module = TARGET_MODULE;
fuzz.target_rettype = "void";
fuzz.target_argstype = ['pointer'];
fuzz.init_callback = function () {
  
  var maps = fuzz.vmmaps;
  var func = ptr(0);
  maps.forEach(function(m) {
    if (m.name == TARGET_MODULE) {
      func = m.base.add(TARGET_OFFSET);
    }
  });

  fuzz.target_function = func;
  //fuzz.target_function = DebugSymbol.fromName("handleClient").address;
  func_handle = new NativeFunction(fuzz.target_function, fuzz.target_rettype, fuzz.target_argstype, { traps: 'all' });
}

fuzz.inflowfuzz = false;

fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload /*,args if inflowfuzz is true */) {
  var payload_memory = payload.buffer.unwrap();
  
  func_handle(payload_memory);
}
