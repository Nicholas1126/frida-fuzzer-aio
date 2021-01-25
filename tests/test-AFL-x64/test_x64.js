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
