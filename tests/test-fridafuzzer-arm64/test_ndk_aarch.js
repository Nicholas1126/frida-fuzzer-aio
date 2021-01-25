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
