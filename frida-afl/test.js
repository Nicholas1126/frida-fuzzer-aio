var log = require("./log.js");
var utils = require("./utils.js");
var typedef = require("./typedef.js");

function entrypoint() {

  var rb = BigInt(18446744073709551615);
  var myNumber = Number(rb);
  
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