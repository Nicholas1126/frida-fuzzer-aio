var aflinstr = require("./aflinstrumentor.js");

exports.init_callback = null;
exports.fuzzer_test_one_input = null;
exports.target_module = null;
exports.target_function = ptr(0);
exports.target_args = [];
exports.target_argstype = null;
exports.target_rettype = null;
exports.inflowfuzz = false;
exports.vmmaps = aflinstr.vmmap();
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
        return aflinstr.afl_area_ptr;
    },


    setupshmlocal: function (shm_id) {
        aflinstr.afl_area_ptr = shmat(shm_id, ptr(0), 0);
        return aflinstr.afl_area_ptr;
    },

    settargetremote: function () {
        // trace whole target_module
        //aflinstr.start_tracing_remote(Process.getCurrentThreadId(), exports.target_module);
        exports.init_callback();
        exports.target_args.length = exports.target_argstype.length;
        aflinstr.start_tracing_remote(exports.target_module, exports.target_function, exports.target_args);
    },

    settargetlocal: function () {
        // trace whole target_module
        //aflinstr.start_tracing_local(Process.getCurrentThreadId(), exports.target_module);
        exports.init_callback();
        exports.target_args.length = exports.target_argstype.length;
        aflinstr.start_tracing_local(exports.target_module, exports.target_function, exports.target_args);
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

        if (exports.inflowfuzz)
        {
            if (aflinstr.target_been_trigger)
            {
                exports.fuzzer_test_one_input(payload, exports.target_args);    
            }
            else
            {
                return true;
            }
        }
        else
        {
            exports.fuzzer_test_one_input(payload);
        }
        
        return false;
    },

};

