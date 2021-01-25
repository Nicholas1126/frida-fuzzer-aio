
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