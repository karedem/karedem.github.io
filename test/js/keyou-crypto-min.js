
;(function (root, factory) {
    if (typeof exports === "object") {
        // CommonJS
        module.exports = exports = factory();
    }
    else if (typeof define === "function" && define.amd) {
        // AMD
        define([], factory);
    }
    else {
        // Global (browser)
        root.KeyouCryptography = factory();
    }
}(this, function () {
    
    var KeyouCryptography = KeyouCryptography || (function (undefined) {
        var K = {};
        K.util = {};
        K.algorithm = {};

        K.AsymmetricAlg = {
            RSA: {name: "RSA"},
            SM2: {name: "SM2"}
        };

        K.SymmetricAlg = {
               SM4: {name: "SM4", size: 16},
             DES64: {name: "DES", size:  8},
            DES128: {name: "DES", size: 16},
            DES192: {name: "DES", size: 24},
            AES128: {name: "AES", size: 16},
            AES192: {name: "AES", size: 24},
            AES256: {name: "AES", size: 32}
        };

        K.Pad = {
            padPKCS5: "PKCS5",
              padLV0: "LV0",
             pad0x00: "0x00",
             pad0x80: "0x80"
        };

        K.Hasher = {
              NONE: {name: 'NONE',   DER_OID: ''},
              SHA1: {name: 'SHA1',   DER_OID: '3021300906052b0E03021A05000414'},
            SHA224: {name: 'SHA224', DER_OID: '302D300D06096086480165030402040500041C'},
            SHA256: {name: 'SHA256', DER_OID: '3031300D060960864801650304020105000420'},
            SHA384: {name: 'SHA384', DER_OID: '3041300D060960864801650304020205000430'},
            SHA512: {name: 'SHA512', DER_OID: '3051300D060960864801650304020305000440'},
               MD5: {name: 'MD5',    DER_OID: '3020300C06082A864886F70d020505000410'}               
        };

        // K.digest = {
        //     SM3: {"oid": ""},
        //     MD2,
        //     MD4,
        //     MD5,
        //     SHA,
        //     SHA1,
        //     SHA224,
        //     SHA256,
        //     SHA384,
        //     SHA512
        // };


        return K;
    }());
    // 公共模块
    
/**
 * @required core.js
 */
(function () {
    var KU = KeyouCryptography.util;

    /**
     * 异常状态和异常参数校验接口
     */
    var Checker = KU.Checker = {

        name: "Checker",

        /**
         * 检查字符串是否仅为可打印字符
         * @param  {String} str 待校验的字符串
         * @return {Boolean}     true 字符串内容仅包含可打印字符
         */
        checkOnlyPrintChar: function (str) {
            return  /^[\u0020-\u007E]+$/.test(str);
        },

        /**
         * 检查字符串是否包含中文字符
         * @param  {String} str 待校验的字符串
         * @return {Boolean}     true 字符串包含中文字符
         */
        checkHasChinese: function (str) {
            return /.*[\u2E80-\u9FFF]+.*$/.test(str);
        },
        
        /**
         * 参数校验接口
         * 
         * @param  {Boolean} expression 布尔表达式
         * @param  {String} message    错误信息
         * 
         * @throws {TypeError} 表达式为 false
         *
         * @static
         * 
         * @example
         *     
         *     KeyouCryptography.util.Checker.checkArgument(argument != undefined, "argument must not be undefined.");
         */
        checkArgument: function (expression, message) {
            if (!expression) {
                throw new TypeError("Illegal Argument:" + message);
            }
            return;
        },

        /**
         * 检查对象是否存在
         * 
         * @param  {Object} object  待检查的对象  
         * @param  {String} message 错误信息
         * 
         * @return {Object}         待检查的对象
         *
         * @throws {TypeError} 对象为空或对象不存在
         *
         * @static
         */
        checkExist: function (object, message) {
            if (typeof object === undefined || object === null) {
                throw new TypeError("object is undefined or object is null. " + message);
            }
            return object;
        },

        /**
         * 检查对象是否为空
         * 
         * @param  {Object} object  待检查的对象
         * @param  {String} message 错误信息
         * 
         * @return {Object}         待检查的对象
         *
         * @static
         * 
         */
        checkNotEmpty: function (object, message) {
            if (typeof object === undefined || object === null) {
                throw new TypeError("object is empty." + message);
            }
            if (typeof object.length !== undefined && object.length === 0) {
                throw new TypeError("object is empty." + message);
            }
            return object;
        },

        /**
         * 状态校验接口
         * 
         * @param  {Boolean} expression 布尔表达式
         * @param  {String} message    错误信息
         *
         * @throws {Exception} 表达式为 false
         *
         * @static
         * 
         * @example
         *
         *      KeyouCryptography.util.Checker.checkState(argument != undefined, "argument must not be undefined.");
         */
        checkState: function (expression, message) {
            if (!expression) {
                throw new Error("Illegal State:" + message);
            }
            return;
        }
    };
}());

;
    /**
 * @required core.js
 * @required checker.js
 */
(function () {
    var KU = KeyouCryptography.util;
    var Checker = KU.Checker;

    /**
     * Hex 16 进制转换
     */
    var Hex = KU.Hex = {
        name: "Hex",

        /**
         * 将字节数组转换为 16 进制字符串
         * 
         * @param  {Uint8Array} bytes 8bits 大小的字节数组
         * 
         * @return {String}       16 进制的字符串
         *
         * @static
         *
         * @example
         *
         *      var bytes = [1, 2, 3, 4, 5, 6];
         *      var hexstr = KeyouCryptography.util.Hex.stringify(bytes);
         *      assert(hexstr === "010203040506");
         */
        stringify: function (bytes) {
            var hexstr = [];
            var length = bytes.length;
            for (var i = 0; i < length; i++) {
                var byte = bytes[i];
                hexstr.push((byte >>> 4).toString(16));
                hexstr.push((byte & 0x0F).toString(16));
            }
            return hexstr.join('').toUpperCase();
        },

        encode: function (bytes) {
            return this.stringify(bytes);
        },

        /**
         * 将 16 进制的字符串转换为字节数组
         * 
         * @param  {String} hexstr 16 进制的字符串
         * 
         * @return {Uint8Array}        字节数组
         *
         * @static
         *
         * @example
         * 
         *     var hexstr = "313233343536";
         *     var bytes = KeyouCryptography.util.Hex.parse(hexstr);
         *     assert(bytes === ['1', '2', '3', '4', '5', '6']);
         */
        parse: function (hexstr) {
            var bytes = [];
            
            Checker.checkArgument(hexstr != undefined && hexstr.length % 2 == 0,
                "illegal Hex string:" + hexstr);
            var regExp = new RegExp("[A-Fa-f0-9]+$", "g");
            Checker.checkArgument(hexstr.match(regExp), "illegal Hex string:" + hexstr);

            var length = hexstr.length / 2;
            for (var i = 0; i < length; i++) {
                bytes[i] = parseInt(hexstr.substring(i * 2, i * 2 + 2), 16);
            }
            
            return bytes;
        },

        decode: function (hexstr) {
            return this.parse(hexstr);
        },

        /*
         * 负数的bytes转为正数
         */
        toUnsignBytes: function (bytes) {
            var bs = [];
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i];
                if(b < 0){
                    b += 256
                }
                bs[i] = b;
            }
            return bs;
        }
    };

}());
;
    (function () {
   var KU = KeyouCryptography.util;

   /**
    * UTF-8 编解码接口
    */
   var UTF8 = KU.UTF8 = {

        /**
         * 将字节数组编码为 UTF-8 字符串
         * 
         * @param  {Uint8Array} bytes 字节数组
         * 
         * @return {String}       UTF-8 编码的字符串
         * 
         * @static
         * 
         * @example
         * 
         */
        stringify: function (bytes) {
            var byteArray = bytes;
            var str = "";
            var offset = 0;
            var unicodeValue;
            while (offset < byteArray.length) {
                unicodeValue = byteArray[offset];
                if (unicodeValue < 0xc0) {
                    offset += 1;
                } else if (unicodeValue < 0xe0) {
                    unicodeValue = ((byteArray[offset] & 0x001f) << 6)
                            | (byteArray[offset + 1] & 0x3f);
                    offset += 2;
                } else if (unicodeValue < 0xf0) {
                    unicodeValue = ((byteArray[offset] & 0x000f) << 12)
                            | ((byteArray[offset + 1] & 0x003f) << 6)
                            | (byteArray[offset + 2] & 0x3f);
                    offset += 3;
                } else if (unicodeValue < 0xf8) {
                    unicodeValue = ((byteArray[offset] & 0x000007) << 18)
                            | ((byteArray[offset + 1] & 0x003f) << 12)
                            | ((byteArray[offset + 2] & 0x003f) << 6)
                            | (byteArray[offset + 3] & 0x3f);
                    offset += 4;
                }
                str += String.fromCharCode(unicodeValue);
            }
            return str;
        },

        /**
         * 将字符串以 UTF-8 的格式解码为字节数组
         * 
         * @param  {String} str 字符串
         * 
         * @return {Uint8Array}     UTF-8 解码后的字符串
         * 
         * @static
         *
         * @example
         * 
         */
        parse: function (str) {
            var byteArray = new Array();
            var unicodeValue;
            for (var i = 0; i < str.length; i++) {
                unicodeValue = str.charCodeAt(i);
                if (unicodeValue < 0x80) {
                    byteArray.push(unicodeValue);
                } else if (unicodeValue < 0x0800) {
                    byteArray.push((unicodeValue >>> 6) & 0x1f | 0xc0);
                    byteArray.push(unicodeValue & 0x3f | 0x80);
                } else if (unicodeValue < 0x010000) {
                    byteArray.push((unicodeValue >>> 12) & 0x0f | 0xe0);
                    byteArray.push((unicodeValue >>> 6) & 0x3f | 0x80);
                    byteArray.push(unicodeValue & 0x3f | 0x80);
                } else if (unicodeValue < 0x200000) {
                    byteArray.push((unicodeValue >>> 18) & 0x07 | 0xf0);
                    byteArray.push((unicodeValue >>> 12) & 0x3f | 0x80);
                    byteArray.push((unicodeValue >>> 6) & 0x3f | 0x80);
                    byteArray.push(unicodeValue & 0x3f | 0x80);
                }
            }
            return byteArray;
        }
   }


}());
    (function () {
	var KU = KeyouCryptography.util;

    var Long = KU.Long = function (high, low) {
        this.high = high;
        this.low = low;
    }

    var fixlow = function(a){
        while (a < 0){
            a += 0x100000000;
        }
        return a;
    }

    /**
     * @param {[type]}
     * @return {[Long]}
     */
    Long.prototype.AND = function() {
        var result = new Long(this.high, this.low);
        for(var i = 0; i < arguments.length; i++){
            result.high = arguments[i].high & result.high;
            result.low = arguments[i].low & result.low;
        }
        result.low = fixlow(result.low);
        return result;
    };  

    /**
     * @param {[Long]}
     * @return {[Long]}
     */
    Long.prototype.OR = function() {
        var result = new Long(this.high, this.low);
        for(var i = 0; i < arguments.length; i++){
            result.high = arguments[i].high | result.high;
            result.low = arguments[i].low | result.low;
        }
        result.low = fixlow(result.low);
        return result;
    };

        /**
         * @param {[Long]}
         * @return {[Long]}
         */
    Long.prototype.XOR = function() {
        var result = new Long(this.high, this.low);
        for(var i = 0; i < arguments.length; i++){
            result.high = arguments[i].high ^ result.high;
            result.low = arguments[i].low ^ result.low;
        }
        result.low = fixlow(result.low);
        return result;
    };

    /**
     * @param {[int]}
     * @return {[Long]}
     */
    Long.prototype.leftShift = function(n) {
        var result = new Long(this.high, this.low);
        var high1 = (result.high << n) & 0x0ffffffff;
        if(n >= 32)
        {
            result.high = result.low << (n- 32);
            result.low =  0x00000000;
            return result;
        }
        result.high = high1 | (result.low >>> (32 - n));
        result.low = (result.low << n) & 0x0ffffffff;
        return result;
    };

    /**
     * @param {[int]}
     * @return {[Long]}
     */
    Long.prototype.rightShift = function(n) {   
        var result = new Long(this.high, this.low);
        var low1 = result.low >>> n;
        if(n >= 32){
            result.low = result.high >>> (n - 32);
            result.high =  0x00000000;
            return result;
        }
        result.low = low1 | ((result.high<<(32 -n) ) & 0x0ffffffff); 
        result.high = result.high >>> n;
        return result;    
    };

    /**
     * @return {[Long]}
     */
    Long.prototype.Negate = function() {
        var result = new Long(this.high, this.low);
        result.high = (~result.high) & 0x0ffffffff;
        result.low = (~result.low) & 0x0ffffffff;
        return result;   
    };

    Long.prototype.add = function() {
        var result = new Long(this.high, this.low);
        for(var i = 0; i < arguments.length; i++){
            result.low += arguments[i].low;
            var plus = 0;
            if(result.low > 0x0ffffffff){
                //plus = result.low >>> 32;
                plus = 1;
                result.low = result.low - 0x100000000;
            }
            result.high += arguments[i].high + plus;
            result.high = result.high & 0x0ffffffff;
        }
        return result;
    }
    
    /**
     * 对数字mod求余  不支持传入long型 （未测 慎用）
     * @param    {[type]}                 mod [description]
     * @return   {[type]}                     [description]
     */
    Long.prototype.mod = function(mod){
        var result = 0;
        var highMod = this.high % mod;
        var tempMod = highMod << 32 + this.low;
        result = tempMod % mod;
        return result;
    }

    Long.prototype.bigger = function(l){
        if (this.high > l.high ) {
            return 1;
        }else if(this.high == l.high && this.low > l.low){
            return 1;
        }
        return 0;
    }

    Long.OR = function (o1, o2) {
        return o1.OR(o2);
    }   

    Long.fixLow = function(a){
        return fixlow(a);
    }

    Long.getLongFromStr = function (data) {
            var L = new Long(0,0);
            var startWithHex = data.indexOf("0x");
            if(data.length <= 10){
                var lowStr = data.substring(data.length-8, data.length);
                L.low = parseInt("0x"+lowStr);
                L.high = 0;
                return L;
            }
            if(startWithHex == 0){
                var lowStr = data.substring(data.length-8, data.length);
                L.low = parseInt("0x"+lowStr);
                var highStr = data.substring(0, data.length-8);
                L.high = parseInt(highStr);
                return L;
            }
                
    }

} ());;
    (function () {
    var KU = KeyouCryptography.util;
    var Checker = KeyouCryptography.util.Checker;
    var Long = KeyouCryptography.util.Long;
    var Hex = KeyouCryptography.util.Hex;

    var Helper = KU.Helper = (function () {
        var chars = "0123456789abcdefghijklmnopqrstuvwxyz";
        var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var b64pad="=";

        var int2char = function (n) {
            return chars.charAt(n);
        };

        return {

            /**
             * 产生随机数
             * 
             * @param  {Integer} size 随机数的个数
             * 
             * @return {Uint8Array}      0 - 255 范围的随机数字节数组
             *
             * @static 
             *
             * @example
             * 
             */
            getRandom: function (size) {
                Checker.checkArgument(size > 0, "the random of size must be more than zero.");
                var r = (function (m_w) {
                    var m_w = m_w;
                    var m_z = 0x3ade68b1;
                    var mask = 0xffffffff;

                    return function () {
                        m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
                        m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
                        var result = ((m_z << 0x10) + m_w) & mask;
                        result /= 0x100000000;
                        result += 0.5;
                        return result * (Math.random() > .5 ? 1 : -1);
                    }
                });

                var random = new Array(size);
                for (var i = 0, rcache; i < size; i++) {
                    var _r = r((rcache || Math.random()) * 0x100000000);
                    rcache = _r() * 0x3ade67b7; 
                    random[i] = rcache & 0xFF;
                }
                return random;                           
            },

            /**
             * 数组拷贝
             * @param  {Array} des    目标数组
             * @param  {Integer} desoff 偏移值
             * @param  {Array} src    待拷贝数组
             * @param  {Integer} srcoff 偏移值
             * @param  {Integer} len    拷贝长度
             * @return {Array}        新的数组
             */
            arraycopy: function (des, desoff, src, srcoff, len) {
                for (var i = 0; i < len; i++) {
                    des[desoff + i] = src[srcoff + i];
                }
            },

            /**
             * 字节数组转 ASC 码字符串，仅限于可打印的 ASCII 码
             * 
             * @param  {Uint8Array} arr 字节数组
             * 
             * @return {String}     转换后的字符串
             *
             * @throws {TypeError} arr 包含不可见字符
             *
             * @static
             *
             * @example
             *
             *      [0x31, 0x32, 0x33] => '123'
             */
            array2ascstr: function (arr) {
                var str = '';
                for (var i = 0, len = arr.length; i < len; i++) {
                    Checker.checkArgument(arr[i] >= 0x20 && arr[i] <= 0x7E, 
                        'contains Non-printable ASCII Character in Array');
                    str += String.fromCharCode(arr[i]);
                }
                return str;
            },

            /**
             * ASC 字符串转字节数组
             * 
             * @param  {String} str ASC 字符串
             * 
             * @return {Uint8Array}     arr 字节数组
             *
             * @throws {TypeError} If str 包含不在 0x20 到 0x7E 范围内的字符
             *
             * @static
             *
             * @example
             *
             *      '1234' => [0x31, 0x32, 0x33, 0x34]
             */
            ascstr2array: function (str) {
                if (str.length === 0) {
                    return [];
                }
                Checker.checkArgument(Checker.checkOnlyPrintChar(str), "only support printable ASCII character.");
                var arr = new Array(str.length);
                for (var i = 0, len = str.length; i < len; i++) {
                    arr[i] = str.charCodeAt(i)
                }
                return arr;
            },

            /**
             * 1 字节的 byte 数组转换为 4 字节的 int 数组
             * @param  {Uint8Array} bytes byte 类型的数组
             * @return {Uint32Array}       int 类型的数组
             */
            bytes2integers: function (bytes, offset) {
                if (bytes.length % 4 != 0) {
                    console.error('illegal argument.');
                }
                var integers = [];
                for (var i = offset || 0, len = bytes.length; i < len; i += 4) {
                    integers.push((
                        bytes[i + 0] << 24 
                        | bytes[i + 1] << 16 
                        | bytes[i + 2] << 8 
                        | bytes[i + 3]) >>> 0);
                }
                return integers;
            },

            /**
             * 4 字节的 int 数组转换为 1 字节 byte 数组
             * @param  {Uint32Array} integers int 类型的数组
             * @return {Uint8Array}          byte 类型的数组
             */
            integers2bytes: function (integers, offset) {
                var bytes = [];
                for (var i = offset || 0, len = integers.length; i < len; i++) {
                    bytes.push((integers[i] >>> 24) & 0xFF);
                    bytes.push((integers[i] >>> 16) & 0xFF);
                    bytes.push((integers[i] >>>  8) & 0xFF);
                    bytes.push((integers[i] >>>  0) & 0xFF);
                }
                return bytes;
            },


            /**
             * 16 进制字符串转换为 Base64 字符串
             * 
             * @param  {String} h 16进制的字符串
             * 
             * @return {String}   Base64 的字符串
             * 
             * @static
             *
             * @example
             * 
             */
            hex2b64: function (h) {
                var i;
                var c;
                var ret = "";
                for(i = 0; i+3 <= h.length; i+=3) {
                    c = parseInt(h.substring(i,i+3),16);
                    ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
                }
                if(i+1 == h.length) {
                    c = parseInt(h.substring(i,i+1),16);
                    ret += b64map.charAt(c << 2);
                }
                else if(i+2 == h.length) {
                    c = parseInt(h.substring(i,i+2),16);
                    ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
                }
                while((ret.length & 3) > 0) ret += b64pad;
                return ret;                
            },

            /**
             * Base 64 的字符串转加密为16进制的字符串
             * 
             * @param  {String} s Base64字符串
             * 
             * @return {String}   16进制的字符串
             *
             * @static
             *
             * @example
             * 
             */
            b64tohex: function (s) {
                var ret = ""
                var i;
                var k = 0; // b64 state, 0-3
                var slop;
                for(i = 0; i < s.length; ++i) {
                    if(s.charAt(i) == b64pad) break;
                    v = b64map.indexOf(s.charAt(i));
                    if(v < 0) continue;
                    if(k == 0) {
                        ret += int2char(v >> 2);
                        slop = v & 3;
                        k = 1;
                    }
                    else if(k == 1) {
                        ret += int2char((slop << 2) | (v >> 4));
                        slop = v & 0xf;
                        k = 2;
                    }
                    else if(k == 2) {
                        ret += int2char(slop);
                        ret += int2char(v >> 2);
                        slop = v & 3;
                        k = 3;
                    }
                    else {
                        ret += int2char((slop << 2) | (v >> 4));
                        ret += int2char(v & 0xf);
                        k = 0;
                    }
                }
                if(k == 1)
                    ret += int2char(slop << 2);
                return ret;
            },

            asctob64: function(s){
                var arr = this.ascstr2array(s);
                var hexStr = Hex.stringify(arr);
                return this.hex2b64(hexStr);
            },

            b64toasc: function(s){
                var hexStr = this.b64tohex(s);
                var arr = Hex.parse(hexStr);
                return this.array2ascstr(arr);
            },

            /**
             * [convertLong 将十六进制字符串类型的数据转换为长度为 8 的字节数组]
             * @param    {[type]}                 number [长整型十六进制数据]
             * @return   {[type]}                        [8 byte 的字节数组]
             */
            convertLong:function(hexnumber){
                var res = new Array(8);
                var numberL = Long.getLongFromStr(hexnumber);
                res[0] = (numberL.high >>> 24) & 0xFF;
                res[1] = (numberL.high >>> 16) & 0xFF;
                res[2] = (numberL.high >>> 8) & 0xFF;
                res[3] = (numberL.high >>> 0) & 0xFF;
                res[4] = (numberL.low >>> 24) & 0xFF;
                res[5] = (numberL.low >>> 16) & 0xFF;
                res[6] = (numberL.low >>>  8) & 0xFF;
                res[7] = (numberL.low >>>  0) & 0xFF;
                return res;
            },
            /**
             * [convertInteger 将 int 型的数据转换为长度为 4 bytes 的字节数组]
             * @param    {[type]}                 number [整型数据]
             * @return   {[type]}                        [4 byte 的字节数组]
             */
            convertInteger:function(number){
                var res = new Array(4);
                res[0] = (number >>> 24) & 0xFF;
                res[1] = (number >>> 16) & 0xFF;
                res[2] = (number >>>  8) & 0xFF;
                res[3] = (number >>>  0) & 0xFF;
                return res;
            },
            /**
             * [ascXOR description]
             * @param    {[type]}                 a [一个 [0-9A-F] 范围的字符]
             * @param    {[type]}                 b [一个 [0-9A-F] 范围的字符]
             * @return   {[type]}                   [异或后得到的 [0-9A-F] 范围的字符]
             */
            ascXOR:function(a,b){
                var HEX = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46];
                return HEX[((a >> 6) * 9 + (a & 0x0F)) ^ ((b >> 6) * 9 + (b & 0x0F))];
            },
            /**
             * [generateDecRandom 生成随机的 10 进制字符串]
             * @param    {[type]}                 size [字符串长度]
             * @return   {[type]}                      [随机 10 进制字符字符串]
             */
            generateDecRandom:function(size){
                var random = this.getRandom(size);
                var dec = '';
                for (var i = 0; i < size; i++){
                    dec += random[i] % 9;
                }
                return dec;
            }
        };

    } ());
} ());;


    

    

    
        (function () {
    var KA = KeyouCryptography.algorithm;
    var Checker = KeyouCryptography.util.Checker;

    /**
     * 国密数据摘要算法
     */
    var SM3 = KA.SM3 = (function () {
        var SM3_BLOCK_SIZE = 32;

        var total = new Array(0x00, 0x00);
        var state = new Array(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        var buffer = new Array(64);
        for  (var i = 0; i < 64; i++) {
            buffer[i] = 0x00;
        }

        var sm3_padding = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        var sm2_par_dig = [
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 
            0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7, 
            0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93, 
            0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94, 
            0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7, 
            0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53, 
            0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
        ];

        var getUnsignedInt = function (data) {
            return data >>> 0;
        }

        var  getUnsignedV = function (d) {
            return (0x0FFFFFFFF - getUnsignedInt(d)) >>> 0;
        }

        var FF0 = function (x, y, z) {
            return getUnsignedInt(x ^ y ^ z);
        }

        var FF1 = function (x, y, z) {
            return getUnsignedInt((x & y) | (x & z) | (y & z));
        }

        var GG0 = function (x, y, z) {
            return getUnsignedInt(x ^ y ^ z);
        }

        var GG1 = function (x, y, z) {
            return getUnsignedInt((x & y) | (getUnsignedV(x) & z));
        }

        var SHL = function (x, n) {
            return getUnsignedInt(getUnsignedInt(x) << n % 32);
        }

        var ROTL = function (x, n) {
            return getUnsignedInt(SHL(x, n) | (getUnsignedInt(x) >>> (32 - n % 32)));
        }

        var P0 = function (x) {
            return getUnsignedInt(getUnsignedInt(x) ^  ROTL(x,9) ^ ROTL(x,17));
        }

        var P1 = function (x) {
            return getUnsignedInt(getUnsignedInt(x) ^  ROTL(x,15) ^ ROTL(x,23));
        }

        var init = function () {
            total[0] = 0;
            total[1] = 0;

            state[0] = 0x7380166F;
            state[1] = 0x4914B2B9;
            state[2] = 0x172442D7;
            state[3] = 0x0DA8A0600;
            state[4] = 0x0A96F30BC;
            state[5] = 0x163138AA;
            state[6] = 0x0E38DEE4D;
            state[7] = 0x0B0FB0E4E;
        }

        var GET_ULONG_BE = function (b, offset, i) {
            var n = ((0x0FF000000 & (b[offset + i + 0] << 24))
                    | (0x000FF0000 & (b[offset + i + 1] << 16))
                    | (0x00000FF00 & (b[offset + i + 2] << 8))
                    | (0x0000000FF & (b[offset + i + 3])));
            return getUnsignedInt(n);
        }

        var PUT_ULONG_BE = function (n, b, i) {
            n = n >>> 0;
            b[i + 0] = (0xFF & ((0x0FF000000 & n) >>> 24));
            b[i + 1] = (0xFF & ((0x000FF0000 & n) >>> 16));
            b[i + 2] = (0xFF & ((0x00000FF00 & n) >>> 8));
            b[i + 3] = (0xFF & ((0x0000000FF & n)));
        }


        var sm3_process = function (data, offset) {
            var SS1, 
                SS2,
                TT1,
                TT2,
                W = new Array(68),
                W1 = new Array(64),
                A,
                B,
                C,
                D,
                E,
                F,
                G,
                H,
                T = new Array(64),
                Temp1,
                Temp2,
                Temp3,
                Temp4,
                Temp5;
            for (var i = 68; i > 0; i--) {
                W[i - 1] = 0;
            }
            for (var i = 64; i > 0; i--) {
                W1[i - 1] = 0;
            }

            for (var i = 0; i < 16; i++) {
                T[i] = 0x79CC4519;
            }
            for (var i = 16; i < 64; i++) {
                T[i] = 0x7A879D8A;
            }
            for (var i = 0; i < 16; i++) {
                W[i] = GET_ULONG_BE(data, offset, i * 4);
            }

            for (var i = 16; i < 68; i++) {
                Temp1 = (W[i - 16] ^ W[i - 9]) >>> 0;
                Temp2 = ROTL(W[i - 3], 15);
                Temp3 = (Temp1 ^ Temp2) >>> 0;
                Temp4 = P1(Temp3);
                Temp5 = (ROTL(W[i - 13], 7) ^ W[i - 6]) >>> 0;
                W[i] = (Temp4 ^ Temp5) >>> 0 ;
            }

            for (var i = 0; i < 64; i++) {
                W1[i] = (W[i] ^ W[i + 4]) >>> 0;
            }

            A = state[0] >>> 0;
            B = state[1] >>> 0;
            C = state[2] >>> 0;
            D = state[3] >>> 0;
            E = state[4] >>> 0;
            F = state[5] >>> 0;
            G = state[6] >>> 0;
            H = state[7] >>> 0; 

            for (var i = 0; i < 16; i++) {
                SS1 = (ROTL((ROTL(A,12) + E + ROTL(T[i],i)), 7)); 
                SS2 = (SS1 ^ ROTL(A,12) >>> 0);
                TT1 = (FF0(A,B,C) + D + SS2 + W1[i]);
                TT2 = (GG0(E,F,G) + H + SS1 + W[i]);
                D = getUnsignedInt(C);
                C = ROTL(B,9);
                B = getUnsignedInt(A);
                A = getUnsignedInt(TT1);
                H = getUnsignedInt(G);
                G = ROTL(F,19);
                F = getUnsignedInt(E);
                E = P0(TT2);
            }

            for(var i =16; i < 64; i++) {
                SS1 = getUnsignedInt(ROTL((ROTL(A,12) + E + ROTL(T[i],i)), 7)); 
                SS2 = getUnsignedInt(SS1 ^ ROTL(A,12));
                TT1 = getUnsignedInt(FF1(A,B,C) + D + SS2 + W1[i]);
                TT2 = getUnsignedInt(GG1(E,F,G) + H + SS1 + W[i]);
                D = getUnsignedInt(C);
                C = ROTL(B,9);
                B = getUnsignedInt(A);
                A = getUnsignedInt(TT1);
                H = getUnsignedInt(G);
                G = ROTL(F,19);
                F = getUnsignedInt(E);
                E = P0(TT2);
            }

            state[0] = (A ^ state[0]) >>> 0;
            state[1] = (B ^ state[1]) >>> 0;
            state[2] = (C ^ state[2]) >>> 0;
            state[3] = (D ^ state[3]) >>> 0;
            state[4] = (E ^ state[4]) >>> 0;
            state[5] = (F ^ state[5]) >>> 0;
            state[6] = (G ^ state[6]) >>> 0;
            state[7] = (H ^ state[7]) >>> 0;
        }

        var memcpy = function (des, desoff, src, srcoff, len) {
            for (var i = 0; i < len; i++) {
                des[desoff + i] = src[srcoff + i];
            }
        }

        var update = function (input, ilen) {
            if (typeof input === undefined || input === null) {
                return;
            }

            var left = total[0] & 0x3F;
            var fill = 64 - left;
            total[0] += ilen;
            total[0] >>> 0;

            if (total[0] < ilen) {
                total[1]++;
            }

            var offset2 = 0;
            if (left !== 0 && ilen >= fill) {
                memcpy(buffer, left, input, offset2, fill);
                sm3_process(buffer, 0);
                offset2 += fill;
                ilen -= fill;
                left = 0;
            }

            while (ilen >= 64) {
                sm3_process(input, offset2);
                offset2 += 64;
                ilen -= 64;
            }

            if (ilen > 0) {
                memcpy (buffer, left, input, offset2, ilen);
            }

        }

        var final = function () {
            var digest = new Array(32);
            var last, padn, high, low, msglen = new Array(8);

            high = getUnsignedInt((total[0] >>> 29) | (total[1] << 3));
            low = getUnsignedInt(total[0] << 3);

            PUT_ULONG_BE(high, msglen, 0);
            PUT_ULONG_BE(low, msglen, 4);

            last = getUnsignedInt(total[0] & 0x3F);
            padn = (last < 56) ? (56 - last) : (120 - last);
            update(sm3_padding, padn);
            update(msglen, 8);
            for (var i = 0; i < 8; i++) {
                PUT_ULONG_BE(state[i], digest, i * 4);
            }
            return digest;
        }

        return {

            /**
             * SM3 计算数据摘要值
             * 
             * @param  {Uint8Array} input 数据值
             * 
             * @return {Uint8Array}       32 字节的摘要数据
             */
            digest: function (input) {
                Checker.checkExist(input, "illegal input.");
                init();
                update(input, input.length);
                return final();                
            },

            init: function (){
                init();
            },

            update: function (input) {
                Checker.checkExist(input, "illegal input.");
                update(input, input.length);
            },

            doFinal: function() {
                var digest = final();
                return digest;
            },

            /**
             * SM3 计算待 SM2 公钥和 userID 的 HMAC 值
             * 
             * @param  {Uint8Array} input     数据值
             * @param  {Uint8Array} userid    用户标识
             * @param  {Uint8Array} publicKey 公钥值
             * 
             * @return {Uint8Array}           32 字节的摘要数据
             */
            hmacWithPublicKey: function (input, userid, publicKey) {
                var tmpBuf = new Array(2 + userid.length + 128 + 64);
                var oriHashData = new Array(input.length + 32);

                var userid_bitlen = userid.length << 3;
                tmpBuf[0] = (userid.length >> 8) & 0xFF;
                tmpBuf[1] = userid.length & 0xFF;

                memcpy(tmpBuf, 2, userid, 0, userid.length);
                memcpy(tmpBuf, 2 + userid.length, sm2_par_dig, 0, sm2_par_dig.length);
                memcpy(tmpBuf, 2 + userid.length + sm2_par_dig.length, publicKey, 0, publicKey.length);

                var sm3data = digest(tmpBuf);
                memcpy(oriHashData, 0, sm3data, 0, 32);
                memcpy(oriHashData, 32, input, 0, input.length);
                return digest(oriHashData);

            },

            /**
             * SM3 计算 HMAC
             * @param  {Uint8Array} key   参与计算的密钥值
             * @param  {Uint8Array} input 参与计算的数据
             * @return {Uint8Array}       32 字节的摘要数据
             */
            hmac: function (key, input) {
                var ipad = new Array(64);
                var opad = new Array(64);
                for (var i = 0; i < 64; i++) {
                    ipad[i] = 0x36;
                    opad[i] = 0x5c;
                }

                for (var i = 0, len = key.length; i < len; i++) {
                    ipad[i] = (ipad[i] ^ key[i]) >>> 0;
                    opad[i] = (opad[i] ^ key[i]) >>> 0;
                }
                init();
                update(ipad, ipad.length);
                update(input, input.length);
                var imac = final();
                init();
                update(opad, opad.length);
                update(imac, imac.length);
                return final();
            }
        }
    }());
}());
    

    

    

    
    
    

    
    

    

    

    

    
    
    
    
    return KeyouCryptography;
}));