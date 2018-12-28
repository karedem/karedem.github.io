
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
    var KU = KeyouCryptography.util;

    var DataPadding = KU.DataPadding = (function () {

        return  {

            encodeWithNone: function (data, size) {
                return data;
            },

            decodeWithNone: function (data) {
                return data;
            },

            /**
             * PKCS#5 或 PKCS#7 填充数据数组
             * 
             * @param  {Uint8Array} data 待填充数据字节数组
             * @param  {Integer} size 数据块大小
             * 
             * @return {Uint8Array}      填充后的字节数组
             *
             * @static 
             *
             * @example
             * 
             */
            encodeWithPKCS5: function (data, size) {
                var length = size - data.length % size;
                var pad = new Array(data.length + length);
                for (var i = 0; i < data.length; i++) {
                    pad[i] = data[i];
                }
                for (var i = data.length; i < length + data.length; i++) {
                    pad[i] = length;
                }
                return pad;
            },

            /**
             * PKCS#5 或 PKCS#7 去填充
             * 
             * @param  {Uint8Array} data 去填充数据
             * 
             * @return {Uint8Array}      去填充后的数据
             *
             * @static
             *
             * @example
             * 
             */
            decodeWithPKCS5: function (data) {
                var length = data[data.length - 1];
                return data.slice(0, data.length - length);
            },

            /**
             * 0x00 填充数据到指定长度
             * 
             * @param  {Uint8Array} data 待填充的数据值
             * @param  {Uint8Array} size 数据块大小
             * 
             * @return {Uint8Array}      填充后的数据值
             * 
             * @static
             * 
             * @example
             * 
             */
            encodeWith0x00: function (data, size) {
                var length = size - data.length % size;
                var pad = new Array(data.length + length);
                for (var i = 0; i < data.length; i++) {
                    pad[i] = data[i];
                }
                for (var i = data.length; i < length + data.length; i++) {
                    pad[i] = 0x00;
                }
                return pad;
            },

            /**
             * 对 0x00 填充的数据去填充
             * 
             * @param  {Uint8Array} data 填充后的数据
             *                                    
             * @return {Uint8Array}      去填充后的数据
             *
             * @static
             *
             * @example
             * 
             */
            decodeWith0x00: function (data) {
                var index = 0;
                for (var i = data.length - 1; i >= 0; i--) {
                    if (data[i] != 0x00) {
                        index = i + 1;
                        break;
                    }
                }
                return data.slice(0, index);
            },

            /**
             * 0x80 的方式填充数据
             * 
             * @param  {Uint8Arrary} data 待填充的数据值
             * @param  {Integer} size 数据块大小
             * 
             * @return {Uint8Array}     填充后的数据
             *
             * @static
             *
             * @example
             *
             * 
             */
            encodeWith0x80: function (data, size) {
                var length = size - data.length % size;
                var pad = new Array(data.length + length);
                for (var i = 0; i < data.length; i++) {
                    pad[i] = data[i];
                }
                pad[data.length] = 0x80;
                for (var i = data.length + 1; i < length + data.length; i++) {
                    pad[i] = 0x00;
                }
                return pad;
            },

            /**
             * 0x80 的方式对数据做去填充
             * 
             * @param  {Uint8Array} data 需要去填充的数据
             * 
             * @return {Uint8Array}      去填充后的数据
             *
             * @static
             *
             * @example
             * 
             */
            decodeWith0x80: function (data) {
                var index = 0;
                for (var i = data.length - 1; i >= 0; i--) {
                    if (data[i] != 0x00 && data[i] != 0x80) {
                        index = i + 1;
                        break;
                    }
                }
                return data.slice(0, index);
            },

            encodeWithLV0: function (data, size) {

            },

            decodeWithLV0: function (data) {
                
            }

        }
    }());
}());;
    

    
        /*****core.js*****/

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
/**
 * CryptoJS core components.
 */
var CryptoJS = CryptoJS || (function (Math, undefined) {
    /**
     * CryptoJS namespace.
     */
    var C = {};

    /**
     * Library namespace.
     */
    var C_lib = C.lib = {};

    /**
     * Base object for prototypal inheritance.
     */
    var Base = C_lib.Base = (function () {
        function F() {}

        return {
            /**
             * Creates a new object that inherits from this object.
             *
             * @param {Object} overrides Properties to copy into the new object.
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         field: 'value',
             *
             *         method: function () {
             *         }
             *     });
             */
            extend: function (overrides) {
                // Spawn
                F.prototype = this;
                var subtype = new F();

                // Augment
                if (overrides) {
                    subtype.mixIn(overrides);
                }

                // Create default initializer
                if (!subtype.hasOwnProperty('init')) {
                    subtype.init = function () {
                        subtype.$super.init.apply(this, arguments);
                    };
                }

                // Initializer's prototype is the subtype object
                subtype.init.prototype = subtype;

                // Reference supertype
                subtype.$super = this;

                return subtype;
            },

            /**
             * Extends this object and runs the init method.
             * Arguments to create() will be passed to init().
             *
             * @return {Object} The new object.
             *
             * @static
             *
             * @example
             *
             *     var instance = MyType.create();
             */
            create: function () {
                var instance = this.extend();
                instance.init.apply(instance, arguments);

                return instance;
            },

            /**
             * Initializes a newly created object.
             * Override this method to add some logic when your objects are created.
             *
             * @example
             *
             *     var MyType = CryptoJS.lib.Base.extend({
             *         init: function () {
             *             // ...
             *         }
             *     });
             */
            init: function () {
            },

            /**
             * Copies properties into this object.
             *
             * @param {Object} properties The properties to mix in.
             *
             * @example
             *
             *     MyType.mixIn({
             *         field: 'value'
             *     });
             */
            mixIn: function (properties) {
                for (var propertyName in properties) {
                    if (properties.hasOwnProperty(propertyName)) {
                        this[propertyName] = properties[propertyName];
                    }
                }

                // IE won't copy toString using the loop above
                if (properties.hasOwnProperty('toString')) {
                    this.toString = properties.toString;
                }
            },

            /**
             * Creates a copy of this object.
             *
             * @return {Object} The clone.
             *
             * @example
             *
             *     var clone = instance.clone();
             */
            clone: function () {
                return this.init.prototype.extend(this);
            }
        };
    }());

    /**
     * An array of 32-bit words.
     *
     * @property {Array} words The array of 32-bit words.
     * @property {number} sigBytes The number of significant bytes in this word array.
     */
    var WordArray = C_lib.WordArray = Base.extend({
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.create();
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
         */
        init: function (words, sigBytes) {
            words = this.words = words || [];

            if (sigBytes != undefined) {
                this.sigBytes = sigBytes;
            } else {
                this.sigBytes = words.length * 4;
            }
        },

        /**
         * Converts this word array to a string.
         *
         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
         *
         * @return {string} The stringified word array.
         *
         * @example
         *
         *     var string = wordArray + '';
         *     var string = wordArray.toString();
         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
         */
        toString: function (encoder) {
            return (encoder || Hex).stringify(this);
        },

        /**
         * Concatenates a word array to this word array.
         *
         * @param {WordArray} wordArray The word array to append.
         *
         * @return {WordArray} This word array.
         *
         * @example
         *
         *     wordArray1.concat(wordArray2);
         */
        concat: function (wordArray) {
            // Shortcuts
            var thisWords = this.words;
            var thatWords = wordArray.words;
            var thisSigBytes = this.sigBytes;
            var thatSigBytes = wordArray.sigBytes;

            // Clamp excess bits
            this.clamp();

            // Concat
            if (thisSigBytes % 4) {
                // Copy one byte at a time
                for (var i = 0; i < thatSigBytes; i++) {
                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                }
            } else if (thatWords.length > 0xffff) {
                // Copy one word at a time
                for (var i = 0; i < thatSigBytes; i += 4) {
                    thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
                }
            } else {
                // Copy all words at once
                thisWords.push.apply(thisWords, thatWords);
            }
            this.sigBytes += thatSigBytes;

            // Chainable
            return this;
        },

        /**
         * Removes insignificant bits.
         *
         * @example
         *
         *     wordArray.clamp();
         */
        clamp: function () {
            // Shortcuts
            var words = this.words;
            var sigBytes = this.sigBytes;

            // Clamp
            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
            words.length = Math.ceil(sigBytes / 4);
        },

        /**
         * Creates a copy of this word array.
         *
         * @return {WordArray} The clone.
         *
         * @example
         *
         *     var clone = wordArray.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone.words = this.words.slice(0);

            return clone;
        },

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {WordArray} The random word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.random(16);
         */
        random: function (nBytes) {
            var words = [];
            for (var i = 0; i < nBytes; i += 4) {
                words.push((Math.random() * 0x100000000) | 0);
            }

            return new WordArray.init(words, nBytes);
        }
    });

    /**
     * Encoder namespace.
     */
    var C_enc = C.enc = {};

    /**
     * Hex encoding strategy.
     */
    var Hex = C_enc.Hex = {
        /**
         * Converts a word array to a hex string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var hexChars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                hexChars.push((bite >>> 4).toString(16));
                hexChars.push((bite & 0x0f).toString(16));
            }

            return hexChars.join('');
        },

        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
         */
        parse: function (hexStr) {
            // Shortcut
            var hexStrLength = hexStr.length;

            // Convert
            var words = [];
            for (var i = 0; i < hexStrLength; i += 2) {
                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
            }

            return new WordArray.init(words, hexStrLength / 2);
        }
    };

    /**
     * Latin1 encoding strategy.
     */
    var Latin1 = C_enc.Latin1 = {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         *
         * @example
         *
         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var latin1Chars = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                latin1Chars.push(String.fromCharCode(bite));
            }

            return latin1Chars.join('');
        },

        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
         */
        parse: function (latin1Str) {
            // Shortcut
            var latin1StrLength = latin1Str.length;

            // Convert
            var words = [];
            for (var i = 0; i < latin1StrLength; i++) {
                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
            }

            return new WordArray.init(words, latin1StrLength);
        }
    };

    /**
     * UTF-8 encoding strategy.
     */
    var Utf8 = C_enc.Utf8 = {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         *
         * @example
         *
         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
         */
        stringify: function (wordArray) {
            try {
                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
            } catch (e) {
                throw new Error('Malformed UTF-8 data');
            }
        },

        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
         */
        parse: function (utf8Str) {
            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
    };

    /**
     * Abstract buffered block algorithm template.
     *
     * The property blockSize must be implemented in a concrete subtype.
     *
     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
     */
    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
        /**
         * Resets this block algorithm's data buffer to its initial state.
         *
         * @example
         *
         *     bufferedBlockAlgorithm.reset();
         */
        reset: function () {
            // Initial values
            this._data = new WordArray.init();
            this._nDataBytes = 0;
        },

        /**
         * Adds new data to this block algorithm's buffer.
         *
         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
         *
         * @example
         *
         *     bufferedBlockAlgorithm._append('data');
         *     bufferedBlockAlgorithm._append(wordArray);
         */
        _append: function (data) {
            // Convert string to WordArray, else assume WordArray already
            if (typeof data == 'string') {
                data = Utf8.parse(data);
            }

            // Append
            this._data.concat(data);
            this._nDataBytes += data.sigBytes;
        },

        /**
         * Processes available data blocks.
         *
         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
         *
         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
         *
         * @return {WordArray} The processed data.
         *
         * @example
         *
         *     var processedData = bufferedBlockAlgorithm._process();
         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
         */
        _process: function (doFlush) {
            // Shortcuts
            var data = this._data;
            var dataWords = data.words;
            var dataSigBytes = data.sigBytes;
            var blockSize = this.blockSize;
            var blockSizeBytes = blockSize * 4;

            // Count blocks ready
            var nBlocksReady = dataSigBytes / blockSizeBytes;
            if (doFlush) {
                // Round up to include partial blocks
                nBlocksReady = Math.ceil(nBlocksReady);
            } else {
                // Round down to include only full blocks,
                // less the number of blocks that must remain in the buffer
                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
            }

            // Count words ready
            var nWordsReady = nBlocksReady * blockSize;

            // Count bytes ready
            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

            // Process blocks
            if (nWordsReady) {
                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
                    // Perform concrete-algorithm logic
                    this._doProcessBlock(dataWords, offset);
                }

                // Remove processed words
                var processedWords = dataWords.splice(0, nWordsReady);
                data.sigBytes -= nBytesReady;
            }

            // Return processed words
            return new WordArray.init(processedWords, nBytesReady);
        },

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = bufferedBlockAlgorithm.clone();
         */
        clone: function () {
            var clone = Base.clone.call(this);
            clone._data = this._data.clone();

            return clone;
        },

        _minBufferSize: 0
    });

    /**
     * Abstract hasher template.
     *
     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
     */
    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
        /**
         * Configuration options.
         */
        cfg: Base.extend(),

        /**
         * Initializes a newly created hasher.
         *
         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
         *
         * @example
         *
         *     var hasher = CryptoJS.algo.SHA256.create();
         */
        init: function (cfg) {
            // Apply config defaults
            this.cfg = this.cfg.extend(cfg);

            // Set initial values
            this.reset();
        },

        /**
         * Resets this hasher to its initial state.
         *
         * @example
         *
         *     hasher.reset();
         */
        reset: function () {
            // Reset data buffer
            BufferedBlockAlgorithm.reset.call(this);

            // Perform concrete-hasher logic
            this._doReset();
        },

        /**
         * Updates this hasher with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {Hasher} This hasher.
         *
         * @example
         *
         *     hasher.update('message');
         *     hasher.update(wordArray);
         */
        update: function (messageUpdate) {
            // Append
            this._append(messageUpdate);

            // Update the hash
            this._process();

            // Chainable
            return this;
        },

        /**
         * Finalizes the hash computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The hash.
         *
         * @example
         *
         *     var hash = hasher.finalize();
         *     var hash = hasher.finalize('message');
         *     var hash = hasher.finalize(wordArray);
         */
        finalize: function (messageUpdate) {
            // Final message update
            if (messageUpdate) {
                this._append(messageUpdate);
            }

            // Perform concrete-hasher logic
            var hash = this._doFinalize();

            return hash;
        },

        blockSize: 512/32,

        /**
         * Creates a shortcut function to a hasher's object interface.
         *
         * @param {Hasher} hasher The hasher to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
         */
        _createHelper: function (hasher) {
            return function (message, cfg) {
                return new hasher.init(cfg).finalize(message);
            };
        },

        /**
         * Creates a shortcut function to the HMAC's object interface.
         *
         * @param {Hasher} hasher The hasher to use in this HMAC helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
         */
        _createHmacHelper: function (hasher) {
            return function (message, key) {
                return new C_algo.HMAC.init(hasher, key).finalize(message);
            };
        }
    });

    /**
     * Algorithm namespace.
     */
    var C_algo = C.algo = {};

    return C;
}(Math));


/*****cipher-core.js*****/

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
/**
 * Cipher core components.
 */
CryptoJS.lib.Cipher || (function (undefined) {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var Base = C_lib.Base;
    var WordArray = C_lib.WordArray;
    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
    var C_enc = C.enc;
    var Utf8 = C_enc.Utf8;
    var Base64 = C_enc.Base64;
    var C_algo = C.algo;
    var EvpKDF = C_algo.EvpKDF;

    /**
     * Abstract base cipher template.
     *
     * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
     * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
     * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
     * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
     */
    var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
        /**
         * Configuration options.
         *
         * @property {WordArray} iv The IV to use for this operation.
         */
        cfg: Base.extend(),

        /**
         * Creates this cipher in encryption mode.
         *
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {Cipher} A cipher instance.
         *
         * @static
         *
         * @example
         *
         *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
         */
        createEncryptor: function (key, cfg) {
            return this.create(this._ENC_XFORM_MODE, key, cfg);
        },

        /**
         * Creates this cipher in decryption mode.
         *
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {Cipher} A cipher instance.
         *
         * @static
         *
         * @example
         *
         *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
         */
        createDecryptor: function (key, cfg) {
            return this.create(this._DEC_XFORM_MODE, key, cfg);
        },

        /**
         * Initializes a newly created cipher.
         *
         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @example
         *
         *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
         */
        init: function (xformMode, key, cfg) {
            // Apply config defaults
            this.cfg = this.cfg.extend(cfg);

            // Store transform mode and key
            this._xformMode = xformMode;
            this._key = key;

            // Set initial values
            this.reset();
        },

        /**
         * Resets this cipher to its initial state.
         *
         * @example
         *
         *     cipher.reset();
         */
        reset: function () {
            // Reset data buffer
            BufferedBlockAlgorithm.reset.call(this);

            // Perform concrete-cipher logic
            this._doReset();
        },

        /**
         * Adds data to be encrypted or decrypted.
         *
         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
         *
         * @return {WordArray} The data after processing.
         *
         * @example
         *
         *     var encrypted = cipher.process('data');
         *     var encrypted = cipher.process(wordArray);
         */
        process: function (dataUpdate) {
            // Append
            this._append(dataUpdate);

            // Process available blocks
            return this._process();
        },

        /**
         * Finalizes the encryption or decryption process.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
         *
         * @return {WordArray} The data after final processing.
         *
         * @example
         *
         *     var encrypted = cipher.finalize();
         *     var encrypted = cipher.finalize('data');
         *     var encrypted = cipher.finalize(wordArray);
         */
        finalize: function (dataUpdate) {
            // Final data update
            if (dataUpdate) {
                this._append(dataUpdate);
            }

            // Perform concrete-cipher logic
            var finalProcessedData = this._doFinalize();

            return finalProcessedData;
        },

        keySize: 128/32,

        ivSize: 128/32,

        _ENC_XFORM_MODE: 1,

        _DEC_XFORM_MODE: 2,

        /**
         * Creates shortcut functions to a cipher's object interface.
         *
         * @param {Cipher} cipher The cipher to create a helper for.
         *
         * @return {Object} An object with encrypt and decrypt shortcut functions.
         *
         * @static
         *
         * @example
         *
         *     var AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
         */
        _createHelper: (function () {
            function selectCipherStrategy(key) {
                if (typeof key == 'string') {
                    return PasswordBasedCipher;
                } else {
                    return SerializableCipher;
                }
            }

            return function (cipher) {
                return {
                    encrypt: function (message, key, cfg) {
                        return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
                    },

                    decrypt: function (ciphertext, key, cfg) {
                        return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
                    }
                };
            };
        }())
    });

    /**
     * Abstract base stream cipher template.
     *
     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
     */
    var StreamCipher = C_lib.StreamCipher = Cipher.extend({
        _doFinalize: function () {
            // Process partial blocks
            var finalProcessedBlocks = this._process(!!'flush');

            return finalProcessedBlocks;
        },

        blockSize: 1
    });

    /**
     * Mode namespace.
     */
    var C_mode = C.mode = {};

    /**
     * Abstract base block cipher mode template.
     */
    var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({
        /**
         * Creates this mode for encryption.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @static
         *
         * @example
         *
         *     var mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
         */
        createEncryptor: function (cipher, iv) {
            return this.Encryptor.create(cipher, iv);
        },

        /**
         * Creates this mode for decryption.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @static
         *
         * @example
         *
         *     var mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
         */
        createDecryptor: function (cipher, iv) {
            return this.Decryptor.create(cipher, iv);
        },

        /**
         * Initializes a newly created mode.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @example
         *
         *     var mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
         */
        init: function (cipher, iv) {
            this._cipher = cipher;
            this._iv = iv;
        }
    });

    /**
     * Cipher Block Chaining mode.
     */
    var CBC = C_mode.CBC = (function () {
        /**
         * Abstract base CBC mode.
         */
        var CBC = BlockCipherMode.extend();

        /**
         * CBC encryptor.
         */
        CBC.Encryptor = CBC.extend({
            /**
             * Processes the data block at offset.
             *
             * @param {Array} words The data words to operate on.
             * @param {number} offset The offset where the block starts.
             *
             * @example
             *
             *     mode.processBlock(data.words, offset);
             */
            processBlock: function (words, offset) {
                // Shortcuts
                var cipher = this._cipher;
                var blockSize = cipher.blockSize;

                // XOR and encrypt
                xorBlock.call(this, words, offset, blockSize);
                cipher.encryptBlock(words, offset);

                // Remember this block to use with next block
                this._prevBlock = words.slice(offset, offset + blockSize);
            }
        });

        /**
         * CBC decryptor.
         */
        CBC.Decryptor = CBC.extend({
            /**
             * Processes the data block at offset.
             *
             * @param {Array} words The data words to operate on.
             * @param {number} offset The offset where the block starts.
             *
             * @example
             *
             *     mode.processBlock(data.words, offset);
             */
            processBlock: function (words, offset) {
                // Shortcuts
                var cipher = this._cipher;
                var blockSize = cipher.blockSize;

                // Remember this block to use with next block
                var thisBlock = words.slice(offset, offset + blockSize);

                // Decrypt and XOR
                cipher.decryptBlock(words, offset);
                xorBlock.call(this, words, offset, blockSize);

                // This block becomes the previous block
                this._prevBlock = thisBlock;
            }
        });

        function xorBlock(words, offset, blockSize) {
            // Shortcut
            var iv = this._iv;

            // Choose mixing block
            if (iv) {
                var block = iv;

                // Remove IV for subsequent blocks
                this._iv = undefined;
            } else {
                var block = this._prevBlock;
            }

            // XOR blocks
            for (var i = 0; i < blockSize; i++) {
                words[offset + i] ^= block[i];
            }
        }

        return CBC;
    }());

    /**
     * Padding namespace.
     */
    var C_pad = C.pad = {};

    /**
     * PKCS #5/7 padding strategy.
     */
    var Pkcs7 = C_pad.Pkcs7 = {
        /**
         * Pads data using the algorithm defined in PKCS #5/7.
         *
         * @param {WordArray} data The data to pad.
         * @param {number} blockSize The multiple that the data should be padded to.
         *
         * @static
         *
         * @example
         *
         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
         */
        pad: function (data, blockSize) {
            // Shortcut
            var blockSizeBytes = blockSize * 4;

            // Count padding bytes
            var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

            // Create padding word
            var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

            // Create padding
            var paddingWords = [];
            for (var i = 0; i < nPaddingBytes; i += 4) {
                paddingWords.push(paddingWord);
            }
            var padding = WordArray.create(paddingWords, nPaddingBytes);

            // Add padding
            data.concat(padding);
        },

        /**
         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
         *
         * @param {WordArray} data The data to unpad.
         *
         * @static
         *
         * @example
         *
         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
         */
        unpad: function (data) {
            // Get number of padding bytes from last byte
            var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

            // Remove padding
            data.sigBytes -= nPaddingBytes;
        }
    };

    /**
     * Abstract base block cipher template.
     *
     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
     */
    var BlockCipher = C_lib.BlockCipher = Cipher.extend({
        /**
         * Configuration options.
         *
         * @property {Mode} mode The block mode to use. Default: CBC
         * @property {Padding} padding The padding strategy to use. Default: Pkcs7
         */
        cfg: Cipher.cfg.extend({
            mode: CBC,
            padding: Pkcs7
        }),

        reset: function () {
            // Reset cipher
            Cipher.reset.call(this);

            // Shortcuts
            var cfg = this.cfg;
            var iv = cfg.iv;
            var mode = cfg.mode;

            // Reset block mode
            if (this._xformMode == this._ENC_XFORM_MODE) {
                var modeCreator = mode.createEncryptor;
            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
                var modeCreator = mode.createDecryptor;

                // Keep at least one block in the buffer for unpadding
                this._minBufferSize = 1;
            }
            this._mode = modeCreator.call(mode, this, iv && iv.words);
        },

        _doProcessBlock: function (words, offset) {
            this._mode.processBlock(words, offset);
        },

        _doFinalize: function () {
            // Shortcut
            var padding = this.cfg.padding;

            // Finalize
            if (this._xformMode == this._ENC_XFORM_MODE) {
                // Pad data
                padding.pad(this._data, this.blockSize);

                // Process final blocks
                var finalProcessedBlocks = this._process(!!'flush');
            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
                // Process final blocks
                var finalProcessedBlocks = this._process(!!'flush');

                // Unpad data
                padding.unpad(finalProcessedBlocks);
            }

            return finalProcessedBlocks;
        },

        blockSize: 128/32
    });

    /**
     * A collection of cipher parameters.
     *
     * @property {WordArray} ciphertext The raw ciphertext.
     * @property {WordArray} key The key to this ciphertext.
     * @property {WordArray} iv The IV used in the ciphering operation.
     * @property {WordArray} salt The salt used with a key derivation function.
     * @property {Cipher} algorithm The cipher algorithm.
     * @property {Mode} mode The block mode used in the ciphering operation.
     * @property {Padding} padding The padding scheme used in the ciphering operation.
     * @property {number} blockSize The block size of the cipher.
     * @property {Format} formatter The default formatting strategy to convert this cipher params object to a string.
     */
    var CipherParams = C_lib.CipherParams = Base.extend({
        /**
         * Initializes a newly created cipher params object.
         *
         * @param {Object} cipherParams An object with any of the possible cipher parameters.
         *
         * @example
         *
         *     var cipherParams = CryptoJS.lib.CipherParams.create({
         *         ciphertext: ciphertextWordArray,
         *         key: keyWordArray,
         *         iv: ivWordArray,
         *         salt: saltWordArray,
         *         algorithm: CryptoJS.algo.AES,
         *         mode: CryptoJS.mode.CBC,
         *         padding: CryptoJS.pad.PKCS7,
         *         blockSize: 4,
         *         formatter: CryptoJS.format.OpenSSL
         *     });
         */
        init: function (cipherParams) {
            this.mixIn(cipherParams);
        },

        /**
         * Converts this cipher params object to a string.
         *
         * @param {Format} formatter (Optional) The formatting strategy to use.
         *
         * @return {string} The stringified cipher params.
         *
         * @throws Error If neither the formatter nor the default formatter is set.
         *
         * @example
         *
         *     var string = cipherParams + '';
         *     var string = cipherParams.toString();
         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
         */
        toString: function (formatter) {
            return (formatter || this.formatter).stringify(this);
        }
    });

    /**
     * Format namespace.
     */
    var C_format = C.format = {};

    /**
     * OpenSSL formatting strategy.
     */
    var OpenSSLFormatter = C_format.OpenSSL = {
        /**
         * Converts a cipher params object to an OpenSSL-compatible string.
         *
         * @param {CipherParams} cipherParams The cipher params object.
         *
         * @return {string} The OpenSSL-compatible string.
         *
         * @static
         *
         * @example
         *
         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
         */
        stringify: function (cipherParams) {
            // Shortcuts
            var ciphertext = cipherParams.ciphertext;
            var salt = cipherParams.salt;

            // Format
            if (salt) {
                var wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
            } else {
                var wordArray = ciphertext;
            }

            return wordArray.toString(Base64);
        },

        /**
         * Converts an OpenSSL-compatible string to a cipher params object.
         *
         * @param {string} openSSLStr The OpenSSL-compatible string.
         *
         * @return {CipherParams} The cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
         */
        parse: function (openSSLStr) {
            // Parse base64
            var ciphertext = Base64.parse(openSSLStr);

            // Shortcut
            var ciphertextWords = ciphertext.words;

            // Test for salt
            if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
                // Extract salt
                var salt = WordArray.create(ciphertextWords.slice(2, 4));

                // Remove salt from ciphertext
                ciphertextWords.splice(0, 4);
                ciphertext.sigBytes -= 16;
            }

            return CipherParams.create({ ciphertext: ciphertext, salt: salt });
        }
    };

    /**
     * A cipher wrapper that returns ciphertext as a serializable cipher params object.
     */
    var SerializableCipher = C_lib.SerializableCipher = Base.extend({
        /**
         * Configuration options.
         *
         * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
         */
        cfg: Base.extend({
            format: OpenSSLFormatter
        }),

        /**
         * Encrypts a message.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {WordArray|string} message The message to encrypt.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {CipherParams} A cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key);
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
         */
        encrypt: function (cipher, message, key, cfg) {
            // Apply config defaults
            cfg = this.cfg.extend(cfg);

            // Encrypt
            var encryptor = cipher.createEncryptor(key, cfg);
            var ciphertext = encryptor.finalize(message);

            // Shortcut
            var cipherCfg = encryptor.cfg;

            // Create and return serializable cipher params
            return CipherParams.create({
                ciphertext: ciphertext,
                key: key,
                iv: cipherCfg.iv,
                algorithm: cipher,
                mode: cipherCfg.mode,
                padding: cipherCfg.padding,
                blockSize: cipher.blockSize,
                formatter: cfg.format
            });
        },

        /**
         * Decrypts serialized ciphertext.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {WordArray} The plaintext.
         *
         * @static
         *
         * @example
         *
         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, key, { iv: iv, format: CryptoJS.format.OpenSSL });
         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, key, { iv: iv, format: CryptoJS.format.OpenSSL });
         */
        decrypt: function (cipher, ciphertext, key, cfg) {
            // Apply config defaults
            cfg = this.cfg.extend(cfg);

            // Convert string to CipherParams
            ciphertext = this._parse(ciphertext, cfg.format);

            // Decrypt
            var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

            return plaintext;
        },

        /**
         * Converts serialized ciphertext to CipherParams,
         * else assumed CipherParams already and returns ciphertext unchanged.
         *
         * @param {CipherParams|string} ciphertext The ciphertext.
         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
         *
         * @return {CipherParams} The unserialized ciphertext.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher._parse(ciphertextStringOrParams, format);
         */
        _parse: function (ciphertext, format) {
            if (typeof ciphertext == 'string') {
                return format.parse(ciphertext, this);
            } else {
                return ciphertext;
            }
        }
    });

    /**
     * Key derivation function namespace.
     */
    var C_kdf = C.kdf = {};

    /**
     * OpenSSL key derivation function.
     */
    var OpenSSLKdf = C_kdf.OpenSSL = {
        /**
         * Derives a key and IV from a password.
         *
         * @param {string} password The password to derive from.
         * @param {number} keySize The size in words of the key to generate.
         * @param {number} ivSize The size in words of the IV to generate.
         * @param {WordArray|string} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
         *
         * @return {CipherParams} A cipher params object with the key, IV, and salt.
         *
         * @static
         *
         * @example
         *
         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
         */
        execute: function (password, keySize, ivSize, salt) {
            // Generate random salt
            if (!salt) {
                salt = WordArray.random(64/8);
            }

            // Derive key and IV
            var key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);

            // Separate key and IV
            var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
            key.sigBytes = keySize * 4;

            // Return params
            return CipherParams.create({ key: key, iv: iv, salt: salt });
        }
    };

    /**
     * A serializable cipher wrapper that derives the key from a password,
     * and returns ciphertext as a serializable cipher params object.
     */
    var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({
        /**
         * Configuration options.
         *
         * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
         */
        cfg: SerializableCipher.cfg.extend({
            kdf: OpenSSLKdf
        }),

        /**
         * Encrypts a message using a password.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {WordArray|string} message The message to encrypt.
         * @param {string} password The password.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {CipherParams} A cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password');
         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
         */
        encrypt: function (cipher, message, password, cfg) {
            // Apply config defaults
            cfg = this.cfg.extend(cfg);

            // Derive key and other params
            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

            // Add IV to config
            cfg.iv = derivedParams.iv;

            // Encrypt
            var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

            // Mix in derived params
            ciphertext.mixIn(derivedParams);

            return ciphertext;
        },

        /**
         * Decrypts serialized ciphertext using a password.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
         * @param {string} password The password.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {WordArray} The plaintext.
         *
         * @static
         *
         * @example
         *
         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password', { format: CryptoJS.format.OpenSSL });
         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, 'password', { format: CryptoJS.format.OpenSSL });
         */
        decrypt: function (cipher, ciphertext, password, cfg) {
            // Apply config defaults
            cfg = this.cfg.extend(cfg);

            // Convert string to CipherParams
            ciphertext = this._parse(ciphertext, cfg.format);

            // Derive key and other params
            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

            // Add IV to config
            cfg.iv = derivedParams.iv;

            // Decrypt
            var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

            return plaintext;
        }
    });
}());

/*****tripledes.js*****/

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function () {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var BlockCipher = C_lib.BlockCipher;
    var C_algo = C.algo;

    // Permuted Choice 1 constants
    var PC1 = [
        57, 49, 41, 33, 25, 17, 9,  1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7,  62, 54, 46, 38,
        30, 22, 14, 6,  61, 53, 45, 37,
        29, 21, 13, 5,  28, 20, 12, 4
    ];

    // Permuted Choice 2 constants
    var PC2 = [
        14, 17, 11, 24, 1,  5,
        3,  28, 15, 6,  21, 10,
        23, 19, 12, 4,  26, 8,
        16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ];

    // Cumulative bit shift constants
    var BIT_SHIFTS = [1,  2,  4,  6,  8,  10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

    // SBOXes and round permutation constants
    var SBOX_P = [
        {
            0x0: 0x808200,
            0x10000000: 0x8000,
            0x20000000: 0x808002,
            0x30000000: 0x2,
            0x40000000: 0x200,
            0x50000000: 0x808202,
            0x60000000: 0x800202,
            0x70000000: 0x800000,
            0x80000000: 0x202,
            0x90000000: 0x800200,
            0xa0000000: 0x8200,
            0xb0000000: 0x808000,
            0xc0000000: 0x8002,
            0xd0000000: 0x800002,
            0xe0000000: 0x0,
            0xf0000000: 0x8202,
            0x8000000: 0x0,
            0x18000000: 0x808202,
            0x28000000: 0x8202,
            0x38000000: 0x8000,
            0x48000000: 0x808200,
            0x58000000: 0x200,
            0x68000000: 0x808002,
            0x78000000: 0x2,
            0x88000000: 0x800200,
            0x98000000: 0x8200,
            0xa8000000: 0x808000,
            0xb8000000: 0x800202,
            0xc8000000: 0x800002,
            0xd8000000: 0x8002,
            0xe8000000: 0x202,
            0xf8000000: 0x800000,
            0x1: 0x8000,
            0x10000001: 0x2,
            0x20000001: 0x808200,
            0x30000001: 0x800000,
            0x40000001: 0x808002,
            0x50000001: 0x8200,
            0x60000001: 0x200,
            0x70000001: 0x800202,
            0x80000001: 0x808202,
            0x90000001: 0x808000,
            0xa0000001: 0x800002,
            0xb0000001: 0x8202,
            0xc0000001: 0x202,
            0xd0000001: 0x800200,
            0xe0000001: 0x8002,
            0xf0000001: 0x0,
            0x8000001: 0x808202,
            0x18000001: 0x808000,
            0x28000001: 0x800000,
            0x38000001: 0x200,
            0x48000001: 0x8000,
            0x58000001: 0x800002,
            0x68000001: 0x2,
            0x78000001: 0x8202,
            0x88000001: 0x8002,
            0x98000001: 0x800202,
            0xa8000001: 0x202,
            0xb8000001: 0x808200,
            0xc8000001: 0x800200,
            0xd8000001: 0x0,
            0xe8000001: 0x8200,
            0xf8000001: 0x808002
        },
        {
            0x0: 0x40084010,
            0x1000000: 0x4000,
            0x2000000: 0x80000,
            0x3000000: 0x40080010,
            0x4000000: 0x40000010,
            0x5000000: 0x40084000,
            0x6000000: 0x40004000,
            0x7000000: 0x10,
            0x8000000: 0x84000,
            0x9000000: 0x40004010,
            0xa000000: 0x40000000,
            0xb000000: 0x84010,
            0xc000000: 0x80010,
            0xd000000: 0x0,
            0xe000000: 0x4010,
            0xf000000: 0x40080000,
            0x800000: 0x40004000,
            0x1800000: 0x84010,
            0x2800000: 0x10,
            0x3800000: 0x40004010,
            0x4800000: 0x40084010,
            0x5800000: 0x40000000,
            0x6800000: 0x80000,
            0x7800000: 0x40080010,
            0x8800000: 0x80010,
            0x9800000: 0x0,
            0xa800000: 0x4000,
            0xb800000: 0x40080000,
            0xc800000: 0x40000010,
            0xd800000: 0x84000,
            0xe800000: 0x40084000,
            0xf800000: 0x4010,
            0x10000000: 0x0,
            0x11000000: 0x40080010,
            0x12000000: 0x40004010,
            0x13000000: 0x40084000,
            0x14000000: 0x40080000,
            0x15000000: 0x10,
            0x16000000: 0x84010,
            0x17000000: 0x4000,
            0x18000000: 0x4010,
            0x19000000: 0x80000,
            0x1a000000: 0x80010,
            0x1b000000: 0x40000010,
            0x1c000000: 0x84000,
            0x1d000000: 0x40004000,
            0x1e000000: 0x40000000,
            0x1f000000: 0x40084010,
            0x10800000: 0x84010,
            0x11800000: 0x80000,
            0x12800000: 0x40080000,
            0x13800000: 0x4000,
            0x14800000: 0x40004000,
            0x15800000: 0x40084010,
            0x16800000: 0x10,
            0x17800000: 0x40000000,
            0x18800000: 0x40084000,
            0x19800000: 0x40000010,
            0x1a800000: 0x40004010,
            0x1b800000: 0x80010,
            0x1c800000: 0x0,
            0x1d800000: 0x4010,
            0x1e800000: 0x40080010,
            0x1f800000: 0x84000
        },
        {
            0x0: 0x104,
            0x100000: 0x0,
            0x200000: 0x4000100,
            0x300000: 0x10104,
            0x400000: 0x10004,
            0x500000: 0x4000004,
            0x600000: 0x4010104,
            0x700000: 0x4010000,
            0x800000: 0x4000000,
            0x900000: 0x4010100,
            0xa00000: 0x10100,
            0xb00000: 0x4010004,
            0xc00000: 0x4000104,
            0xd00000: 0x10000,
            0xe00000: 0x4,
            0xf00000: 0x100,
            0x80000: 0x4010100,
            0x180000: 0x4010004,
            0x280000: 0x0,
            0x380000: 0x4000100,
            0x480000: 0x4000004,
            0x580000: 0x10000,
            0x680000: 0x10004,
            0x780000: 0x104,
            0x880000: 0x4,
            0x980000: 0x100,
            0xa80000: 0x4010000,
            0xb80000: 0x10104,
            0xc80000: 0x10100,
            0xd80000: 0x4000104,
            0xe80000: 0x4010104,
            0xf80000: 0x4000000,
            0x1000000: 0x4010100,
            0x1100000: 0x10004,
            0x1200000: 0x10000,
            0x1300000: 0x4000100,
            0x1400000: 0x100,
            0x1500000: 0x4010104,
            0x1600000: 0x4000004,
            0x1700000: 0x0,
            0x1800000: 0x4000104,
            0x1900000: 0x4000000,
            0x1a00000: 0x4,
            0x1b00000: 0x10100,
            0x1c00000: 0x4010000,
            0x1d00000: 0x104,
            0x1e00000: 0x10104,
            0x1f00000: 0x4010004,
            0x1080000: 0x4000000,
            0x1180000: 0x104,
            0x1280000: 0x4010100,
            0x1380000: 0x0,
            0x1480000: 0x10004,
            0x1580000: 0x4000100,
            0x1680000: 0x100,
            0x1780000: 0x4010004,
            0x1880000: 0x10000,
            0x1980000: 0x4010104,
            0x1a80000: 0x10104,
            0x1b80000: 0x4000004,
            0x1c80000: 0x4000104,
            0x1d80000: 0x4010000,
            0x1e80000: 0x4,
            0x1f80000: 0x10100
        },
        {
            0x0: 0x80401000,
            0x10000: 0x80001040,
            0x20000: 0x401040,
            0x30000: 0x80400000,
            0x40000: 0x0,
            0x50000: 0x401000,
            0x60000: 0x80000040,
            0x70000: 0x400040,
            0x80000: 0x80000000,
            0x90000: 0x400000,
            0xa0000: 0x40,
            0xb0000: 0x80001000,
            0xc0000: 0x80400040,
            0xd0000: 0x1040,
            0xe0000: 0x1000,
            0xf0000: 0x80401040,
            0x8000: 0x80001040,
            0x18000: 0x40,
            0x28000: 0x80400040,
            0x38000: 0x80001000,
            0x48000: 0x401000,
            0x58000: 0x80401040,
            0x68000: 0x0,
            0x78000: 0x80400000,
            0x88000: 0x1000,
            0x98000: 0x80401000,
            0xa8000: 0x400000,
            0xb8000: 0x1040,
            0xc8000: 0x80000000,
            0xd8000: 0x400040,
            0xe8000: 0x401040,
            0xf8000: 0x80000040,
            0x100000: 0x400040,
            0x110000: 0x401000,
            0x120000: 0x80000040,
            0x130000: 0x0,
            0x140000: 0x1040,
            0x150000: 0x80400040,
            0x160000: 0x80401000,
            0x170000: 0x80001040,
            0x180000: 0x80401040,
            0x190000: 0x80000000,
            0x1a0000: 0x80400000,
            0x1b0000: 0x401040,
            0x1c0000: 0x80001000,
            0x1d0000: 0x400000,
            0x1e0000: 0x40,
            0x1f0000: 0x1000,
            0x108000: 0x80400000,
            0x118000: 0x80401040,
            0x128000: 0x0,
            0x138000: 0x401000,
            0x148000: 0x400040,
            0x158000: 0x80000000,
            0x168000: 0x80001040,
            0x178000: 0x40,
            0x188000: 0x80000040,
            0x198000: 0x1000,
            0x1a8000: 0x80001000,
            0x1b8000: 0x80400040,
            0x1c8000: 0x1040,
            0x1d8000: 0x80401000,
            0x1e8000: 0x400000,
            0x1f8000: 0x401040
        },
        {
            0x0: 0x80,
            0x1000: 0x1040000,
            0x2000: 0x40000,
            0x3000: 0x20000000,
            0x4000: 0x20040080,
            0x5000: 0x1000080,
            0x6000: 0x21000080,
            0x7000: 0x40080,
            0x8000: 0x1000000,
            0x9000: 0x20040000,
            0xa000: 0x20000080,
            0xb000: 0x21040080,
            0xc000: 0x21040000,
            0xd000: 0x0,
            0xe000: 0x1040080,
            0xf000: 0x21000000,
            0x800: 0x1040080,
            0x1800: 0x21000080,
            0x2800: 0x80,
            0x3800: 0x1040000,
            0x4800: 0x40000,
            0x5800: 0x20040080,
            0x6800: 0x21040000,
            0x7800: 0x20000000,
            0x8800: 0x20040000,
            0x9800: 0x0,
            0xa800: 0x21040080,
            0xb800: 0x1000080,
            0xc800: 0x20000080,
            0xd800: 0x21000000,
            0xe800: 0x1000000,
            0xf800: 0x40080,
            0x10000: 0x40000,
            0x11000: 0x80,
            0x12000: 0x20000000,
            0x13000: 0x21000080,
            0x14000: 0x1000080,
            0x15000: 0x21040000,
            0x16000: 0x20040080,
            0x17000: 0x1000000,
            0x18000: 0x21040080,
            0x19000: 0x21000000,
            0x1a000: 0x1040000,
            0x1b000: 0x20040000,
            0x1c000: 0x40080,
            0x1d000: 0x20000080,
            0x1e000: 0x0,
            0x1f000: 0x1040080,
            0x10800: 0x21000080,
            0x11800: 0x1000000,
            0x12800: 0x1040000,
            0x13800: 0x20040080,
            0x14800: 0x20000000,
            0x15800: 0x1040080,
            0x16800: 0x80,
            0x17800: 0x21040000,
            0x18800: 0x40080,
            0x19800: 0x21040080,
            0x1a800: 0x0,
            0x1b800: 0x21000000,
            0x1c800: 0x1000080,
            0x1d800: 0x40000,
            0x1e800: 0x20040000,
            0x1f800: 0x20000080
        },
        {
            0x0: 0x10000008,
            0x100: 0x2000,
            0x200: 0x10200000,
            0x300: 0x10202008,
            0x400: 0x10002000,
            0x500: 0x200000,
            0x600: 0x200008,
            0x700: 0x10000000,
            0x800: 0x0,
            0x900: 0x10002008,
            0xa00: 0x202000,
            0xb00: 0x8,
            0xc00: 0x10200008,
            0xd00: 0x202008,
            0xe00: 0x2008,
            0xf00: 0x10202000,
            0x80: 0x10200000,
            0x180: 0x10202008,
            0x280: 0x8,
            0x380: 0x200000,
            0x480: 0x202008,
            0x580: 0x10000008,
            0x680: 0x10002000,
            0x780: 0x2008,
            0x880: 0x200008,
            0x980: 0x2000,
            0xa80: 0x10002008,
            0xb80: 0x10200008,
            0xc80: 0x0,
            0xd80: 0x10202000,
            0xe80: 0x202000,
            0xf80: 0x10000000,
            0x1000: 0x10002000,
            0x1100: 0x10200008,
            0x1200: 0x10202008,
            0x1300: 0x2008,
            0x1400: 0x200000,
            0x1500: 0x10000000,
            0x1600: 0x10000008,
            0x1700: 0x202000,
            0x1800: 0x202008,
            0x1900: 0x0,
            0x1a00: 0x8,
            0x1b00: 0x10200000,
            0x1c00: 0x2000,
            0x1d00: 0x10002008,
            0x1e00: 0x10202000,
            0x1f00: 0x200008,
            0x1080: 0x8,
            0x1180: 0x202000,
            0x1280: 0x200000,
            0x1380: 0x10000008,
            0x1480: 0x10002000,
            0x1580: 0x2008,
            0x1680: 0x10202008,
            0x1780: 0x10200000,
            0x1880: 0x10202000,
            0x1980: 0x10200008,
            0x1a80: 0x2000,
            0x1b80: 0x202008,
            0x1c80: 0x200008,
            0x1d80: 0x0,
            0x1e80: 0x10000000,
            0x1f80: 0x10002008
        },
        {
            0x0: 0x100000,
            0x10: 0x2000401,
            0x20: 0x400,
            0x30: 0x100401,
            0x40: 0x2100401,
            0x50: 0x0,
            0x60: 0x1,
            0x70: 0x2100001,
            0x80: 0x2000400,
            0x90: 0x100001,
            0xa0: 0x2000001,
            0xb0: 0x2100400,
            0xc0: 0x2100000,
            0xd0: 0x401,
            0xe0: 0x100400,
            0xf0: 0x2000000,
            0x8: 0x2100001,
            0x18: 0x0,
            0x28: 0x2000401,
            0x38: 0x2100400,
            0x48: 0x100000,
            0x58: 0x2000001,
            0x68: 0x2000000,
            0x78: 0x401,
            0x88: 0x100401,
            0x98: 0x2000400,
            0xa8: 0x2100000,
            0xb8: 0x100001,
            0xc8: 0x400,
            0xd8: 0x2100401,
            0xe8: 0x1,
            0xf8: 0x100400,
            0x100: 0x2000000,
            0x110: 0x100000,
            0x120: 0x2000401,
            0x130: 0x2100001,
            0x140: 0x100001,
            0x150: 0x2000400,
            0x160: 0x2100400,
            0x170: 0x100401,
            0x180: 0x401,
            0x190: 0x2100401,
            0x1a0: 0x100400,
            0x1b0: 0x1,
            0x1c0: 0x0,
            0x1d0: 0x2100000,
            0x1e0: 0x2000001,
            0x1f0: 0x400,
            0x108: 0x100400,
            0x118: 0x2000401,
            0x128: 0x2100001,
            0x138: 0x1,
            0x148: 0x2000000,
            0x158: 0x100000,
            0x168: 0x401,
            0x178: 0x2100400,
            0x188: 0x2000001,
            0x198: 0x2100000,
            0x1a8: 0x0,
            0x1b8: 0x2100401,
            0x1c8: 0x100401,
            0x1d8: 0x400,
            0x1e8: 0x2000400,
            0x1f8: 0x100001
        },
        {
            0x0: 0x8000820,
            0x1: 0x20000,
            0x2: 0x8000000,
            0x3: 0x20,
            0x4: 0x20020,
            0x5: 0x8020820,
            0x6: 0x8020800,
            0x7: 0x800,
            0x8: 0x8020000,
            0x9: 0x8000800,
            0xa: 0x20800,
            0xb: 0x8020020,
            0xc: 0x820,
            0xd: 0x0,
            0xe: 0x8000020,
            0xf: 0x20820,
            0x80000000: 0x800,
            0x80000001: 0x8020820,
            0x80000002: 0x8000820,
            0x80000003: 0x8000000,
            0x80000004: 0x8020000,
            0x80000005: 0x20800,
            0x80000006: 0x20820,
            0x80000007: 0x20,
            0x80000008: 0x8000020,
            0x80000009: 0x820,
            0x8000000a: 0x20020,
            0x8000000b: 0x8020800,
            0x8000000c: 0x0,
            0x8000000d: 0x8020020,
            0x8000000e: 0x8000800,
            0x8000000f: 0x20000,
            0x10: 0x20820,
            0x11: 0x8020800,
            0x12: 0x20,
            0x13: 0x800,
            0x14: 0x8000800,
            0x15: 0x8000020,
            0x16: 0x8020020,
            0x17: 0x20000,
            0x18: 0x0,
            0x19: 0x20020,
            0x1a: 0x8020000,
            0x1b: 0x8000820,
            0x1c: 0x8020820,
            0x1d: 0x20800,
            0x1e: 0x820,
            0x1f: 0x8000000,
            0x80000010: 0x20000,
            0x80000011: 0x800,
            0x80000012: 0x8020020,
            0x80000013: 0x20820,
            0x80000014: 0x20,
            0x80000015: 0x8020000,
            0x80000016: 0x8000000,
            0x80000017: 0x8000820,
            0x80000018: 0x8020820,
            0x80000019: 0x8000020,
            0x8000001a: 0x8000800,
            0x8000001b: 0x0,
            0x8000001c: 0x20800,
            0x8000001d: 0x820,
            0x8000001e: 0x20020,
            0x8000001f: 0x8020800
        }
    ];

    // Masks that select the SBOX input
    var SBOX_MASK = [
        0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000,
        0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f
    ];

    /**
     * DES block cipher algorithm.
     */
    var DES = C_algo.DES = BlockCipher.extend({
        _doReset: function () {
            // Shortcuts
            var key = this._key;
            var keyWords = key.words;

            // Select 56 bits according to PC1
            var keyBits = [];
            for (var i = 0; i < 56; i++) {
                var keyBitPos = PC1[i] - 1;
                keyBits[i] = (keyWords[keyBitPos >>> 5] >>> (31 - keyBitPos % 32)) & 1;
            }

            // Assemble 16 subkeys
            var subKeys = this._subKeys = [];
            for (var nSubKey = 0; nSubKey < 16; nSubKey++) {
                // Create subkey
                var subKey = subKeys[nSubKey] = [];

                // Shortcut
                var bitShift = BIT_SHIFTS[nSubKey];

                // Select 48 bits according to PC2
                for (var i = 0; i < 24; i++) {
                    // Select from the left 28 key bits
                    subKey[(i / 6) | 0] |= keyBits[((PC2[i] - 1) + bitShift) % 28] << (31 - i % 6);

                    // Select from the right 28 key bits
                    subKey[4 + ((i / 6) | 0)] |= keyBits[28 + (((PC2[i + 24] - 1) + bitShift) % 28)] << (31 - i % 6);
                }

                // Since each subkey is applied to an expanded 32-bit input,
                // the subkey can be broken into 8 values scaled to 32-bits,
                // which allows the key to be used without expansion
                subKey[0] = (subKey[0] << 1) | (subKey[0] >>> 31);
                for (var i = 1; i < 7; i++) {
                    subKey[i] = subKey[i] >>> ((i - 1) * 4 + 3);
                }
                subKey[7] = (subKey[7] << 5) | (subKey[7] >>> 27);
            }

            // Compute inverse subkeys
            var invSubKeys = this._invSubKeys = [];
            for (var i = 0; i < 16; i++) {
                invSubKeys[i] = subKeys[15 - i];
            }
        },

        encryptBlock: function (M, offset) {
            this._doCryptBlock(M, offset, this._subKeys);
        },

        decryptBlock: function (M, offset) {
            this._doCryptBlock(M, offset, this._invSubKeys);
        },

        _doCryptBlock: function (M, offset, subKeys) {
            // Get input
            this._lBlock = M[offset];
            this._rBlock = M[offset + 1];

            // Initial permutation
            exchangeLR.call(this, 4,  0x0f0f0f0f);
            exchangeLR.call(this, 16, 0x0000ffff);
            exchangeRL.call(this, 2,  0x33333333);
            exchangeRL.call(this, 8,  0x00ff00ff);
            exchangeLR.call(this, 1,  0x55555555);

            // Rounds
            for (var round = 0; round < 16; round++) {
                // Shortcuts
                var subKey = subKeys[round];
                var lBlock = this._lBlock;
                var rBlock = this._rBlock;

                // Feistel function
                var f = 0;
                for (var i = 0; i < 8; i++) {
                    f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
                }
                this._lBlock = rBlock;
                this._rBlock = lBlock ^ f;
            }

            // Undo swap from last round
            var t = this._lBlock;
            this._lBlock = this._rBlock;
            this._rBlock = t;

            // Final permutation
            exchangeLR.call(this, 1,  0x55555555);
            exchangeRL.call(this, 8,  0x00ff00ff);
            exchangeRL.call(this, 2,  0x33333333);
            exchangeLR.call(this, 16, 0x0000ffff);
            exchangeLR.call(this, 4,  0x0f0f0f0f);

            // Set output
            M[offset] = this._lBlock;
            M[offset + 1] = this._rBlock;
        },

        keySize: 64/32,

        ivSize: 64/32,

        blockSize: 64/32
    });

    // Swap bits across the left and right words
    function exchangeLR(offset, mask) {
        var t = ((this._lBlock >>> offset) ^ this._rBlock) & mask;
        this._rBlock ^= t;
        this._lBlock ^= t << offset;
    }

    function exchangeRL(offset, mask) {
        var t = ((this._rBlock >>> offset) ^ this._lBlock) & mask;
        this._lBlock ^= t;
        this._rBlock ^= t << offset;
    }

    /**
     * Shortcut functions to the cipher's object interface.
     *
     * @example
     *
     *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
     *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
     */
    C.DES = BlockCipher._createHelper(DES);

    /**
     * Triple-DES block cipher algorithm.
     */
    var TripleDES = C_algo.TripleDES = BlockCipher.extend({
        _doReset: function () {
            // Shortcuts
            var key = this._key;
            var keyWords = key.words;

            // Create DES instances
            this._des1 = DES.createEncryptor(WordArray.create(keyWords.slice(0, 2)));
            this._des2 = DES.createEncryptor(WordArray.create(keyWords.slice(2, 4)));
            this._des3 = DES.createEncryptor(WordArray.create(keyWords.slice(4, 6)));
        },

        encryptBlock: function (M, offset) {
            this._des1.encryptBlock(M, offset);
            this._des2.decryptBlock(M, offset);
            this._des3.encryptBlock(M, offset);
        },

        decryptBlock: function (M, offset) {
            this._des3.decryptBlock(M, offset);
            this._des2.encryptBlock(M, offset);
            this._des1.decryptBlock(M, offset);
        },

        keySize: 192/32,

        ivSize: 64/32,

        blockSize: 64/32
    });

    /**
     * Shortcut functions to the cipher's object interface.
     *
     * @example
     *
     *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
     *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
     */
    C.TripleDES = BlockCipher._createHelper(TripleDES);
}());

/*****enc-base64.js*****/

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function () {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var C_enc = C.enc;

    /**
     * Base64 encoding strategy.
     */
    var Base64 = C_enc.Base64 = {
        /**
         * Converts a word array to a Base64 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Base64 string.
         *
         * @static
         *
         * @example
         *
         *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;
            var map = this._map;

            // Clamp excess bits
            wordArray.clamp();

            // Convert
            var base64Chars = [];
            for (var i = 0; i < sigBytes; i += 3) {
                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
                }
            }

            // Add padding
            var paddingChar = map.charAt(64);
            if (paddingChar) {
                while (base64Chars.length % 4) {
                    base64Chars.push(paddingChar);
                }
            }

            return base64Chars.join('');
        },

        /**
         * Converts a Base64 string to a word array.
         *
         * @param {string} base64Str The Base64 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
         */
        parse: function (base64Str) {
            // Shortcuts
            var base64StrLength = base64Str.length;
            var map = this._map;

            // Ignore padding
            var paddingChar = map.charAt(64);
            if (paddingChar) {
                var paddingIndex = base64Str.indexOf(paddingChar);
                if (paddingIndex != -1) {
                    base64StrLength = paddingIndex;
                }
            }

            // Convert
            var words = [];
            var nBytes = 0;
            for (var i = 0; i < base64StrLength; i++) {
                if (i % 4) {
                    var bits1 = map.indexOf(base64Str.charAt(i - 1)) << ((i % 4) * 2);
                    var bits2 = map.indexOf(base64Str.charAt(i)) >>> (6 - (i % 4) * 2);
                    words[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
                    nBytes++;
                }
            }

            return WordArray.create(words, nBytes);
        },

        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    };
}());

/*****jsbn.js*****/

/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
//change ~start by wx
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

//start replace
function BigInteger(a, b, c) {
  if (!(this instanceof BigInteger))
    return new BigInteger(a, b, c)

  if (a != null) {
    if ("number" == typeof a) this.fromNumber(a, b, c)
    else if (b == null && "string" != typeof a) this.fromString(a, 256)
    else this.fromString(a, b)
  }
}

var proto = BigInteger.prototype

// duck-typed isBigInteger
/*proto.__bigi = require('package.json').version
BigInteger.isBigInteger = function (obj, check_ver) {
  return obj && obj.__bigi && (!check_ver || obj.__bigi === proto.__bigi)
}*/

// Bits per digit
var dbits

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i, x, w, j, c, n) {
  while (--n >= 0) {
    var v = x * this[i++] + w[j] + c
    c = Math.floor(v / 0x4000000)
    w[j++] = v & 0x3ffffff
  }
  return c
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i, x, w, j, c, n) {
  var xl = x & 0x7fff,
    xh = x >> 15
  while (--n >= 0) {
    var l = this[i] & 0x7fff
    var h = this[i++] >> 15
    var m = xh * l + h * xl
    l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff)
    c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30)
    w[j++] = l & 0x3fffffff
  }
  return c
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i, x, w, j, c, n) {
  var xl = x & 0x3fff,
    xh = x >> 14
  while (--n >= 0) {
    var l = this[i] & 0x3fff
    var h = this[i++] >> 14
    var m = xh * l + h * xl
    l = xl * l + ((m & 0x3fff) << 14) + w[j] + c
    c = (l >> 28) + (m >> 14) + xh * h
    w[j++] = l & 0xfffffff
  }
  return c
}



// wtf?
BigInteger.prototype.am = am1
dbits = 26

BigInteger.prototype.DB = dbits
BigInteger.prototype.DM = ((1 << dbits) - 1)
var DV = BigInteger.prototype.DV = (1 << dbits)

var BI_FP = 52
BigInteger.prototype.FV = Math.pow(2, BI_FP)
BigInteger.prototype.F1 = BI_FP - dbits
BigInteger.prototype.F2 = 2 * dbits - BI_FP

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz"
var BI_RC = new Array()
var rr, vv
rr = "0".charCodeAt(0)
for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv
rr = "a".charCodeAt(0)
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv
rr = "A".charCodeAt(0)
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv

function int2char(n) {
  return BI_RM.charAt(n)
}

function intAt(s, i) {
  var c = BI_RC[s.charCodeAt(i)]
  return (c == null) ? -1 : c
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for (var i = this.t - 1; i >= 0; --i) r[i] = this[i]
  r.t = this.t
  r.s = this.s
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1
  this.s = (x < 0) ? -1 : 0
  if (x > 0) this[0] = x
  else if (x < -1) this[0] = x + DV
  else this.t = 0
}

// return bigint initialized to value
function nbv(i) {
  var r = new BigInteger()
  r.fromInt(i)
  return r
}

// (protected) set from string and radix
function bnpFromString(s, b) {
  var self = this

  var k
  if (b == 16) k = 4
  else if (b == 8) k = 3
  else if (b == 256) k = 8; // byte array
  else if (b == 2) k = 1
  else if (b == 32) k = 5
  else if (b == 4) k = 2
  else {
    self.fromRadix(s, b)
    return
  }
  self.t = 0
  self.s = 0
  var i = s.length,
    mi = false,
    sh = 0
  while (--i >= 0) {
    var x = (k == 8) ? s[i] & 0xff : intAt(s, i)
    if (x < 0) {
      if (s.charAt(i) == "-") mi = true
      continue
    }
    mi = false
    if (sh == 0)
      self[self.t++] = x
    else if (sh + k > self.DB) {
      self[self.t - 1] |= (x & ((1 << (self.DB - sh)) - 1)) << sh
      self[self.t++] = (x >> (self.DB - sh))
    } else
      self[self.t - 1] |= x << sh
    sh += k
    if (sh >= self.DB) sh -= self.DB
  }
  if (k == 8 && (s[0] & 0x80) != 0) {
    self.s = -1
    if (sh > 0) self[self.t - 1] |= ((1 << (self.DB - sh)) - 1) << sh
  }
  self.clamp()
  if (mi) BigInteger.ZERO.subTo(self, self)
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s & this.DM
  while (this.t > 0 && this[this.t - 1] == c)--this.t
}

// (public) return string representation in given radix
function bnToString(b) {
  var self = this
  if (self.s < 0) return "-" + self.negate()
    .toString(b)
  var k
  if (b == 16) k = 4
  else if (b == 8) k = 3
  else if (b == 2) k = 1
  else if (b == 32) k = 5
  else if (b == 4) k = 2
  else return self.toRadix(b)
  var km = (1 << k) - 1,
    d, m = false,
    r = "",
    i = self.t
  var p = self.DB - (i * self.DB) % k
  if (i-- > 0) {
    if (p < self.DB && (d = self[i] >> p) > 0) {
      m = true
      r = int2char(d)
    }
    while (i >= 0) {
      if (p < k) {
        d = (self[i] & ((1 << p) - 1)) << (k - p)
        d |= self[--i] >> (p += self.DB - k)
      } else {
        d = (self[i] >> (p -= k)) & km
        if (p <= 0) {
          p += self.DB
          --i
        }
      }
      if (d > 0) m = true
      if (m) r += int2char(d)
    }
  }
  return m ? r : "0"
}

// (public) -this
function bnNegate() {
  var r = new BigInteger()
  BigInteger.ZERO.subTo(this, r)
  return r
}

// (public) |this|
function bnAbs() {
  return (this.s < 0) ? this.negate() : this
}

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s - a.s
  if (r != 0) return r
  var i = this.t
  r = i - a.t
  if (r != 0) return (this.s < 0) ? -r : r
  while (--i >= 0)
    if ((r = this[i] - a[i]) != 0) return r
  return 0
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1,
    t
  if ((t = x >>> 16) != 0) {
    x = t
    r += 16
  }
  if ((t = x >> 8) != 0) {
    x = t
    r += 8
  }
  if ((t = x >> 4) != 0) {
    x = t
    r += 4
  }
  if ((t = x >> 2) != 0) {
    x = t
    r += 2
  }
  if ((t = x >> 1) != 0) {
    x = t
    r += 1
  }
  return r
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if (this.t <= 0) return 0
  return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM))
}

// (public) return the number of bytes in "this"
function bnByteLength() {
  return this.bitLength() >> 3
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n, r) {
  var i
  for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i]
  for (i = n - 1; i >= 0; --i) r[i] = 0
  r.t = this.t + n
  r.s = this.s
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n, r) {
  for (var i = n; i < this.t; ++i) r[i - n] = this[i]
  r.t = Math.max(this.t - n, 0)
  r.s = this.s
}

// (protected) r = this << n
function bnpLShiftTo(n, r) {
  var self = this
  var bs = n % self.DB
  var cbs = self.DB - bs
  var bm = (1 << cbs) - 1
  var ds = Math.floor(n / self.DB),
    c = (self.s << bs) & self.DM,
    i
  for (i = self.t - 1; i >= 0; --i) {
    r[i + ds + 1] = (self[i] >> cbs) | c
    c = (self[i] & bm) << bs
  }
  for (i = ds - 1; i >= 0; --i) r[i] = 0
  r[ds] = c
  r.t = self.t + ds + 1
  r.s = self.s
  r.clamp()
}

// (protected) r = this >> n
function bnpRShiftTo(n, r) {
  var self = this
  r.s = self.s
  var ds = Math.floor(n / self.DB)
  if (ds >= self.t) {
    r.t = 0
    return
  }
  var bs = n % self.DB
  var cbs = self.DB - bs
  var bm = (1 << bs) - 1
  r[0] = self[ds] >> bs
  for (var i = ds + 1; i < self.t; ++i) {
    r[i - ds - 1] |= (self[i] & bm) << cbs
    r[i - ds] = self[i] >> bs
  }
  if (bs > 0) r[self.t - ds - 1] |= (self.s & bm) << cbs
  r.t = self.t - ds
  r.clamp()
}

// (protected) r = this - a
function bnpSubTo(a, r) {
  var self = this
  var i = 0,
    c = 0,
    m = Math.min(a.t, self.t)
  while (i < m) {
    c += self[i] - a[i]
    r[i++] = c & self.DM
    c >>= self.DB
  }
  if (a.t < self.t) {
    c -= a.s
    while (i < self.t) {
      c += self[i]
      r[i++] = c & self.DM
      c >>= self.DB
    }
    c += self.s
  } else {
    c += self.s
    while (i < a.t) {
      c -= a[i]
      r[i++] = c & self.DM
      c >>= self.DB
    }
    c -= a.s
  }
  r.s = (c < 0) ? -1 : 0
  if (c < -1) r[i++] = self.DV + c
  else if (c > 0) r[i++] = c
  r.t = i
  r.clamp()
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a, r) {
  var x = this.abs(),
    y = a.abs()
  var i = x.t
  r.t = i + y.t
  while (--i >= 0) r[i] = 0
  for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t)
  r.s = 0
  r.clamp()
  if (this.s != a.s) BigInteger.ZERO.subTo(r, r)
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs()
  var i = r.t = 2 * x.t
  while (--i >= 0) r[i] = 0
  for (i = 0; i < x.t - 1; ++i) {
    var c = x.am(i, x[i], r, 2 * i, 0, 1)
    if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
      r[i + x.t] -= x.DV
      r[i + x.t + 1] = 1
    }
  }
  if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1)
  r.s = 0
  r.clamp()
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m, q, r) {
  var self = this
  var pm = m.abs()
  if (pm.t <= 0) return
  var pt = self.abs()
  if (pt.t < pm.t) {
    if (q != null) q.fromInt(0)
    if (r != null) self.copyTo(r)
    return
  }
  if (r == null) r = new BigInteger()
  var y = new BigInteger(),
    ts = self.s,
    ms = m.s
  var nsh = self.DB - nbits(pm[pm.t - 1]); // normalize modulus
  if (nsh > 0) {
    pm.lShiftTo(nsh, y)
    pt.lShiftTo(nsh, r)
  } else {
    pm.copyTo(y)
    pt.copyTo(r)
  }
  var ys = y.t
  var y0 = y[ys - 1]
  if (y0 == 0) return
  var yt = y0 * (1 << self.F1) + ((ys > 1) ? y[ys - 2] >> self.F2 : 0)
  var d1 = self.FV / yt,
    d2 = (1 << self.F1) / yt,
    e = 1 << self.F2
  var i = r.t,
    j = i - ys,
    t = (q == null) ? new BigInteger() : q
  y.dlShiftTo(j, t)
  if (r.compareTo(t) >= 0) {
    r[r.t++] = 1
    r.subTo(t, r)
  }
  BigInteger.ONE.dlShiftTo(ys, t)
  t.subTo(y, y); // "negative" y so we can replace sub with am later
  while (y.t < ys) y[y.t++] = 0
  while (--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i] == y0) ? self.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2)
    if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) { // Try it out
      y.dlShiftTo(j, t)
      r.subTo(t, r)
      while (r[i] < --qd) r.subTo(t, r)
    }
  }
  if (q != null) {
    r.drShiftTo(ys, q)
    if (ts != ms) BigInteger.ZERO.subTo(q, q)
  }
  r.t = ys
  r.clamp()
  if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
  if (ts < 0) BigInteger.ZERO.subTo(r, r)
}

// (public) this mod a
function bnMod(a) {
  var r = new BigInteger()
  this.abs()
    .divRemTo(a, null, r)
  if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r)
  return r
}

// Modular reduction using "classic" algorithm
function Classic(m) {
  this.m = m
}

function cConvert(x) {
  if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m)
  else return x
}

function cRevert(x) {
  return x
}

function cReduce(x) {
  x.divRemTo(this.m, null, x)
}

function cMulTo(x, y, r) {
  x.multiplyTo(y, r)
  this.reduce(r)
}

function cSqrTo(x, r) {
  x.squareTo(r)
  this.reduce(r)
}

Classic.prototype.convert = cConvert
Classic.prototype.revert = cRevert
Classic.prototype.reduce = cReduce
Classic.prototype.mulTo = cMulTo
Classic.prototype.sqrTo = cSqrTo

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if (this.t < 1) return 0
  var x = this[0]
  if ((x & 1) == 0) return 0
  var y = x & 3; // y == 1/x mod 2^2
  y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
  y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
  y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y * (2 - x * y % this.DV)) % this.DV; // y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y > 0) ? this.DV - y : -y
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m
  this.mp = m.invDigit()
  this.mpl = this.mp & 0x7fff
  this.mph = this.mp >> 15
  this.um = (1 << (m.DB - 15)) - 1
  this.mt2 = 2 * m.t
}

// xR mod m
function montConvert(x) {
  var r = new BigInteger()
  x.abs()
    .dlShiftTo(this.m.t, r)
  r.divRemTo(this.m, null, r)
  if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r)
  return r
}

// x/R mod m
function montRevert(x) {
  var r = new BigInteger()
  x.copyTo(r)
  this.reduce(r)
  return r
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while (x.t <= this.mt2) // pad x so am has enough room later
    x[x.t++] = 0
  for (var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i] & 0x7fff
    var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM
    // use am to combine the multiply-shift-add into one call
    j = i + this.m.t
    x[j] += this.m.am(0, u0, x, i, 0, this.m.t)
    // propagate carry
    while (x[j] >= x.DV) {
      x[j] -= x.DV
      x[++j]++
    }
  }
  x.clamp()
  x.drShiftTo(this.m.t, x)
  if (x.compareTo(this.m) >= 0) x.subTo(this.m, x)
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x, r) {
  x.squareTo(r)
  this.reduce(r)
}

// r = "xy/R mod m"; x,y != r
function montMulTo(x, y, r) {
  x.multiplyTo(y, r)
  this.reduce(r)
}

Montgomery.prototype.convert = montConvert
Montgomery.prototype.revert = montRevert
Montgomery.prototype.reduce = montReduce
Montgomery.prototype.mulTo = montMulTo
Montgomery.prototype.sqrTo = montSqrTo

// (protected) true iff this is even
function bnpIsEven() {
  return ((this.t > 0) ? (this[0] & 1) : this.s) == 0
}

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e, z) {
  if (e > 0xffffffff || e < 1) return BigInteger.ONE
  var r = new BigInteger(),
    r2 = new BigInteger(),
    g = z.convert(this),
    i = nbits(e) - 1
  g.copyTo(r)
  while (--i >= 0) {
    z.sqrTo(r, r2)
    if ((e & (1 << i)) > 0) z.mulTo(r2, g, r)
    else {
      var t = r
      r = r2
      r2 = t
    }
  }
  return z.revert(r)
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e, m) {
  var z
  if (e < 256 || m.isEven()) z = new Classic(m)
  else z = new Montgomery(m)
  return this.exp(e, z)
}

// protected
proto.copyTo = bnpCopyTo
proto.fromInt = bnpFromInt
proto.fromString = bnpFromString
proto.clamp = bnpClamp
proto.dlShiftTo = bnpDLShiftTo
proto.drShiftTo = bnpDRShiftTo
proto.lShiftTo = bnpLShiftTo
proto.rShiftTo = bnpRShiftTo
proto.subTo = bnpSubTo
proto.multiplyTo = bnpMultiplyTo
proto.squareTo = bnpSquareTo
proto.divRemTo = bnpDivRemTo
proto.invDigit = bnpInvDigit
proto.isEven = bnpIsEven
proto.exp = bnpExp

// public
//proto.toByteArraySigned = toByteArray
proto.toString = bnToString
proto.negate = bnNegate
proto.abs = bnAbs
proto.compareTo = bnCompareTo
proto.bitLength = bnBitLength
proto.byteLength = bnByteLength
proto.mod = bnMod
proto.modPowInt = bnModPowInt

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

/*****jsbn2.js*****/

/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
// (public)  change start
function bnClone() {
  var r = new BigInteger()
  this.copyTo(r)
  return r
}

// (public) return value as integer
function bnIntValue() {
  if (this.s < 0) {
    if (this.t == 1) return this[0] - this.DV
    else if (this.t == 0) return -1
  } else if (this.t == 1) return this[0]
  else if (this.t == 0) return 0
  // assumes 16 < DB < 32
  return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0]
}

// (public) return value as byte
function bnByteValue() {
  return (this.t == 0) ? this.s : (this[0] << 24) >> 24
}

// (public) return value as short (assumes DB>=16)
function bnShortValue() {
  return (this.t == 0) ? this.s : (this[0] << 16) >> 16
}

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) {
  return Math.floor(Math.LN2 * this.DB / Math.log(r))
}

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if (this.s < 0) return -1
  else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0
  else return 1
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if (b == null) b = 10
  if (this.signum() == 0 || b < 2 || b > 36) return "0"
  var cs = this.chunkSize(b)
  var a = Math.pow(b, cs)
  var d = nbv(a),
    y = new BigInteger(),
    z = new BigInteger(),
    r = ""
  this.divRemTo(d, y, z)
  while (y.signum() > 0) {
    r = (a + z.intValue())
      .toString(b)
      .substr(1) + r
    y.divRemTo(d, y, z)
  }
  return z.intValue()
    .toString(b) + r
}

// (protected) convert from radix string
function bnpFromRadix(s, b) {
  var self = this
  self.fromInt(0)
  if (b == null) b = 10
  var cs = self.chunkSize(b)
  var d = Math.pow(b, cs),
    mi = false,
    j = 0,
    w = 0
  for (var i = 0; i < s.length; ++i) {
    var x = intAt(s, i)
    if (x < 0) {
      if (s.charAt(i) == "-" && self.signum() == 0) mi = true
      continue
    }
    w = b * w + x
    if (++j >= cs) {
      self.dMultiply(d)
      self.dAddOffset(w, 0)
      j = 0
      w = 0
    }
  }
  if (j > 0) {
    self.dMultiply(Math.pow(b, j))
    self.dAddOffset(w, 0)
  }
  if (mi) BigInteger.ZERO.subTo(self, self)
}

// (protected) alternate constructor
function bnpFromNumber(a, b, c) {
  var self = this
  if ("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if (a < 2) self.fromInt(1)
    else {
      self.fromNumber(a, c)
      if (!self.testBit(a - 1)) // force MSB set
        self.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, self)
      if (self.isEven()) self.dAddOffset(1, 0); // force odd
      while (!self.isProbablePrime(b)) {
        self.dAddOffset(2, 0)
        if (self.bitLength() > a) self.subTo(BigInteger.ONE.shiftLeft(a - 1), self)
      }
    }
  } else {
    // new BigInteger(int,RNG)
    var x = new Array(),
      t = a & 7
    x.length = (a >> 3) + 1
    b.nextBytes(x)
    if (t > 0) x[0] &= ((1 << t) - 1)
    else x[0] = 0
    self.fromString(x, 256)
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var self = this
  var i = self.t,
    r = new Array()
  r[0] = self.s
  var p = self.DB - (i * self.DB) % 8,
    d, k = 0
  if (i-- > 0) {
    if (p < self.DB && (d = self[i] >> p) != (self.s & self.DM) >> p)
      r[k++] = d | (self.s << (self.DB - p))
    while (i >= 0) {
      if (p < 8) {
        d = (self[i] & ((1 << p) - 1)) << (8 - p)
        d |= self[--i] >> (p += self.DB - 8)
      } else {
        d = (self[i] >> (p -= 8)) & 0xff
        if (p <= 0) {
          p += self.DB
          --i
        }
      }
      if ((d & 0x80) != 0) d |= -256
      if (k === 0 && (self.s & 0x80) != (d & 0x80))++k
      if (k > 0 || d != self.s) r[k++] = d
    }
  }
  return r
}

// add by wx 
function bnFromByteArray(array){
    if (array == undefined || !Array.isArray(array)) {
        return undefined;
    }
    var Hex = KeyouCryptography.util.Hex;
    return new BigInteger(Hex.stringify(array), 16);
}

//
function bnToByteArrayUnsign(){
    var Hex = KeyouCryptography.util.Hex;
    return Hex.toUnsignBytes(this.toByteArray());
}

function bnEquals(a) {
  return (this.compareTo(a) == 0)
}

function bnMin(a) {
  return (this.compareTo(a) < 0) ? this : a
}

function bnMax(a) {
  return (this.compareTo(a) > 0) ? this : a
}

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a, op, r) {
  var self = this
  var i, f, m = Math.min(a.t, self.t)
  for (i = 0; i < m; ++i) r[i] = op(self[i], a[i])
  if (a.t < self.t) {
    f = a.s & self.DM
    for (i = m; i < self.t; ++i) r[i] = op(self[i], f)
    r.t = self.t
  } else {
    f = self.s & self.DM
    for (i = m; i < a.t; ++i) r[i] = op(f, a[i])
    r.t = a.t
  }
  r.s = op(self.s, a.s)
  r.clamp()
}

// (public) this & a
function op_and(x, y) {
  return x & y
}

function bnAnd(a) {
  var r = new BigInteger()
  this.bitwiseTo(a, op_and, r)
  return r
}

// (public) this | a
function op_or(x, y) {
  return x | y
}

function bnOr(a) {
  var r = new BigInteger()
  this.bitwiseTo(a, op_or, r)
  return r
}

// (public) this ^ a
function op_xor(x, y) {
  return x ^ y
}

function bnXor(a) {
  var r = new BigInteger()
  this.bitwiseTo(a, op_xor, r)
  return r
}

// (public) this & ~a
function op_andnot(x, y) {
  return x & ~y
}

function bnAndNot(a) {
  var r = new BigInteger()
  this.bitwiseTo(a, op_andnot, r)
  return r
}

// (public) ~this
function bnNot() {
  var r = new BigInteger()
  for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i]
  r.t = this.t
  r.s = ~this.s
  return r
}

// (public) this << n
function bnShiftLeft(n) {
  var r = new BigInteger()
  if (n < 0) this.rShiftTo(-n, r)
  else this.lShiftTo(n, r)
  return r
}

// (public) this >> n
function bnShiftRight(n) {
  var r = new BigInteger()
  if (n < 0) this.lShiftTo(-n, r)
  else this.rShiftTo(n, r)
  return r
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if (x == 0) return -1
  var r = 0
  if ((x & 0xffff) == 0) {
    x >>= 16
    r += 16
  }
  if ((x & 0xff) == 0) {
    x >>= 8
    r += 8
  }
  if ((x & 0xf) == 0) {
    x >>= 4
    r += 4
  }
  if ((x & 3) == 0) {
    x >>= 2
    r += 2
  }
  if ((x & 1) == 0)++r
  return r
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for (var i = 0; i < this.t; ++i)
    if (this[i] != 0) return i * this.DB + lbit(this[i])
  if (this.s < 0) return this.t * this.DB
  return -1
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0
  while (x != 0) {
    x &= x - 1
    ++r
  }
  return r
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0,
    x = this.s & this.DM
  for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x)
  return r
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n / this.DB)
  if (j >= this.t) return (this.s != 0)
  return ((this[j] & (1 << (n % this.DB))) != 0)
}

// (protected) this op (1<<n)
function bnpChangeBit(n, op) {
  var r = BigInteger.ONE.shiftLeft(n)
  this.bitwiseTo(r, op, r)
  return r
}

// (public) this | (1<<n)
function bnSetBit(n) {
  return this.changeBit(n, op_or)
}

// (public) this & ~(1<<n)
function bnClearBit(n) {
  return this.changeBit(n, op_andnot)
}

// (public) this ^ (1<<n)
function bnFlipBit(n) {
  return this.changeBit(n, op_xor)
}

// (protected) r = this + a
function bnpAddTo(a, r) {
  var self = this

  var i = 0,
    c = 0,
    m = Math.min(a.t, self.t)
  while (i < m) {
    c += self[i] + a[i]
    r[i++] = c & self.DM
    c >>= self.DB
  }
  if (a.t < self.t) {
    c += a.s
    while (i < self.t) {
      c += self[i]
      r[i++] = c & self.DM
      c >>= self.DB
    }
    c += self.s
  } else {
    c += self.s
    while (i < a.t) {
      c += a[i]
      r[i++] = c & self.DM
      c >>= self.DB
    }
    c += a.s
  }
  r.s = (c < 0) ? -1 : 0
  if (c > 0) r[i++] = c
  else if (c < -1) r[i++] = self.DV + c
  r.t = i
  r.clamp()
}

// (public) this + a
function bnAdd(a) {
  var r = new BigInteger()
  this.addTo(a, r)
  return r
}

// (public) this - a
function bnSubtract(a) {
  var r = new BigInteger()
  this.subTo(a, r)
  return r
}

// (public) this * a
function bnMultiply(a) {
  var r = new BigInteger()
  this.multiplyTo(a, r)
  return r
}

// (public) this^2
function bnSquare() {
  var r = new BigInteger()
  this.squareTo(r)
  return r
}

// (public) this / a
function bnDivide(a) {
  var r = new BigInteger()
  this.divRemTo(a, r, null)
  return r
}

// (public) this % a
function bnRemainder(a) {
  var r = new BigInteger()
  this.divRemTo(a, null, r)
  return r
}

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = new BigInteger(),
    r = new BigInteger()
  this.divRemTo(a, q, r)
  return new Array(q, r)
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0, n - 1, this, 0, 0, this.t)
  ++this.t
  this.clamp()
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n, w) {
  if (n == 0) return
  while (this.t <= w) this[this.t++] = 0
  this[w] += n
  while (this[w] >= this.DV) {
    this[w] -= this.DV
    if (++w >= this.t) this[this.t++] = 0
    ++this[w]
  }
}

// A "null" reducer
function NullExp() {}

function nNop(x) {
  return x
}

function nMulTo(x, y, r) {
  x.multiplyTo(y, r)
}

function nSqrTo(x, r) {
  x.squareTo(r)
}

NullExp.prototype.convert = nNop
NullExp.prototype.revert = nNop
NullExp.prototype.mulTo = nMulTo
NullExp.prototype.sqrTo = nSqrTo

// (public) this^e
function bnPow(e) {
  return this.exp(e, new NullExp())
}

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a, n, r) {
  var i = Math.min(this.t + a.t, n)
  r.s = 0; // assumes a,this >= 0
  r.t = i
  while (i > 0) r[--i] = 0
  var j
  for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t)
  for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i)
  r.clamp()
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a, n, r) {
  --n
  var i = r.t = this.t + a.t - n
  r.s = 0; // assumes a,this >= 0
  while (--i >= 0) r[i] = 0
  for (i = Math.max(n - this.t, 0); i < a.t; ++i)
    r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n)
  r.clamp()
  r.drShiftTo(1, r)
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = new BigInteger()
  this.q3 = new BigInteger()
  BigInteger.ONE.dlShiftTo(2 * m.t, this.r2)
  this.mu = this.r2.divide(m)
  this.m = m
}

function barrettConvert(x) {
  if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m)
  else if (x.compareTo(this.m) < 0) return x
  else {
    var r = new BigInteger()
    x.copyTo(r)
    this.reduce(r)
    return r
  }
}

function barrettRevert(x) {
  return x
}

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  var self = this
  x.drShiftTo(self.m.t - 1, self.r2)
  if (x.t > self.m.t + 1) {
    x.t = self.m.t + 1
    x.clamp()
  }
  self.mu.multiplyUpperTo(self.r2, self.m.t + 1, self.q3)
  self.m.multiplyLowerTo(self.q3, self.m.t + 1, self.r2)
  while (x.compareTo(self.r2) < 0) x.dAddOffset(1, self.m.t + 1)
  x.subTo(self.r2, x)
  while (x.compareTo(self.m) >= 0) x.subTo(self.m, x)
}

// r = x^2 mod m; x != r
function barrettSqrTo(x, r) {
  x.squareTo(r)
  this.reduce(r)
}

// r = x*y mod m; x,y != r
function barrettMulTo(x, y, r) {
  x.multiplyTo(y, r)
  this.reduce(r)
}

Barrett.prototype.convert = barrettConvert
Barrett.prototype.revert = barrettRevert
Barrett.prototype.reduce = barrettReduce
Barrett.prototype.mulTo = barrettMulTo
Barrett.prototype.sqrTo = barrettSqrTo

// (public) this^e % m (HAC 14.85)
function bnModPow(e, m) {
  var i = e.bitLength(),
    k, r = nbv(1),
    z
  if (i <= 0) return r
  else if (i < 18) k = 1
  else if (i < 48) k = 3
  else if (i < 144) k = 4
  else if (i < 768) k = 5
  else k = 6
  if (i < 8)
    z = new Classic(m)
  else if (m.isEven())
    z = new Barrett(m)
  else
    z = new Montgomery(m)

  // precomputation
  var g = new Array(),
    n = 3,
    k1 = k - 1,
    km = (1 << k) - 1
  g[1] = z.convert(this)
  if (k > 1) {
    var g2 = new BigInteger()
    z.sqrTo(g[1], g2)
    while (n <= km) {
      g[n] = new BigInteger()
      z.mulTo(g2, g[n - 2], g[n])
      n += 2
    }
  }

  var j = e.t - 1,
    w, is1 = true,
    r2 = new BigInteger(),
    t
  i = nbits(e[j]) - 1
  while (j >= 0) {
    if (i >= k1) w = (e[j] >> (i - k1)) & km
    else {
      w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i)
      if (j > 0) w |= e[j - 1] >> (this.DB + i - k1)
    }

    n = k
    while ((w & 1) == 0) {
      w >>= 1
      --n
    }
    if ((i -= n) < 0) {
      i += this.DB
      --j
    }
    if (is1) { // ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r)
      is1 = false
    } else {
      while (n > 1) {
        z.sqrTo(r, r2)
        z.sqrTo(r2, r)
        n -= 2
      }
      if (n > 0) z.sqrTo(r, r2)
      else {
        t = r
        r = r2
        r2 = t
      }
      z.mulTo(r2, g[w], r)
    }

    while (j >= 0 && (e[j] & (1 << i)) == 0) {
      z.sqrTo(r, r2)
      t = r
      r = r2
      r2 = t
      if (--i < 0) {
        i = this.DB - 1
        --j
      }
    }
  }
  return z.revert(r)
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s < 0) ? this.negate() : this.clone()
  var y = (a.s < 0) ? a.negate() : a.clone()
  if (x.compareTo(y) < 0) {
    var t = x
    x = y
    y = t
  }
  var i = x.getLowestSetBit(),
    g = y.getLowestSetBit()
  if (g < 0) return x
  if (i < g) g = i
  if (g > 0) {
    x.rShiftTo(g, x)
    y.rShiftTo(g, y)
  }
  while (x.signum() > 0) {
    if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x)
    if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y)
    if (x.compareTo(y) >= 0) {
      x.subTo(y, x)
      x.rShiftTo(1, x)
    } else {
      y.subTo(x, y)
      y.rShiftTo(1, y)
    }
  }
  if (g > 0) y.lShiftTo(g, y)
  return y
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if (n <= 0) return 0
  var d = this.DV % n,
    r = (this.s < 0) ? n - 1 : 0
  if (this.t > 0)
    if (d == 0) r = this[0] % n
    else
      for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n
  return r
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven()
  if (this.signum() === 0) throw new Error('division by zero')
  if ((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO
  var u = m.clone(),
    v = this.clone()
  var a = nbv(1),
    b = nbv(0),
    c = nbv(0),
    d = nbv(1)
  while (u.signum() != 0) {
    while (u.isEven()) {
      u.rShiftTo(1, u)
      if (ac) {
        if (!a.isEven() || !b.isEven()) {
          a.addTo(this, a)
          b.subTo(m, b)
        }
        a.rShiftTo(1, a)
      } else if (!b.isEven()) b.subTo(m, b)
      b.rShiftTo(1, b)
    }
    while (v.isEven()) {
      v.rShiftTo(1, v)
      if (ac) {
        if (!c.isEven() || !d.isEven()) {
          c.addTo(this, c)
          d.subTo(m, d)
        }
        c.rShiftTo(1, c)
      } else if (!d.isEven()) d.subTo(m, d)
      d.rShiftTo(1, d)
    }
    if (u.compareTo(v) >= 0) {
      u.subTo(v, u)
      if (ac) a.subTo(c, a)
      b.subTo(d, b)
    } else {
      v.subTo(u, v)
      if (ac) c.subTo(a, c)
      d.subTo(b, d)
    }
  }
  if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO
  while (d.compareTo(m) >= 0) d.subTo(m, d)
  while (d.signum() < 0) d.addTo(m, d)
  return d
}

var lowprimes = [
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
  73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
  239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
  421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
  613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
  821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
]

var lplim = (1 << 26) / lowprimes[lowprimes.length - 1]

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs()
  if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
    for (i = 0; i < lowprimes.length; ++i)
      if (x[0] == lowprimes[i]) return true
    return false
  }
  if (x.isEven()) return false
  i = 1
  while (i < lowprimes.length) {
    var m = lowprimes[i],
      j = i + 1
    while (j < lowprimes.length && m < lplim) m *= lowprimes[j++]
    m = x.modInt(m)
    while (i < j) if (m % lowprimes[i++] == 0) return false
  }
  return x.millerRabin(t)
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE)
  var k = n1.getLowestSetBit()
  if (k <= 0) return false
  var r = n1.shiftRight(k)
  t = (t + 1) >> 1
  if (t > lowprimes.length) t = lowprimes.length
  var a = new BigInteger(null)
  var j, bases = []
  for (var i = 0; i < t; ++i) {
    for (;;) {
      j = lowprimes[Math.floor(Math.random() * lowprimes.length)]
      if (bases.indexOf(j) == -1) break
    }
    bases.push(j)
    a.fromInt(j)
    var y = a.modPow(r, this)
    if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1
      while (j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2, this)
        if (y.compareTo(BigInteger.ONE) == 0) return false
      }
      if (y.compareTo(n1) != 0) return false
    }
  }
  return true
}

// protected
proto.chunkSize = bnpChunkSize
proto.toRadix = bnpToRadix
proto.fromRadix = bnpFromRadix
proto.fromNumber = bnpFromNumber
proto.bitwiseTo = bnpBitwiseTo
proto.changeBit = bnpChangeBit
proto.addTo = bnpAddTo
proto.dMultiply = bnpDMultiply
proto.dAddOffset = bnpDAddOffset
proto.multiplyLowerTo = bnpMultiplyLowerTo
proto.multiplyUpperTo = bnpMultiplyUpperTo
proto.modInt = bnpModInt
proto.millerRabin = bnpMillerRabin

// public
proto.clone = bnClone
proto.intValue = bnIntValue
proto.byteValue = bnByteValue
proto.shortValue = bnShortValue
proto.signum = bnSigNum
proto.toByteArray = bnToByteArray

//add  by wx
proto.toByteArraySigned = bnToByteArrayUnsign
BigInteger.fromByteArrayUnsigned = bnFromByteArray

proto.equals = bnEquals
proto.min = bnMin
proto.max = bnMax
proto.and = bnAnd
proto.or = bnOr
proto.xor = bnXor
proto.andNot = bnAndNot
proto.not = bnNot
proto.shiftLeft = bnShiftLeft
proto.shiftRight = bnShiftRight
proto.getLowestSetBit = bnGetLowestSetBit
proto.bitCount = bnBitCount
proto.testBit = bnTestBit
proto.setBit = bnSetBit
proto.clearBit = bnClearBit
proto.flipBit = bnFlipBit
proto.add = bnAdd
proto.subtract = bnSubtract
proto.multiply = bnMultiply
proto.divide = bnDivide
proto.remainder = bnRemainder
proto.divideAndRemainder = bnDivideAndRemainder
proto.modPow = bnModPow
proto.modInverse = bnModInverse
proto.pow = bnPow
proto.gcd = bnGCD
proto.isProbablePrime = bnIsProbablePrime

// JSBN-specific extension
proto.square = bnSquare

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)

/*****prng4.js*****/

/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
  this.i = 0;
  this.j = 0;
  this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
  var i, j, t;
  for(i = 0; i < 256; ++i)
    this.S[i] = i;
  j = 0;
  for(i = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  this.i = 0;
  this.j = 0;
}

function ARC4next() {
  var t;
  this.i = (this.i + 1) & 255;
  this.j = (this.j + this.S[this.i]) & 255;
  t = this.S[this.i];
  this.S[this.i] = this.S[this.j];
  this.S[this.j] = t;
  return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
  return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;

/*****rng.js*****/

/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

var rng_state;
var rng_pool;
var rng_pptr;

// Mix in a 32-bit integer into the pool
function rng_seed_int(x) {
  rng_pool[rng_pptr++] ^= x & 255;
  rng_pool[rng_pptr++] ^= (x >> 8) & 255;
  rng_pool[rng_pptr++] ^= (x >> 16) & 255;
  rng_pool[rng_pptr++] ^= (x >> 24) & 255;
  if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

// Mix in the current time (w/milliseconds) into the pool
function rng_seed_time() {
  rng_seed_int(new Date().getTime());
}

// Initialize the pool with junk if needed.
if(rng_pool == null) {
  rng_pool = new Array(32);
  rng_pptr = 0;
  var t;
  for(t = 0; t < 32; ++t)
    {
        rng_pool[rng_pptr++] =  Math.random(10) & 255;
    }   
      
  while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
    t = Math.floor(65536 * Math.random());
    rng_pool[rng_pptr++] = t >>> 8;
    rng_pool[rng_pptr++] = t & 255;
  }
  rng_pptr = 0;
  rng_seed_time();
  //rng_seed_int(window.screenX);
  //rng_seed_int(window.screenY);
}

function rng_get_byte() {
  if(rng_state == null) {
    rng_seed_time();
    rng_state = prng_newstate();
    rng_state.init(rng_pool);
    for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
      rng_pool[rng_pptr] = 0;
    rng_pptr = 0;
    //rng_pool = null;
  }
  // TODO: allow reseeding after first request
  return rng_state.next();
  //return 0x01; //modify for test
}

function rng_get_bytes(ba) {
  var i;
  for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;

/*****crypto-1.1.js*****/

/*! crypto-1.1.5.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * crypto.js - Cryptographic Algorithm Provider class
 *
 * Copyright (c) 2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name crypto-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.1.5 (2013-Oct-06)
 * @since jsrsasign 2.2
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

/** 
 * kjur's class library name space
 * @name KJUR
 * @namespace kjur's class library name space
 */
if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
/**
 * kjur's cryptographic algorithm provider library name space
 * <p>
 * This namespace privides following crytpgrahic classes.
 * <ul>
 * <li>{@link KJUR.crypto.MessageDigest} - Java JCE(cryptograhic extension) style MessageDigest class</li>
 * <li>{@link KJUR.crypto.Signature} - Java JCE(cryptograhic extension) style Signature class</li>
 * <li>{@link KJUR.crypto.Util} - cryptographic utility functions and properties</li>
 * </ul>
 * NOTE: Please ignore method summary and document of this namespace. This caused by a bug of jsdoc2.
 * </p>
 * @name KJUR.crypto
 * @namespace
 */
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.Util
 * @class static object for cryptographic function utilities
 * @property {Array} DIGESTINFOHEAD PKCS#1 DigestInfo heading hexadecimal bytes for each hash algorithms
 * @property {Array} DEFAULTPROVIDER associative array of default provider name for each hash and signature algorithms
 * @description
 */
KJUR.crypto.Util = new function() {
    this.DIGESTINFOHEAD = {
	'sha1':      "3021300906052b0e03021a05000414",
        'sha224':    "302d300d06096086480165030402040500041c",
	'sha256':    "3031300d060960864801650304020105000420",
	'sha384':    "3041300d060960864801650304020205000430",
	'sha512':    "3051300d060960864801650304020305000440",
	'md2':       "3020300c06082a864886f70d020205000410",
	'md5':       "3020300c06082a864886f70d020505000410",
	'ripemd160': "3021300906052b2403020105000414"
    };

    /*
     * @since crypto 1.1.1
     */
    this.DEFAULTPROVIDER = {
	'md5':			'cryptojs',
	'sha1':			'cryptojs',
	'sha224':		'cryptojs',
	'sha256':		'cryptojs',
	'sha384':		'cryptojs',
	'sha512':		'cryptojs',
	'ripemd160':		'cryptojs',
	'hmacmd5':		'cryptojs',
	'hmacsha1':		'cryptojs',
	'hmacsha224':		'cryptojs',
	'hmacsha256':		'cryptojs',
	'hmacsha384':		'cryptojs',
	'hmacsha512':		'cryptojs',
	'hmacripemd160':	'cryptojs',
	'sm3':	            'cryptojs',

	'MD5withRSA':		'cryptojs/jsrsa',
	'SHA1withRSA':		'cryptojs/jsrsa',
	'SHA224withRSA':	'cryptojs/jsrsa',
	'SHA256withRSA':	'cryptojs/jsrsa',
	'SHA384withRSA':	'cryptojs/jsrsa',
	'SHA512withRSA':	'cryptojs/jsrsa',
	'RIPEMD160withRSA':	'cryptojs/jsrsa',

	'MD5withECDSA':		'cryptojs/jsrsa',
	'SHA1withECDSA':	'cryptojs/jsrsa',
	'SHA224withECDSA':	'cryptojs/jsrsa',
	'SHA256withECDSA':	'cryptojs/jsrsa',
	'SHA384withECDSA':	'cryptojs/jsrsa',
	'SHA512withECDSA':	'cryptojs/jsrsa',
	'RIPEMD160withECDSA':	'cryptojs/jsrsa',

	'SHA1withDSA':		'cryptojs/jsrsa',
	'SHA224withDSA':	'cryptojs/jsrsa',
	'SHA256withDSA':	'cryptojs/jsrsa',

	'MD5withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA1withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA224withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA256withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA384withRSAandMGF1':		'cryptojs/jsrsa',
	'SHA512withRSAandMGF1':		'cryptojs/jsrsa',
	'RIPEMD160withRSAandMGF1':	'cryptojs/jsrsa'
    };

    /*
     * @since crypto 1.1.2
     */
    this.CRYPTOJSMESSAGEDIGESTNAME = {
	'md5':		'CryptoJS.algo.MD5',
	'sha1':		'CryptoJS.algo.SHA1',
	'sha224':	'CryptoJS.algo.SHA224',
	'sha256':	'CryptoJS.algo.SHA256',
	'sha384':	'CryptoJS.algo.SHA384',
	'sha512':	'CryptoJS.algo.SHA512',
	'ripemd160':'CryptoJS.algo.RIPEMD160',
	'sm3':      'CryptoJS.algo.SM3'
    };

    /**
     * get hexadecimal DigestInfo
     * @name getDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @return {String} hexadecimal string DigestInfo ASN.1 structure
     */
    this.getDigestInfoHex = function(hHash, alg) {
	if (typeof this.DIGESTINFOHEAD[alg] == "undefined")
	    throw "alg not supported in Util.DIGESTINFOHEAD: " + alg;
	return this.DIGESTINFOHEAD[alg] + hHash;
    };

    /**
     * get PKCS#1 padded hexadecimal DigestInfo
     * @name getPaddedDigestInfoHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} hHash hexadecimal hash value of message to be signed
     * @param {String} alg hash algorithm name (ex. 'sha1')
     * @param {Integer} keySize key bit length (ex. 1024)
     * @return {String} hexadecimal string of PKCS#1 padded DigestInfo
     */
    this.getPaddedDigestInfoHex = function(hHash, alg, keySize) {
	var hDigestInfo = this.getDigestInfoHex(hHash, alg);
	var pmStrLen = keySize / 4; // minimum PM length

	if (hDigestInfo.length + 22 > pmStrLen) // len(0001+ff(*8)+00+hDigestInfo)=22
	    throw "key is too short for SigAlg: keylen=" + keySize + "," + alg;

	var hHead = "0001";
	var hTail = "00" + hDigestInfo;
	var hMid = "";
	var fLen = pmStrLen - hHead.length - hTail.length;
	for (var i = 0; i < fLen; i += 2) {
	    hMid += "ff";
	}
	var hPaddedMessage = hHead + hMid + hTail;
	return hPaddedMessage;
    };

    /**
     * get hexadecimal hash of string with specified algorithm
     * @name hashString
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @param {String} alg hash algorithm name
     * @return {String} hexadecimal string of hash value
     * @since 1.1.1
     */
    this.hashString = function(s, alg) {
        var md = new KJUR.crypto.MessageDigest({'alg': alg});
        return md.digestString(s);
    };

    /**
     * get hexadecimal hash of hexadecimal string with specified algorithm
     * @name hashHex
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} sHex input hexadecimal string to be hashed
     * @param {String} alg hash algorithm name
     * @return {String} hexadecimal string of hash value
     * @since 1.1.1
     */
    this.hashHex = function(sHex, alg) {
        var md = new KJUR.crypto.MessageDigest({'alg': alg});
        return md.digestHex(sHex);
    };

    /**
     * get hexadecimal SHA1 hash of string
     * @name sha1
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha1 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha1', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal SHA256 hash of string
     * @name sha256
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha256 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    this.sha256Hex = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha256', 'prov':'cryptojs'});
        return md.digestHex(s);
    };

    /**
     * get hexadecimal SHA512 hash of string
     * @name sha512
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.sha512 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    this.sha512Hex = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'sha512', 'prov':'cryptojs'});
        return md.digestHex(s);
    };

    /**
     * get hexadecimal MD5 hash of string
     * @name md5
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.md5 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'md5', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /**
     * get hexadecimal RIPEMD160 hash of string
     * @name ripemd160
     * @memberOf KJUR.crypto.Util
     * @function
     * @param {String} s input string to be hashed
     * @return {String} hexadecimal string of hash value
     * @since 1.0.3
     */
    this.ripemd160 = function(s) {
        var md = new KJUR.crypto.MessageDigest({'alg':'ripemd160', 'prov':'cryptojs'});
        return md.digestString(s);
    };

    /*
     * @since 1.1.2
     */
    this.getCryptoJSMDByName = function(s) {
	
    };
};

/**
 * MessageDigest class which is very similar to java.security.MessageDigest class
 * @name KJUR.crypto.MessageDigest
 * @class MessageDigest class which is very similar to java.security.MessageDigest class
 * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>md5 - cryptojs</li>
 * <li>sha1 - cryptojs</li>
 * <li>sha224 - cryptojs</li>
 * <li>sha256 - cryptojs</li>
 * <li>sha384 - cryptojs</li>
 * <li>sha512 - cryptojs</li>
 * <li>ripemd160 - cryptojs</li>
 * <li>sha256 - sjcl (NEW from crypto.js 1.0.4)</li>
 * </ul>
 * @example
 * // CryptoJS provider sample
 * &lt;script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/core.js"&gt;&lt;/script&gt;
 * &lt;script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/sha1.js"&gt;&lt;/script&gt;
 * &lt;script src="crypto-1.0.js"&gt;&lt;/script&gt;
 * var md = new KJUR.crypto.MessageDigest({alg: "sha1", prov: "cryptojs"});
 * md.updateString('aaa')
 * var mdHex = md.digest()
 *
 * // SJCL(Stanford JavaScript Crypto Library) provider sample
 * &lt;script src="http://bitwiseshiftleft.github.io/sjcl/sjcl.js"&gt;&lt;/script&gt;
 * &lt;script src="crypto-1.0.js"&gt;&lt;/script&gt;
 * var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "sjcl"}); // sjcl supports sha256 only
 * md.updateString('aaa')
 * var mdHex = md.digest()
 */
KJUR.crypto.MessageDigest = function(params) {
    var md = null;
    var algName = null;
    var provName = null;

    /**
     * set hash algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} alg hash algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * // for SHA1
     * md.setAlgAndProvider('sha1', 'cryptojs');
     * // for RIPEMD160
     * md.setAlgAndProvider('ripemd160', 'cryptojs');
     */
    this.setAlgAndProvider = function(alg, prov) {
	if (alg != null && prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];

	// for cryptojs
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:sm3:'.indexOf(alg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		this.md = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[alg].create();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.md.update(wHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
	if (':sha256:'.indexOf(alg) != -1 &&
	    prov == 'sjcl') {
	    try {
		this.md = new sjcl.hash.sha256();
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" + alg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.md.update(str);
	    };
	    this.updateHex = function(hex) {
		var baHex = sjcl.codec.hex.toBits(hex);
		this.md.update(baHex);
	    };
	    this.digest = function() {
		var hash = this.md.finalize();
		return sjcl.codec.hex.fromBits(hash);
	    };
	    this.digestString = function(str) {
		this.updateString(str);
		return this.digest();
	    };
	    this.digestHex = function(hex) {
		this.updateHex(hex);
		return this.digest();
	    };
	}
    };

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * completes hash calculation and returns hash result
     * @name digest
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.digest = function() {
	throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name digestString
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.digestString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    /**
     * performs final update on the digest using hexadecimal string, then completes the digest computation
     * @name digestHex
     * @memberOf KJUR.crypto.MessageDigest
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
    this.digestHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName;
    };

    if (params !== undefined) {
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined)
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    this.setAlgAndProvider(this.algName, this.provName);
	}
    }
};

/**
 * Mac(Message Authentication Code) class which is very similar to java.security.Mac class 
 * @name KJUR.crypto.Mac
 * @class Mac class which is very similar to java.security.Mac class
 * @param {Array} params parameters for constructor
 * @description
 * <br/>
 * Currently this supports following algorithm and providers combination:
 * <ul>
 * <li>hmacmd5 - cryptojs</li>
 * <li>hmacsha1 - cryptojs</li>
 * <li>hmacsha224 - cryptojs</li>
 * <li>hmacsha256 - cryptojs</li>
 * <li>hmacsha384 - cryptojs</li>
 * <li>hmacsha512 - cryptojs</li>
 * </ul>
 * NOTE: HmacSHA224 and HmacSHA384 issue was fixed since jsrsasign 4.1.4.
 * Please use 'ext/cryptojs-312-core-fix*.js' instead of 'core.js' of original CryptoJS
 * to avoid those issue.
 * @example
 * var mac = new KJUR.crypto.Mac({alg: "HmacSHA1", prov: "cryptojs", "pass": "pass"});
 * mac.updateString('aaa')
 * var macHex = md.doFinal()
 */
KJUR.crypto.Mac = function(params) {
    var mac = null;
    var pass = null;
    var algName = null;
    var provName = null;
    var algProv = null;

    this.setAlgAndProvider = function(alg, prov) {
	if (alg == null) alg = "hmacsha1";

	alg = alg.toLowerCase();
        if (alg.substr(0, 4) != "hmac") {
	    throw "setAlgAndProvider unsupported HMAC alg: " + alg;
	}

	if (prov === undefined) prov = KJUR.crypto.Util.DEFAULTPROVIDER[alg];
	this.algProv = alg + "/" + prov;

	var hashAlg = alg.substr(4);

	// for cryptojs
	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:'.indexOf(hashAlg) != -1 &&
	    prov == 'cryptojs') {
	    try {
		var mdObj = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[hashAlg];
		this.mac = CryptoJS.algo.HMAC.create(mdObj, this.pass);
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail hashAlg=" + hashAlg + "/" + ex;
	    }
	    this.updateString = function(str) {
		this.mac.update(str);
	    };
	    this.updateHex = function(hex) {
		var wHex = CryptoJS.enc.Hex.parse(hex);
		this.mac.update(wHex);
	    };
	    this.doFinal = function() {
		var hash = this.mac.finalize();
		return hash.toString(CryptoJS.enc.Hex);
	    };
	    this.doFinalString = function(str) {
		this.updateString(str);
		return this.doFinal();
	    };
	    this.doFinalHex = function(hex) {
		this.updateHex(hex);
		return this.doFinal();
	    };
	}
    };

    /**
     * update digest by specified string
     * @name updateString
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} str string to update
     * @description
     * @example
     * md.updateString('New York');
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * update digest by specified hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} hex hexadecimal string to update
     * @description
     * @example
     * md.updateHex('0afe36');
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * completes hash calculation and returns hash result
     * @name doFinal
     * @memberOf KJUR.crypto.Mac
     * @function
     * @description
     * @example
     * md.digest()
     */
    this.doFinal = function() {
	throw "digest() not supported for this alg/prov: " + this.algProv;
    };

    /**
     * performs final update on the digest using string, then completes the digest computation
     * @name doFinalString
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} str string to final update
     * @description
     * @example
     * md.digestString('aaa')
     */
    this.doFinalString = function(str) {
	throw "digestString(str) not supported for this alg/prov: " + this.algProv;
    };

    /**
     * performs final update on the digest using hexadecimal string, 
     * then completes the digest computation
     * @name doFinalHex
     * @memberOf KJUR.crypto.Mac
     * @function
     * @param {String} hex hexadecimal string to final update
     * @description
     * @example
     * md.digestHex('0f2abd')
     */
    this.doFinalHex = function(hex) {
	throw "digestHex(hex) not supported for this alg/prov: " + this.algProv;
    };

    if (params !== undefined) {
	if (params['pass'] !== undefined) {
	    this.pass = params['pass'];
	}
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined)
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    this.setAlgAndProvider(this.algName, this.provName);
	}
    }
};

/**
 * Signature class which is very similar to java.security.Signature class
 * @name KJUR.crypto.Signature
 * @class Signature class which is very similar to java.security.Signature class
 * @param {Array} params parameters for constructor
 * @property {String} state Current state of this signature object whether 'SIGN', 'VERIFY' or null
 * @description
 * <br/>
 * As for params of constructor's argument, it can be specify following attributes:
 * <ul>
 * <li>alg - signature algorithm name (ex. {MD5,SHA1,SHA224,SHA256,SHA384,SHA512,RIPEMD160}with{RSA,ECDSA,DSA})</li>
 * <li>provider - currently 'cryptojs/jsrsa' only</li>
 * </ul>
 * <h4>SUPPORTED ALGORITHMS AND PROVIDERS</h4>
 * This Signature class supports following signature algorithm and provider names:
 * <ul>
 * <li>MD5withRSA - cryptojs/jsrsa</li>
 * <li>SHA1withRSA - cryptojs/jsrsa</li>
 * <li>SHA224withRSA - cryptojs/jsrsa</li>
 * <li>SHA256withRSA - cryptojs/jsrsa</li>
 * <li>SHA384withRSA - cryptojs/jsrsa</li>
 * <li>SHA512withRSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSA - cryptojs/jsrsa</li>
 * <li>MD5withECDSA - cryptojs/jsrsa</li>
 * <li>SHA1withECDSA - cryptojs/jsrsa</li>
 * <li>SHA224withECDSA - cryptojs/jsrsa</li>
 * <li>SHA256withECDSA - cryptojs/jsrsa</li>
 * <li>SHA384withECDSA - cryptojs/jsrsa</li>
 * <li>SHA512withECDSA - cryptojs/jsrsa</li>
 * <li>RIPEMD160withECDSA - cryptojs/jsrsa</li>
 * <li>MD5withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA224withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA256withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA384withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA512withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>RIPEMD160withRSAandMGF1 - cryptojs/jsrsa</li>
 * <li>SHA1withDSA - cryptojs/jsrsa</li>
 * <li>SHA224withDSA - cryptojs/jsrsa</li>
 * <li>SHA256withDSA - cryptojs/jsrsa</li>
 * </ul>
 * Here are supported elliptic cryptographic curve names and their aliases for ECDSA:
 * <ul>
 * <li>secp256k1</li>
 * <li>secp256r1, NIST P-256, P-256, prime256v1</li>
 * <li>secp384r1, NIST P-384, P-384</li>
 * </ul>
 * NOTE1: DSA signing algorithm is also supported since crypto 1.1.5.
 * <h4>EXAMPLES</h4>
 * @example
 * // RSA signature generation
 * var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * var hSigVal = sig.sign();
 *
 * // DSA signature validation
 * var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withDSA"});
 * sig2.init(certPEM);
 * sig.updateString('aaa');
 * var isValid = sig2.verify(hSigVal);
 * 
 * // ECDSA signing
 * var sig = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(prvKeyPEM);
 * sig.updateString('aaa');
 * var sigValueHex = sig.sign();
 *
 * // ECDSA verifying
 * var sig2 = new KJUR.crypto.Signature({'alg':'SHA1withECDSA'});
 * sig.init(certPEM);
 * sig.updateString('aaa');
 * var isValid = sig.verify(sigValueHex);
 */
KJUR.crypto.Signature = function(params) {
    var prvKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for signing
    var pubKey = null; // RSAKey/KJUR.crypto.{ECDSA,DSA} object for verifying

    var md = null; // KJUR.crypto.MessageDigest object
    var sig = null;
    var algName = null;
    var provName = null;
    var algProvName = null;
    var mdAlgName = null;
    var pubkeyAlgName = null;	// rsa,ecdsa,rsaandmgf1(=rsapss)
    var state = null;
    var pssSaltLen = -1;
    var initParams = null;

    var sHashHex = null; // hex hash value for hex
    var hDigestInfo = null;
    var hPaddedDigestInfo = null;
    var hSign = null;

    this._setAlgNames = function() {
	if (this.algName.match(/^(.+)with(.+)$/)) {
	    this.mdAlgName = RegExp.$1.toLowerCase();
	    this.pubkeyAlgName = RegExp.$2.toLowerCase();
	}
    };

    this._zeroPaddingOfSignature = function(hex, bitLength) {
	var s = "";
	var nZero = bitLength / 4 - hex.length;
	for (var i = 0; i < nZero; i++) {
	    s = s + "0";
	}
	return s + hex;
    };

    /**
     * set signature algorithm and provider
     * @name setAlgAndProvider
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} alg signature algorithm name
     * @param {String} prov provider name
     * @description
     * @example
     * md.setAlgAndProvider('SHA1withRSA', 'cryptojs/jsrsa');
     */
    this.setAlgAndProvider = function(alg, prov) {
	this._setAlgNames();
	if (prov != 'cryptojs/jsrsa')
	    throw "provider not supported: " + prov;

	if (':md5:sha1:sha224:sha256:sha384:sha512:ripemd160:sm3:'.indexOf(this.mdAlgName) != -1) {
	    try {
		this.md = new KJUR.crypto.MessageDigest({'alg':this.mdAlgName});
	    } catch (ex) {
		throw "setAlgAndProvider hash alg set fail alg=" +
                      this.mdAlgName + "/" + ex;
	    }

	    this.init = function(keyparam, pass) {
		var keyObj = null;
		try {
		    if (pass === undefined) {
			keyObj = KEYUTIL.getKey(keyparam);
		    } else {
			keyObj = KEYUTIL.getKey(keyparam, pass);
		    }
		} catch (ex) {
		    throw "init failed:" + ex;
		}

		if (keyObj.isPrivate === true) {
		    this.prvKey = keyObj;
		    this.state = "SIGN";
		} else if (keyObj.isPublic === true) {
		    this.pubKey = keyObj;
		    this.state = "VERIFY";
		} else {
		    throw "init failed.:" + keyObj;
		}
	    };

	    this.initSign = function(params) {
		if (typeof params['ecprvhex'] == 'string' &&
                    typeof params['eccurvename'] == 'string') {
		    this.ecprvhex = params['ecprvhex'];
		    this.eccurvename = params['eccurvename'];
		} else {
		    this.prvKey = params;
		}
		this.state = "SIGN";
	    };

	    this.initVerifyByPublicKey = function(params) {
		if (typeof params['ecpubhex'] == 'string' &&
		    typeof params['eccurvename'] == 'string') {
		    this.ecpubhex = params['ecpubhex'];
		    this.eccurvename = params['eccurvename'];
		} else if (params instanceof KJUR.crypto.ECDSA) {
		    this.pubKey = params;
		} else if (params instanceof RSAKey) {
		    this.pubKey = params;
		}
		this.state = "VERIFY";
	    };

	    this.initVerifyByCertificatePEM = function(certPEM) {
		var x509 = new X509();
		x509.readCertPEM(certPEM);
		this.pubKey = x509.subjectPublicKeyRSA;
		this.state = "VERIFY";
	    };

	    this.updateString = function(str) {
		this.md.updateString(str);
	    };
	    this.updateHex = function(hex) {
		this.md.updateHex(hex);
	    };

	    this.sign = function() {
	    
	    if(this.eccurvename != "sm2") {
		    this.sHashHex = this.md.digest();
		}
		
		if (typeof this.ecprvhex != "undefined" &&
		    typeof this.eccurvename != "undefined") {
			if(this.eccurvename == "sm2")
			{
				var ec = new KJUR.crypto.SM3withSM2({curve: this.eccurvename});
				
				var G = ec.ecparams['G'];
				var Q = G.multiply(new BigInteger(this.ecprvhex, 16));
				
				var pubKeyHex = Q.getX().toBigInteger().toRadix(16) + Q.getY().toBigInteger().toRadix(16);
				
				var smDigest = new SM3Digest();
				
				var z = new SM3Digest().GetZ(G, pubKeyHex);
				var zValue = smDigest.GetWords(smDigest.GetHex(z).toString());
				
				var rawData = CryptoJS.enc.Utf8.stringify(this.md.md._data);
				rawData = CryptoJS.enc.Utf8.parse(rawData).toString();
				rawData = smDigest.GetWords(rawData);
								
                var smHash = new Array(smDigest.GetDigestSize());
                smDigest.BlockUpdate(zValue, 0, zValue.length);
                smDigest.BlockUpdate(rawData, 0, rawData.length);
                smDigest.DoFinal(smHash, 0);

                var hashHex = smDigest.GetHex(smHash).toString();
				
				this.sHashHex = hashHex;
				
		    	this.hSign = ec.signHex(this.sHashHex, this.ecprvhex);
			}else {
		    	var ec = new KJUR.crypto.ECDSA({'curve': this.eccurvename});
		    	this.hSign = ec.signHex(this.sHashHex, this.ecprvhex);
			}
		} else if (this.pubkeyAlgName == "rsaandmgf1") {
		    this.hSign = this.prvKey.signWithMessageHashPSS(this.sHashHex,
								    this.mdAlgName,
								    this.pssSaltLen);
		} else if (this.pubkeyAlgName == "rsa") {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex,
								 this.mdAlgName);
		} else if (this.prvKey instanceof KJUR.crypto.ECDSA) {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else if (this.prvKey instanceof KJUR.crypto.DSA) {
		    this.hSign = this.prvKey.signWithMessageHash(this.sHashHex);
		} else {
		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
		return this.hSign;
	    };
	    this.signString = function(str) {
		this.updateString(str);
		this.sign();
	    };
	    this.signHex = function(hex) {
		this.updateHex(hex);
		this.sign();
	    };
	    this.verify = function(hSigVal) {
	    
	    if(this.eccurvename != "sm2") {
	        this.sHashHex = this.md.digest();
	    }
	    
		if (typeof this.ecpubhex != "undefined" &&
		    typeof this.eccurvename != "undefined") {
			if(this.eccurvename == "sm2")
			{
				var ec = new KJUR.crypto.SM3withSM2({curve: this.eccurvename});
				
				var G = ec.ecparams['G'];
								
				var pubKeyHex = this.ecpubhex.substr(2, 128);
				
				var smDigest = new SM3Digest();
				
				var z = new SM3Digest().GetZ(G, pubKeyHex);
				var zValue = smDigest.GetWords(smDigest.GetHex(z).toString());
				
				var rawData = CryptoJS.enc.Utf8.stringify(this.md.md._data);
				rawData = CryptoJS.enc.Utf8.parse(rawData).toString();
				rawData = smDigest.GetWords(rawData);
				
                var smHash = new Array(smDigest.GetDigestSize());
                smDigest.BlockUpdate(zValue, 0, zValue.length);
                smDigest.BlockUpdate(rawData, 0, rawData.length);
                smDigest.DoFinal(smHash, 0);

                var hashHex = smDigest.GetHex(smHash).toString();
				
				this.sHashHex = hashHex;
				
				
		    	return ec.verifyHex(this.sHashHex, hSigVal, this.ecpubhex);
			}else {
		    	var ec = new KJUR.crypto.ECDSA({curve: this.eccurvename});
		    	return ec.verifyHex(this.sHashHex, hSigVal, this.ecpubhex);
			}
		} else if (this.pubkeyAlgName == "rsaandmgf1") {
		    return this.pubKey.verifyWithMessageHashPSS(this.sHashHex, hSigVal, 
								this.mdAlgName,
								this.pssSaltLen);
		} else if (this.pubkeyAlgName == "rsa") {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (this.pubKey instanceof KJUR.crypto.ECDSA) {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else if (this.pubKey instanceof KJUR.crypto.DSA) {
		    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal);
		} else {
		    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName;
		}
	    };
	}
    };

    /**
     * Initialize this object for signing or verifying depends on key
     * @name init
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} key specifying public or private key as plain/encrypted PKCS#5/8 PEM file, certificate PEM or {@link RSAKey}, {@link KJUR.crypto.DSA} or {@link KJUR.crypto.ECDSA} object
     * @param {String} pass (OPTION) passcode for encrypted private key
     * @since crypto 1.1.3
     * @description
     * This method is very useful initialize method for Signature class since
     * you just specify key then this method will automatically initialize it
     * using {@link KEYUTIL.getKey} method.
     * As for 'key',  following argument type are supported:
     * <h5>signing</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 encrypted RSA/ECDSA private key concluding "BEGIN ENCRYPTED PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 encrypted RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" and ",ENCRYPTED"</li>
     * <li>PEM formatted PKCS#8 plain RSA/ECDSA private key concluding "BEGIN PRIVATE KEY"</li>
     * <li>PEM formatted PKCS#5 plain RSA/DSA private key concluding "BEGIN RSA/DSA PRIVATE KEY" without ",ENCRYPTED"</li>
     * <li>RSAKey object of private key</li>
     * <li>KJUR.crypto.ECDSA object of private key</li>
     * <li>KJUR.crypto.DSA object of private key</li>
     * </ul>
     * <h5>verification</h5>
     * <ul>
     * <li>PEM formatted PKCS#8 RSA/EC/DSA public key concluding "BEGIN PUBLIC KEY"</li>
     * <li>PEM formatted X.509 certificate with RSA/EC/DSA public key concluding
     *     "BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE" or "BEGIN TRUSTED CERTIFICATE".</li>
     * <li>RSAKey object of public key</li>
     * <li>KJUR.crypto.ECDSA object of public key</li>
     * <li>KJUR.crypto.DSA object of public key</li>
     * </ul>
     * @example
     * sig.init(sCertPEM)
     */
    this.init = function(key, pass) {
	throw "init(key, pass) not supported for this alg:prov=" +
	      this.algProvName;
    };

    /**
     * Initialize this object for verifying with a public key
     * @name initVerifyByPublicKey
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} param RSAKey object of public key or associative array for ECDSA
     * @since 1.0.2
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * Public key information will be provided as 'param' parameter and the value will be
     * following:
     * <ul>
     * <li>{@link RSAKey} object for RSA verification</li>
     * <li>associative array for ECDSA verification
     *     (ex. <code>{'ecpubhex': '041f..', 'eccurvename': 'secp256r1'}</code>)
     * </li>
     * </ul>
     * @example
     * sig.initVerifyByPublicKey(rsaPrvKey)
     */
    this.initVerifyByPublicKey = function(rsaPubKey) {
	throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" +
	      this.algProvName;
    };

    /**
     * Initialize this object for verifying with a certficate
     * @name initVerifyByCertificatePEM
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} certPEM PEM formatted string of certificate
     * @since 1.0.2
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * @example
     * sig.initVerifyByCertificatePEM(certPEM)
     */
    this.initVerifyByCertificatePEM = function(certPEM) {
	throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" +
	    this.algProvName;
    };

    /**
     * Initialize this object for signing
     * @name initSign
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {Object} param RSAKey object of public key or associative array for ECDSA
     * @deprecated from crypto 1.1.5. please use init() method instead.
     * @description
     * Private key information will be provided as 'param' parameter and the value will be
     * following:
     * <ul>
     * <li>{@link RSAKey} object for RSA signing</li>
     * <li>associative array for ECDSA signing
     *     (ex. <code>{'ecprvhex': '1d3f..', 'eccurvename': 'secp256r1'}</code>)</li>
     * </ul>
     * @example
     * sig.initSign(prvKey)
     */
    this.initSign = function(prvKey) {
	throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a string
     * @name updateString
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to use for the update
     * @description
     * @example
     * sig.updateString('aaa')
     */
    this.updateString = function(str) {
	throw "updateString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Updates the data to be signed or verified by a hexadecimal string
     * @name updateHex
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} hex hexadecimal string to use for the update
     * @description
     * @example
     * sig.updateHex('1f2f3f')
     */
    this.updateHex = function(hex) {
	throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * Returns the signature bytes of all data updates as a hexadecimal string
     * @name sign
     * @memberOf KJUR.crypto.Signature
     * @function
     * @return the signature bytes as a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.sign()
     */
    this.sign = function() {
	throw "sign() not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signString
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signString('aaa')
     */
    this.signString = function(str) {
	throw "digestString(str) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * performs final update on the sign using hexadecimal string, then returns the signature bytes of all data updates as a hexadecimal string
     * @name signHex
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} hex hexadecimal string to final update
     * @return the signature bytes of a hexadecimal string
     * @description
     * @example
     * var hSigValue = sig.signHex('1fdc33')
     */
    this.signHex = function(hex) {
	throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName;
    };

    /**
     * verifies the passed-in signature.
     * @name verify
     * @memberOf KJUR.crypto.Signature
     * @function
     * @param {String} str string to final update
     * @return {Boolean} true if the signature was verified, otherwise false
     * @description
     * @example
     * var isValid = sig.verify('1fbcefdca4823a7(snip)')
     */
    this.verify = function(hSigVal) {
	throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName;
    };

    this.initParams = params;

    if (params !== undefined) {
	if (params['alg'] !== undefined) {
	    this.algName = params['alg'];
	    if (params['prov'] === undefined) {
		this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName];
	    } else {
		this.provName = params['prov'];
	    }
	    this.algProvName = this.algName + ":" + this.provName;
	    this.setAlgAndProvider(this.algName, this.provName);
	    this._setAlgNames();
	}

	if (params['psssaltlen'] !== undefined) this.pssSaltLen = params['psssaltlen'];

	if (params['prvkeypem'] !== undefined) {
	    if (params['prvkeypas'] !== undefined) {
		throw "both prvkeypem and prvkeypas parameters not supported";
	    } else {
		try {
		    var prvKey = new RSAKey();
		    prvKey.readPrivateKeyFromPEMString(params['prvkeypem']);
		    this.initSign(prvKey);
		} catch (ex) {
		    throw "fatal error to load pem private key: " + ex;
		}
	    }
	}
    }
};

/**
 * static object for cryptographic function utilities
 * @name KJUR.crypto.OID
 * @class static object for cryptography related OIDs
 * @property {Array} oidhex2name key value of hexadecimal OID and its name
 *           (ex. '2a8648ce3d030107' and 'secp256r1')
 * @since crypto 1.1.3
 * @description
 */


KJUR.crypto.OID = new function() {
    this.oidhex2name = {
	'2a864886f70d010101': 'rsaEncryption',
	'2a8648ce3d0201': 'ecPublicKey',
	'2a8648ce380401': 'dsa',
	'2a8648ce3d030107': 'secp256r1',
	'2b8104001f': 'secp192k1',
	'2b81040021': 'secp224r1',
	'2b8104000a': 'secp256k1',
	'2b81040023': 'secp521r1',
	'2b81040022': 'secp384r1',
	'2a8648ce380403': 'SHA1withDSA', // 1.2.840.10040.4.3
	'608648016503040301': 'SHA224withDSA', // 2.16.840.1.101.3.4.3.1
	'608648016503040302': 'SHA256withDSA' // 2.16.840.1.101.3.4.3.2
    };
};

/*****ec.js*****/

/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// Only Fp curves implemented for now

// Requires jsbn.js and jsbn2.js

// ----------------
// ECFieldElementFp

// constructor
function ECFieldElementFp(q,x) {
    this.x = x;
    // TODO if(x.compareTo(q) >= 0) error
    this.q = q;
}

function feFpEquals(other) {
    if(other == this) return true;
    return (this.q.equals(other.q) && this.x.equals(other.x));
}

function feFpToBigInteger() {
    return this.x;
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}

function feFpAdd(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}

function feFpSubtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}

function feFpMultiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}

function feFpDivide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}

ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;

// ----------------
// ECPointFp

// constructor
function ECPointFp(curve,x,y,z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    // Projective coordinates: either zinv == null or z * zinv == 1
    // z and zinv are just BigIntegers, not fieldElements
    if(z == null) {
      this.z = BigInteger.ONE;
    }
    else {
      this.z = z;
    }
    this.zinv = null;
    //TODO: compression flag
}

function pointFpGetX() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpGetY() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpEquals(other) {
    if(other == this) return true;
    if(this.isInfinity()) return other.isInfinity();
    if(other.isInfinity()) return this.isInfinity();
    var u, v;
    // u = Y2 * Z1 - Y1 * Z2
    u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
    if(!u.equals(BigInteger.ZERO)) return false;
    // v = X2 * Z1 - X1 * Z2
    v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
    return v.equals(BigInteger.ZERO);
}

function pointFpIsInfinity() {
    if((this.x == null) && (this.y == null)) return true;
    return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}

function pointFpNegate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}

function pointFpAdd(b) {
    if(this.isInfinity()) return b;
    if(b.isInfinity()) return this;

    // u = Y2 * Z1 - Y1 * Z2
    var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
    // v = X2 * Z1 - X1 * Z2
    var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

    if(BigInteger.ZERO.equals(v)) {
        if(BigInteger.ZERO.equals(u)) {
            return this.twice(); // this == b, so double
        }
	return this.curve.getInfinity(); // this = -b, so infinity
    }

    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();
    var x2 = b.x.toBigInteger();
    var y2 = b.y.toBigInteger();

    var v2 = v.square();
    var v3 = v2.multiply(v);
    var x1v2 = x1.multiply(v2);
    var zu2 = u.square().multiply(this.z);

    // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
    var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
    // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
    var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
    // z3 = v^3 * z1 * z2
    var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpTwice() {
    if(this.isInfinity()) return this;
    if(this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

    // TODO: optimized handling of constants
    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();

    var y1z1 = y1.multiply(this.z);
    var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
    var a = this.curve.a.toBigInteger();

    // w = 3 * x1^2 + a * z1^2
    var w = x1.square().multiply(THREE);
    if(!BigInteger.ZERO.equals(a)) {
      w = w.add(this.z.square().multiply(a));
    }
    w = w.mod(this.curve.q);
    // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
    var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
    // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
    var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
    // z3 = 8 * (y1 * z1)^3
    var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

// Simple NAF (Non-Adjacent Form) multiplication algorithm
// TODO: modularize the multiplication algorithm
function pointFpMultiply(k) {
    if(this.isInfinity()) return this;
    if(k.signum() == 0) return this.curve.getInfinity();

    var e = k;
    var h = e.multiply(new BigInteger("3"));

    var neg = this.negate();
    var R = this;

    var i;
    for(i = h.bitLength() - 2; i > 0; --i) {
	R = R.twice();

	var hBit = h.testBit(i);
	var eBit = e.testBit(i);

	if (hBit != eBit) {
	    R = R.add(hBit ? this : neg);
	}
    }

    return R;
}

// Compute this*j + x*k (simultaneous multiplication)
function pointFpMultiplyTwo(j,x,k) {
  var i;
  if(j.bitLength() > k.bitLength())
    i = j.bitLength() - 1;
  else
    i = k.bitLength() - 1;

  var R = this.curve.getInfinity();
  var both = this.add(x);
  while(i >= 0) {
    R = R.twice();
    if(j.testBit(i)) {
      if(k.testBit(i)) {
        R = R.add(both);
      }
      else {
        R = R.add(this);
      }
    }
    else {
      if(k.testBit(i)) {
        R = R.add(x);
      }
    }
    --i;
  }

  return R;
}

ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;

// ----------------
// ECCurveFp

// constructor
function ECCurveFp(q,a,b) {
    this.q = q;
    this.a = this.fromBigInteger(a);
    this.b = this.fromBigInteger(b);
    this.infinity = new ECPointFp(this, null, null);
}

function curveFpGetQ() {
    return this.q;
}

function curveFpGetA() {
    return this.a;
}

function curveFpGetB() {
    return this.b;
}

function curveFpEquals(other) {
    if(other == this) return true;
    return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
}

function curveFpGetInfinity() {
    return this.infinity;
}

function curveFpFromBigInteger(x) {
    return new ECFieldElementFp(this.q, x);
}

// for now, work with hex strings because they're easier in JS
function curveFpDecodePointHex(s) {
    switch(parseInt(s.substr(0,2), 16)) { // first byte
    case 0:
	return this.infinity;
    case 2:
    case 3:
	// point compression not supported yet
	return null;
    case 4:
    case 6:
    case 7:
	var len = (s.length - 2) / 2;
	var xHex = s.substr(2, len);
	var yHex = s.substr(len+2, len);

	return new ECPointFp(this,
			     this.fromBigInteger(new BigInteger(xHex, 16)),
			     this.fromBigInteger(new BigInteger(yHex, 16)));

    default: // unsupported
	return null;
    }
}

ECCurveFp.prototype.getQ = curveFpGetQ;
ECCurveFp.prototype.getA = curveFpGetA;
ECCurveFp.prototype.getB = curveFpGetB;
ECCurveFp.prototype.equals = curveFpEquals;
ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;

/*****ec-patch.js*****/

/*! (c) Stefan Thomas | https://github.com/bitcoinjs/bitcoinjs-lib
 */
/*
 * splitted from bitcoin-lib/ecdsa.js
 *
 * version 1.0.0 is the original of bitcoin-lib/ecdsa.js
 */
ECFieldElementFp.prototype.getByteLength = function () {
  return Math.floor((this.toBigInteger().bitLength() + 7) / 8);
};

ECPointFp.prototype.getEncoded = function (compressed) {
  var integerToBytes = function(i, len) {
    var bytes = i.toByteArrayUnsigned();

    if (len < bytes.length) {
      bytes = bytes.slice(bytes.length-len);
    } else while (len > bytes.length) {
      bytes.unshift(0);
    }
    return bytes;
  };

  var x = this.getX().toBigInteger();
  var y = this.getY().toBigInteger();

  // Get value as a 32-byte Buffer
  // Fixed length based on a patch by bitaddress.org and Casascius
  var enc = integerToBytes(x, 32);

  if (compressed) {
    if (y.isEven()) {
      // Compressed even pubkey
      // M = 02 || X
      enc.unshift(0x02);
    } else {
      // Compressed uneven pubkey
      // M = 03 || X
      enc.unshift(0x03);
    }
  } else {
    // Uncompressed pubkey
    // M = 04 || X || Y
    enc.unshift(0x04);
    enc = enc.concat(integerToBytes(y, 32));
  }
  return enc;
};

ECPointFp.decodeFrom = function (curve, enc) {
  var type = enc[0];
  var dataLen = enc.length-1;

  // Extract x and y as byte arrays
  var xBa = enc.slice(1, 1 + dataLen/2);
  var yBa = enc.slice(1 + dataLen/2, 1 + dataLen);

  // Prepend zero byte to prevent interpretation as negative integer
  xBa.unshift(0);
  yBa.unshift(0);

  // Convert to BigIntegers
  var x = new BigInteger(xBa);
  var y = new BigInteger(yBa);

  // Return point
  return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
};

/*
 * @since ec-patch.js 1.0.1
 */
ECPointFp.decodeFromHex = function (curve, encHex) {
  var type = encHex.substr(0, 2); // shall be "04"
  var dataLen = encHex.length - 2;

  // Extract x and y as byte arrays
  var xHex = encHex.substr(2, dataLen / 2);
  var yHex = encHex.substr(2 + dataLen / 2, dataLen / 2);

  // Convert to BigIntegers
  var x = new BigInteger(xHex, 16);
  var y = new BigInteger(yHex, 16);

  // Return point
  return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
};

ECPointFp.prototype.add2D = function (b) {
  if(this.isInfinity()) return b;
  if(b.isInfinity()) return this;

  if (this.x.equals(b.x)) {
    if (this.y.equals(b.y)) {
      // this = b, i.e. this must be doubled
      return this.twice();
    }
    // this = -b, i.e. the result is the point at infinity
    return this.curve.getInfinity();
  }

  var x_x = b.x.subtract(this.x);
  var y_y = b.y.subtract(this.y);
  var gamma = y_y.divide(x_x);

  var x3 = gamma.square().subtract(this.x).subtract(b.x);
  var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

  return new ECPointFp(this.curve, x3, y3);
};

ECPointFp.prototype.twice2D = function () {
  if (this.isInfinity()) return this;
  if (this.y.toBigInteger().signum() == 0) {
    // if y1 == 0, then (x1, y1) == (x1, -y1)
    // and hence this = -this and thus 2(x1, y1) == infinity
    return this.curve.getInfinity();
  }

  var TWO = this.curve.fromBigInteger(BigInteger.valueOf(2));
  var THREE = this.curve.fromBigInteger(BigInteger.valueOf(3));
  var gamma = this.x.square().multiply(THREE).add(this.curve.a).divide(this.y.multiply(TWO));

  var x3 = gamma.square().subtract(this.x.multiply(TWO));
  var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

  return new ECPointFp(this.curve, x3, y3);
};

ECPointFp.prototype.multiply2D = function (k) {
  if(this.isInfinity()) return this;
  if(k.signum() == 0) return this.curve.getInfinity();

  var e = k;
  var h = e.multiply(new BigInteger("3"));

  var neg = this.negate();
  var R = this;

  var i;
  for (i = h.bitLength() - 2; i > 0; --i) {
    R = R.twice();

    var hBit = h.testBit(i);
    var eBit = e.testBit(i);

    if (hBit != eBit) {
      R = R.add2D(hBit ? this : neg);
    }
  }

  return R;
};

ECPointFp.prototype.isOnCurve = function () {
  var x = this.getX().toBigInteger();
  var y = this.getY().toBigInteger();
  var a = this.curve.getA().toBigInteger();
  var b = this.curve.getB().toBigInteger();
  var n = this.curve.getQ();
  var lhs = y.multiply(y).mod(n);
  var rhs = x.multiply(x).multiply(x)
    .add(a.multiply(x)).add(b).mod(n);
  return lhs.equals(rhs);
};

ECPointFp.prototype.toString = function () {
  return '('+this.getX().toBigInteger().toString()+','+
    this.getY().toBigInteger().toString()+')';
};

/**
 * Validate an elliptic curve point.
 *
 * See SEC 1, section 3.2.2.1: Elliptic Curve Public Key Validation Primitive
 */
ECPointFp.prototype.validate = function () {
  var n = this.curve.getQ();

  // Check Q != O
  if (this.isInfinity()) {
    throw new Error("Point is at infinity.");
  }

  // Check coordinate bounds
  var x = this.getX().toBigInteger();
  var y = this.getY().toBigInteger();
  if (x.compareTo(BigInteger.ONE) < 0 ||
      x.compareTo(n.subtract(BigInteger.ONE)) > 0) {
    throw new Error('x coordinate out of bounds');
  }
  if (y.compareTo(BigInteger.ONE) < 0 ||
      y.compareTo(n.subtract(BigInteger.ONE)) > 0) {
    throw new Error('y coordinate out of bounds');
  }

  // Check y^2 = x^3 + ax + b (mod n)
  if (!this.isOnCurve()) {
    throw new Error("Point is not on the curve.");
  }

  // Check nQ = 0 (Q is a scalar multiple of G)
  if (this.multiply(n).isInfinity()) {
    // TODO: This check doesn't work - fix.
    throw new Error("Point is not a scalar multiple of G.");
  }

  return true;
};

/*****ecdsa-modified-1.0.js*****/
/*! ecdsa-modified-1.0.4.js (c) Stephan Thomas, Kenji Urushima | github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE
 */
/*
 * ecdsa-modified.js - modified Bitcoin.ECDSA class
 * 
 * Copyright (c) 2013 Stefan Thomas (github.com/justmoon)
 *                    Kenji Urushima (kenji.urushima@gmail.com)
 * LICENSE
 *   https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE
 */

/**
 * @fileOverview
 * @name ecdsa-modified-1.0.js
 * @author Stefan Thomas (github.com/justmoon) and Kenji Urushima (kenji.urushima@gmail.com)
 * @version 1.0.4 (2013-Oct-06)
 * @since jsrsasign 4.0
 * @license <a href="https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * class for EC key generation,  ECDSA signing and verifcation
 * @name KJUR.crypto.ECDSA
 * @class class for EC key generation,  ECDSA signing and verifcation
 * @description
 * <p>
 * CAUTION: Most of the case, you don't need to use this class except
 * for generating an EC key pair. Please use {@link KJUR.crypto.Signature} class instead.
 * </p>
 * <p>
 * This class was originally developped by Stefan Thomas for Bitcoin JavaScript library.
 * (See {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/ecdsa.js})
 * Currently this class supports following named curves and their aliases.
 * <ul>
 * <li>secp256r1, NIST P-256, P-256, prime256v1 (*)</li>
 * <li>secp256k1 (*)</li>
 * <li>secp384r1, NIST P-384, P-384 (*)</li>
 * </ul>
 * </p>
 */
KJUR.crypto.ECDSA = function(params) {
    var curveName = "secp256r1";	// curve name default
    var ecparams = null;
    var prvKeyHex = null;
    var pubKeyHex = null;

    var rng = new SecureRandom();

    var P_OVER_FOUR = null;

    this.type = "EC";

    function implShamirsTrick(P, k, Q, l) {
	var m = Math.max(k.bitLength(), l.bitLength());
	var Z = P.add2D(Q);
	var R = P.curve.getInfinity();

	for (var i = m - 1; i >= 0; --i) {
	    R = R.twice2D();

	    R.z = BigInteger.ONE;

	    if (k.testBit(i)) {
		if (l.testBit(i)) {
		    R = R.add2D(Z);
		} else {
		    R = R.add2D(P);
		}
	    } else {
		if (l.testBit(i)) {
		    R = R.add2D(Q);
		}
	    }
	}
	
	return R;
    };

    //===========================
    // PUBLIC METHODS
    //===========================
    this.getBigRandom = function (limit) {
	return new BigInteger(limit.bitLength(), rng)
	.mod(limit.subtract(BigInteger.ONE))
	.add(BigInteger.ONE)
	;
    };

    this.setNamedCurve = function(curveName) {
	this.ecparams = KJUR.crypto.ECParameterDB.getByName(curveName);
	this.prvKeyHex = null;
	this.pubKeyHex = null;
	this.curveName = curveName;
    }

    this.setPrivateKeyHex = function(prvKeyHex) {
        this.isPrivate = true;
	this.prvKeyHex = prvKeyHex;
    }

    this.setPublicKeyHex = function(pubKeyHex) {
        this.isPublic = true;
	this.pubKeyHex = pubKeyHex;
    }

    /**
     * generate a EC key pair
     * @name generateKeyPairHex
     * @memberOf KJUR.crypto.ECDSA
     * @function
     * @return {Array} associative array of hexadecimal string of private and public key
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.ECDSA({'curve': 'secp256r1'});
     * var keypair = ec.generateKeyPairHex();
     * var pubhex = keypair.ecpubhex; // hexadecimal string of EC private key (=d)
     * var prvhex = keypair.ecprvhex; // hexadecimal string of EC public key
     */
    this.generateKeyPairHex = function() {
	var biN = this.ecparams['n'];
	var biPrv = this.getBigRandom(biN);
	var epPub = this.ecparams['G'].multiply(biPrv);
	var biX = epPub.getX().toBigInteger();
	var biY = epPub.getY().toBigInteger();

	var charlen = this.ecparams['keylen'] / 4;
	var hPrv = ("0000000000" + biPrv.toString(16)).slice(- charlen);
	var hX   = ("0000000000" + biX.toString(16)).slice(- charlen);
	var hY   = ("0000000000" + biY.toString(16)).slice(- charlen);
	var hPub = "04" + hX + hY;

	this.setPrivateKeyHex(hPrv);
	this.setPublicKeyHex(hPub);
	return {'ecprvhex': hPrv, 'ecpubhex': hPub};
    };

    this.signWithMessageHash = function(hashHex) {
	return this.signHex(hashHex, this.prvKeyHex);
    };

    /**
     * signing to message hash
     * @name signHex
     * @memberOf KJUR.crypto.ECDSA
     * @function
     * @param {String} hashHex hexadecimal string of hash value of signing message
     * @param {String} privHex hexadecimal string of EC private key
     * @return {String} hexadecimal string of ECDSA signature
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.ECDSA({'curve': 'secp256r1'});
     * var sigValue = ec.signHex(hash, prvKey);
     */
    this.signHex = function (hashHex, privHex) {
	var d = new BigInteger(privHex, 16);
	var n = this.ecparams['n'];
	var e = new BigInteger(hashHex, 16);

	do {
	    var k = this.getBigRandom(n);
	    var G = this.ecparams['G'];
	    var Q = G.multiply(k);
	    var r = Q.getX().toBigInteger().mod(n);
	} while (r.compareTo(BigInteger.ZERO) <= 0);

	var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

	return KJUR.crypto.ECDSA.biRSSigToASN1Sig(r, s);
    };

 //    this.sign = function (hash, priv) {
	// var d = BigInteger.fromByteArrayUnsigned(priv);
	// var n = this.ecparams['n'];
	// var e = BigInteger.fromByteArrayUnsigned(hash);
	// do {
	//     var k = this.getBigRandom(n);
	//     var G = this.ecparams['G'];
	//     var Q = G.multiply(k);
	//     var r = Q.getX().toBigInteger().mod(n);
	// } while (r.compareTo(BigInteger.ZERO) <= 0);

	// var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
	// return this.serializeSig(r, s);
 //    };
    this.signWithoutHash = function (hash, priv) {  //mod by wx  todo 缺少对数据预处理 wx
        var d = BigInteger.fromByteArrayUnsigned(priv);
        var n = this.ecparams['n'];
        var e = BigInteger.fromByteArrayUnsigned(hash);
        var r;
        var k;
        var s;
        do{
            do {
                k = this.getBigRandom(n);
                var G = this.ecparams['G'];
                var kp = G.multiply(k);
                r = e.add(kp.getX().toBigInteger());
                r = r.mod(n);
            } while (r.compareTo(BigInteger.ZERO) == 0 || r.add(k).equals(n));
            var da_1 = d.add(BigInteger.ONE).modInverse(n);
            s = r.multiply(d);
            s = k.subtract(s);
            s = s.multiply(da_1);
            s = s.mod(n);
        } while (s.compareTo(BigInteger.ZERO) == 0);
        return this.serializeSig(r, s);
    };

    this.getZForHash = function(userID, priv) {
        var SM3 = KeyouCryptography.algorithm.SM3;
        var Hex = KeyouCryptography.util.Hex;
        var data = [];
        var i = 0;
        var BitsLength = userID.length << 3;
        userID.unshift(BitsLength & 0xFF);
        userID.unshift(BitsLength >> 8 & 0xFF);
        SM3.init();
        SM3.update(userID);
        var curve = this.ecparams['curve'];
        var a = curve.a.toBigInteger().toByteArraySigned();
        if (a.length == 33) {
            a.shift(); //首字节符号位移除
        }
        var b = curve.b.toBigInteger().toByteArraySigned();
        if (b.length == 33) {
            b.shift(); //首字节符号位移除
        }
        var g = this.ecparams['G'];
        var gx = g.getX().toBigInteger().toByteArraySigned();
        if (gx.length == 33) {
            gx.shift();
        }
        var gy = g.getY().toBigInteger().toByteArraySigned();
        if (gy.length == 33) {
            gy.shift();
        }
        SM3.update(a);
        SM3.update(b);
        SM3.update(gx);
        SM3.update(gy);
        var vkx = priv.getX().toBigInteger().toByteArraySigned();
        var vky = priv.getY().toBigInteger().toByteArraySigned();
        if (vkx.length == 33) {
            vkx.shift();
        }
        if (vky.length == 33) {
            vky.shift();
        }
        SM3.update(vkx);
        SM3.update(vky);
        var hashData = SM3.doFinal();
        return hashData;
    }

    this.sign = function(data, priv) {
        var SM3 = KeyouCryptography.algorithm.SM3;
        var Hex = KeyouCryptography.util.Hex;
        var userID = [49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56];
        var G = this.ecparams['G'];
        var privateKey = BigInteger.fromByteArrayUnsigned(priv);
        var z = this.getZForHash(userID, G.multiply(privateKey));
        SM3.init();
        SM3.update(z);
        SM3.update(data);
        var hashData = SM3.doFinal();
        return this.signWithoutHash(hashData, priv);
    }

    this.verifyWithMessageHash = function(hashHex, sigHex) {
	return this.verifyHex(hashHex, sigHex, this.pubKeyHex);
    };

    /**
     * verifying signature with message hash and public key
     * @name verifyHex
     * @memberOf KJUR.crypto.ECDSA
     * @function
     * @param {String} hashHex hexadecimal string of hash value of signing message
     * @param {String} sigHex hexadecimal string of signature value
     * @param {String} pubkeyHex hexadecimal string of public key
     * @return {Boolean} true if the signature is valid, otherwise false
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.ECDSA({'curve': 'secp256r1'});
     * var result = ec.verifyHex(msgHashHex, sigHex, pubkeyHex);
     */
    this.verifyHex = function(hashHex, sigHex, pubkeyHex) {
	var r,s;

	var obj = KJUR.crypto.ECDSA.parseSigHex(sigHex);
	r = obj.r;
	s = obj.s;

	var Q;
	Q = ECPointFp.decodeFromHex(this.ecparams['curve'], pubkeyHex);
	var e = new BigInteger(hashHex, 16);

	return this.verifyRaw(e, r, s, Q);
    };

    this.verifyWithoutHash = function (hash, sig, pubkey) {
    	var r,s;
    	if (Array.isArray(sig)) { //Bitcoin.Util.isArray(sig)
    	    var obj = this.parseSig(sig);
    	    r = obj.r;
    	    s = obj.s;
    	} else if ("object" === typeof sig && sig.r && sig.s) {
    	    r = sig.r;
    	    s = sig.s;
    	} else {
    	    throw "Invalid value for signature";
    	}

    	var Q;
    	if (pubkey instanceof ECPointFp) {
    	    Q = pubkey;
    	} else if (Array.isArray(pubkey)) { //
            if (pubkey[0] != 4) {
                pubkey.unshift(4);
            }
    	    Q = ECPointFp.decodeFrom(this.ecparams['curve'], pubkey);
    	} else {
    	    throw "Invalid format for pubkey value, must be byte array or ECPointFp";
    	}
    	var e = BigInteger.fromByteArrayUnsigned(hash);

    	return this.verifyRaw(e, r, s, Q);
    };

    this.createPoint = function(pk) {
        var ecc_curve = this.ecparams['curve'];
        if (pk.substr(0, 2) != "04") {
            pk = '04' + pk;
        }
        var point = ECPointFp.decodeFromHex(ecc_curve, pk);
        return point
    }

    this.verify = function (data, sig, pubkey) {
        var SM3 = KeyouCryptography.algorithm.SM3;
        var userID = [49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56];
        var G = this.ecparams['G'];
        var Hex = KeyouCryptography.util.Hex;
        var userKey = this.createPoint(Hex.encode(pubkey));
        var z = this.getZForHash(userID, userKey);
        SM3.init();
        SM3.update(z);
        SM3.update(data);
        var hashData = SM3.doFinal();
        return this.verifyWithoutHash(hashData, sig, pubkey);
    }

 //    this.verifyRaw = function (e, r, s, Q) {
	// var n = this.ecparams['n'];
	// var G = this.ecparams['G'];

	// if (r.compareTo(BigInteger.ONE) < 0 ||
	//     r.compareTo(n) >= 0)
	//     return false;

	// if (s.compareTo(BigInteger.ONE) < 0 ||
	//     s.compareTo(n) >= 0)
	//     return false;

	// var c = s.modInverse(n);

	// var u1 = e.multiply(c).mod(n);
	// var u2 = r.multiply(c).mod(n);

	// // TODO(!!!): For some reason Shamir's trick isn't working with
	// // signed message verification!? Probably an implementation
	// // error!
	// //var point = implShamirsTrick(G, u1, Q, u2);
	// var point = G.multiply(u1).add(Q.multiply(u2));

	// var v = point.getX().toBigInteger().mod(n);

	// return v.equals(r);
 //    };
    this.verifyRaw = function (e, r, s, Q) { //mod by wx 
        var n = this.ecparams['n'];
        var G = this.ecparams['G'];

        if (r.compareTo(BigInteger.ONE) < 0 ||
            r.compareTo(n) >= 0)
            return false;

        if (s.compareTo(BigInteger.ONE) < 0 ||
            s.compareTo(n) >= 0)
            return false;

        var t = r.add(s).mod(n);
        if (t.compareTo(BigInteger.ZERO) == 0) {
            return false;
        }
        var x1y1 = G.multiply(s);
        x1y1 = x1y1.add(Q.multiply(t));
        var v = e.add(x1y1.getX().toBigInteger()).mod(n);
        return v.equals(r);
    };

    /**
     * Serialize a signature into DER format.
     *
     * Takes two BigIntegers representing r and s and returns a byte array.
     */
    this.serializeSig = function (r, s) {
	var rBa = r.toByteArraySigned();
	var sBa = s.toByteArraySigned();

	var sequence = [];
	sequence.push(0x02); // INTEGER
	sequence.push(rBa.length);
	sequence = sequence.concat(rBa);

	sequence.push(0x02); // INTEGER
	sequence.push(sBa.length);
	sequence = sequence.concat(sBa);

	sequence.unshift(sequence.length);
	sequence.unshift(0x30); // SEQUENCE
	return sequence;
    };

    /**
     * Parses a byte array containing a DER-encoded signature.
     *
     * This function will return an object of the form:
     *
     * {
     *   r: BigInteger,
     *   s: BigInteger
     * }
     */
    this.parseSig = function (sig) {
	var cursor;
	if (sig[0] != 0x30)
	    throw new Error("Signature not a valid DERSequence");

	cursor = 2;
	if (sig[cursor] != 0x02)
	    throw new Error("First element in signature must be a DERInteger");;
	var rBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

	cursor += 2+sig[cursor+1];
	if (sig[cursor] != 0x02)
	    throw new Error("Second element in signature must be a DERInteger");
	var sBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

	cursor += 2+sig[cursor+1];

	//if (cursor != sig.length)
	//  throw new Error("Extra bytes in signature");

	var r = BigInteger.fromByteArrayUnsigned(rBa);
	var s = BigInteger.fromByteArrayUnsigned(sBa);

	return {r: r, s: s};
    };

    this.parseSigCompact = function (sig) {
	if (sig.length !== 65) {
	    throw "Signature has the wrong length";
	}

	// Signature is prefixed with a type byte storing three bits of
	// information.
	var i = sig[0] - 27;
	if (i < 0 || i > 7) {
	    throw "Invalid signature type";
	}

	var n = this.ecparams['n'];
	var r = BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
	var s = BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);

	return {r: r, s: s, i: i};
    };

    /*
     * Recover a public key from a signature.
     *
     * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
     * Key Recovery Operation".
     *
     * http://www.secg.org/download/aid-780/sec1-v2.pdf
     */
    /*
    recoverPubKey: function (r, s, hash, i) {
	// The recovery parameter i has two bits.
	i = i & 3;

	// The less significant bit specifies whether the y coordinate
	// of the compressed point is even or not.
	var isYEven = i & 1;

	// The more significant bit specifies whether we should use the
	// first or second candidate key.
	var isSecondKey = i >> 1;

	var n = this.ecparams['n'];
	var G = this.ecparams['G'];
	var curve = this.ecparams['curve'];
	var p = curve.getQ();
	var a = curve.getA().toBigInteger();
	var b = curve.getB().toBigInteger();

	// We precalculate (p + 1) / 4 where p is if the field order
	if (!P_OVER_FOUR) {
	    P_OVER_FOUR = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
	}

	// 1.1 Compute x
	var x = isSecondKey ? r.add(n) : r;

	// 1.3 Convert x to point
	var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
	var beta = alpha.modPow(P_OVER_FOUR, p);

	var xorOdd = beta.isEven() ? (i % 2) : ((i+1) % 2);
	// If beta is even, but y isn't or vice versa, then convert it,
	// otherwise we're done and y == beta.
	var y = (beta.isEven() ? !isYEven : isYEven) ? beta : p.subtract(beta);

	// 1.4 Check that nR is at infinity
	var R = new ECPointFp(curve,
			      curve.fromBigInteger(x),
			      curve.fromBigInteger(y));
	R.validate();

	// 1.5 Compute e from M
	var e = BigInteger.fromByteArrayUnsigned(hash);
	var eNeg = BigInteger.ZERO.subtract(e).mod(n);

	// 1.6 Compute Q = r^-1 (sR - eG)
	var rInv = r.modInverse(n);
	var Q = implShamirsTrick(R, s, G, eNeg).multiply(rInv);

	Q.validate();
	if (!this.verifyRaw(e, r, s, Q)) {
	    throw "Pubkey recovery unsuccessful";
	}

	var pubKey = new Bitcoin.ECKey();
	pubKey.pub = Q;
	return pubKey;
    },
    */

    /*
     * Calculate pubkey extraction parameter.
     *
     * When extracting a pubkey from a signature, we have to
     * distinguish four different cases. Rather than putting this
     * burden on the verifier, Bitcoin includes a 2-bit value with the
     * signature.
     *
     * This function simply tries all four cases and returns the value
     * that resulted in a successful pubkey recovery.
     */
    /*
    calcPubkeyRecoveryParam: function (address, r, s, hash) {
	for (var i = 0; i < 4; i++) {
	    try {
		var pubkey = Bitcoin.ECDSA.recoverPubKey(r, s, hash, i);
		if (pubkey.getBitcoinAddress().toString() == address) {
		    return i;
		}
	    } catch (e) {}
	}
	throw "Unable to find valid recovery factor";
    }
    */

    if (params !== undefined) {
	if (params['curve'] !== undefined) {
	    this.curveName = params['curve'];
	}
    }
    if (this.curveName === undefined) this.curveName = curveName;
    this.setNamedCurve(this.curveName);
    if (params !== undefined) {
	if (params['prv'] !== undefined) this.setPrivateKeyHex(params['prv']);
	if (params['pub'] !== undefined) this.setPublicKeyHex(params['pub']);
    }
};

/**
 * parse ASN.1 DER encoded ECDSA signature
 * @name parseSigHex
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} sigHex hexadecimal string of ECDSA signature value
 * @return {Array} associative array of signature field r and s of BigInteger
 * @since ecdsa-modified 1.0.1
 * @example
 * var ec = KJUR.crypto.ECDSA({'curve': 'secp256r1'});
 * var sig = ec.parseSigHex('30...');
 * var biR = sig.r; // BigInteger object for 'r' field of signature.
 * var biS = sig.s; // BigInteger object for 's' field of signature.
 */
KJUR.crypto.ECDSA.parseSigHex = function(sigHex) {
    var p = KJUR.crypto.ECDSA.parseSigHexInHexRS(sigHex);
    var biR = new BigInteger(p.r, 16);
    var biS = new BigInteger(p.s, 16);
    
    return {'r': biR, 's': biS};
};

/**
 * parse ASN.1 DER encoded ECDSA signature
 * @name parseSigHexInHexRS
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} sigHex hexadecimal string of ECDSA signature value
 * @return {Array} associative array of signature field r and s in hexadecimal
 * @since ecdsa-modified 1.0.3
 * @example
 * var ec = KJUR.crypto.ECDSA({'curve': 'secp256r1'});
 * var sig = ec.parseSigHexInHexRS('30...');
 * var hR = sig.r; // hexadecimal string for 'r' field of signature.
 * var hS = sig.s; // hexadecimal string for 's' field of signature.
 */
KJUR.crypto.ECDSA.parseSigHexInHexRS = function(sigHex) {
    // 1. ASN.1 Sequence Check
    if (sigHex.substr(0, 2) != "30")
	throw "signature is not a ASN.1 sequence";

    // 2. Items of ASN.1 Sequence Check
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(sigHex, 0);
    if (a.length != 2)
	throw "number of signature ASN.1 sequence elements seem wrong";
    
    // 3. Integer check
    var iTLV1 = a[0];
    var iTLV2 = a[1];
    if (sigHex.substr(iTLV1, 2) != "02")
	throw "1st item of sequene of signature is not ASN.1 integer";
    if (sigHex.substr(iTLV2, 2) != "02")
	throw "2nd item of sequene of signature is not ASN.1 integer";

    // 4. getting value
    var hR = ASN1HEX.getHexOfV_AtObj(sigHex, iTLV1);
    var hS = ASN1HEX.getHexOfV_AtObj(sigHex, iTLV2);
    
    return {'r': hR, 's': hS};
};

/**
 * convert hexadecimal ASN.1 encoded signature to concatinated signature
 * @name asn1SigToConcatSig
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} asn1Hex hexadecimal string of ASN.1 encoded ECDSA signature value
 * @return {String} r-s concatinated format of ECDSA signature value
 * @since ecdsa-modified 1.0.3
 */
KJUR.crypto.ECDSA.asn1SigToConcatSig = function(asn1Sig) {
    var pSig = KJUR.crypto.ECDSA.parseSigHexInHexRS(asn1Sig);
    var hR = pSig.r;
    var hS = pSig.s;

    if (hR.substr(0, 2) == "00" && (((hR.length / 2) * 8) % (16 * 8)) == 8) 
	hR = hR.substr(2);

    if (hS.substr(0, 2) == "00" && (((hS.length / 2) * 8) % (16 * 8)) == 8) 
	hS = hS.substr(2);

    if ((((hR.length / 2) * 8) % (16 * 8)) != 0)
	throw "unknown ECDSA sig r length error";

    if ((((hS.length / 2) * 8) % (16 * 8)) != 0)
	throw "unknown ECDSA sig s length error";

    return hR + hS;
};

/**
 * convert hexadecimal concatinated signature to ASN.1 encoded signature
 * @name concatSigToASN1Sig
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} concatSig r-s concatinated format of ECDSA signature value
 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
 * @since ecdsa-modified 1.0.3
 */
KJUR.crypto.ECDSA.concatSigToASN1Sig = function(concatSig) {
    if ((((concatSig.length / 2) * 8) % (16 * 8)) != 0)
	throw "unknown ECDSA concatinated r-s sig  length error";

    var hR = concatSig.substr(0, concatSig.length / 2);
    var hS = concatSig.substr(concatSig.length / 2);
    return KJUR.crypto.ECDSA.hexRSSigToASN1Sig(hR, hS);
};

/**
 * convert hexadecimal R and S value of signature to ASN.1 encoded signature
 * @name hexRSSigToASN1Sig
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {String} hR hexadecimal string of R field of ECDSA signature value
 * @param {String} hS hexadecimal string of S field of ECDSA signature value
 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
 * @since ecdsa-modified 1.0.3
 */
KJUR.crypto.ECDSA.hexRSSigToASN1Sig = function(hR, hS) {
    var biR = new BigInteger(hR, 16);
    var biS = new BigInteger(hS, 16);
    return KJUR.crypto.ECDSA.biRSSigToASN1Sig(biR, biS);
};

/**
 * convert R and S BigInteger object of signature to ASN.1 encoded signature
 * @name biRSSigToASN1Sig
 * @memberOf KJUR.crypto.ECDSA
 * @function
 * @static
 * @param {BigInteger} biR BigInteger object of R field of ECDSA signature value
 * @param {BigInteger} biS BIgInteger object of S field of ECDSA signature value
 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
 * @since ecdsa-modified 1.0.3
 */
KJUR.crypto.ECDSA.biRSSigToASN1Sig = function(biR, biS) {
    var derR = new KJUR.asn1.DERInteger({'bigint': biR});
    var derS = new KJUR.asn1.DERInteger({'bigint': biS});
    var derSeq = new KJUR.asn1.DERSequence({'array': [derR, derS]});
    return derSeq.getEncodedHex();
};

/*****sm3.js*****/

(function() {
	var C = CryptoJS;
	var C_lib = C.lib;
	var WordArray = C_lib.WordArray;
	var Hasher = C_lib.Hasher;
	var C_algo = C.algo;
	var W = [];
	var SM3 = C_algo.SM3 = Hasher.extend({
		_doReset : function() {
			this._hash = new WordArray.init([ 0x7380166f, 0x4914b2b9,
					0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d,
					0xb0fb0e4e ])
		},
		_doProcessBlock : function(M, offset) {
			var H = this._hash.words;
			var a = H[0];
			var b = H[1];
			var c = H[2];
			var d = H[3];
			var e = H[4];
			for ( var i = 0; i < 80; i++) {
				if (i < 16) {
					W[i] = M[offset + i] | 0
				} else {
					var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
					W[i] = (n << 1) | (n >>> 31)
				}
				var t = ((a << 5) | (a >>> 27)) + e + W[i];
				if (i < 20) {
					t += ((b & c) | (~b & d)) + 0x5a827999
				} else if (i < 40) {
					t += (b ^ c ^ d) + 0x6ed9eba1
				} else if (i < 60) {
					t += ((b & c) | (b & d) | (c & d)) - 0x70e44324
				} else {
					t += (b ^ c ^ d) - 0x359d3e2a
				}
				e = d;
				d = c;
				c = (b << 30) | (b >>> 2);
				b = a;
				a = t
			}
			H[0] = (H[0] + a) | 0;
			H[1] = (H[1] + b) | 0;
			H[2] = (H[2] + c) | 0;
			H[3] = (H[3] + d) | 0;
			H[4] = (H[4] + e) | 0
		},
		_doFinalize : function() {
			var data = this._data;
			var dataWords = data.words;
			var nBitsTotal = this._nDataBytes * 8;
			var nBitsLeft = data.sigBytes * 8;
			dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
			dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math
					.floor(nBitsTotal / 0x100000000);
			dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
			data.sigBytes = dataWords.length * 4;
			this._process();
			return this._hash
		},
		clone : function() {
			var clone = Hasher.clone.call(this);
			clone._hash = this._hash.clone();
			return clone
		}
	});
	C.SM3 = Hasher._createHelper(SM3);
	C.HmacSM3 = Hasher._createHmacHelper(SM3)
}());
function SM3Digest() {
	this.BYTE_LENGTH = 64;
	this.xBuf = new Array();
	this.xBufOff = 0;
	this.byteCount = 0;
	this.DIGEST_LENGTH = 32;
	this.v0 = [ 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc,
			0x163138aa, 0xe38dee4d, 0xb0fb0e4e ];
	this.v0 = [ 0x7380166f, 0x4914b2b9, 0x172442d7, -628488704, -1452330820,
			0x163138aa, -477237683, -1325724082 ];
	this.v = new Array(8);
	this.v_ = new Array(8);
	this.X0 = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
	this.X = new Array(68);
	this.xOff = 0;
	this.T_00_15 = 0x79cc4519;
	this.T_16_63 = 0x7a879d8a;
	if (arguments.length > 0) {
		this.InitDigest(arguments[0])
	} else {
		this.Init()
	}
}
SM3Digest.prototype = {
	Init : function() {
		this.xBuf = new Array(4);
		this.Reset()
	},
	InitDigest : function(t) {
		this.xBuf = new Array(t.xBuf.length);
		Array.Copy(t.xBuf, 0, this.xBuf, 0, t.xBuf.length);
		this.xBufOff = t.xBufOff;
		this.byteCount = t.byteCount;
		Array.Copy(t.X, 0, this.X, 0, t.X.length);
		this.xOff = t.xOff;
		Array.Copy(t.v, 0, this.v, 0, t.v.length)
	},
	GetDigestSize : function() {
		return this.DIGEST_LENGTH
	},
	Reset : function() {
		this.byteCount = 0;
		this.xBufOff = 0;
		Array.Clear(this.xBuf, 0, this.xBuf.length);
		Array.Copy(this.v0, 0, this.v, 0, this.v0.length);
		this.xOff = 0;
		Array.Copy(this.X0, 0, this.X, 0, this.X0.length)
	},
	GetByteLength : function() {
		return this.BYTE_LENGTH
	},
	ProcessBlock : function() {
		var i;
		var ww = this.X;
		var ww_ = new Array(64);
		for (i = 16; i < 68; i++) {
			ww[i] = this.P1(ww[i - 16] ^ ww[i - 9]
					^ (this.ROTATE(ww[i - 3], 15)))
					^ (this.ROTATE(ww[i - 13], 7)) ^ ww[i - 6]
		}
		for (i = 0; i < 64; i++) {
			ww_[i] = ww[i] ^ ww[i + 4]
		}
		var vv = this.v;
		var vv_ = this.v_;
		Array.Copy(vv, 0, vv_, 0, this.v0.length);
		var SS1, SS2, TT1, TT2, aaa;
		for (i = 0; i < 16; i++) {
			aaa = this.ROTATE(vv_[0], 12);
			SS1 = Int32.parse(Int32.parse(aaa + vv_[4])
					+ this.ROTATE(this.T_00_15, i));
			SS1 = this.ROTATE(SS1, 7);
			SS2 = SS1 ^ aaa;
			TT1 = Int32.parse(Int32.parse(this.FF_00_15(vv_[0], vv_[1], vv_[2])
					+ vv_[3])
					+ SS2)
					+ ww_[i];
			TT2 = Int32.parse(Int32.parse(this.GG_00_15(vv_[4], vv_[5], vv_[6])
					+ vv_[7])
					+ SS1)
					+ ww[i];
			vv_[3] = vv_[2];
			vv_[2] = this.ROTATE(vv_[1], 9);
			vv_[1] = vv_[0];
			vv_[0] = TT1;
			vv_[7] = vv_[6];
			vv_[6] = this.ROTATE(vv_[5], 19);
			vv_[5] = vv_[4];
			vv_[4] = this.P0(TT2)
		}
		for (i = 16; i < 64; i++) {
			aaa = this.ROTATE(vv_[0], 12);
			SS1 = Int32.parse(Int32.parse(aaa + vv_[4])
					+ this.ROTATE(this.T_16_63, i));
			SS1 = this.ROTATE(SS1, 7);
			SS2 = SS1 ^ aaa;
			TT1 = Int32.parse(Int32.parse(this.FF_16_63(vv_[0], vv_[1], vv_[2])
					+ vv_[3])
					+ SS2)
					+ ww_[i];
			TT2 = Int32.parse(Int32.parse(this.GG_16_63(vv_[4], vv_[5], vv_[6])
					+ vv_[7])
					+ SS1)
					+ ww[i];
			vv_[3] = vv_[2];
			vv_[2] = this.ROTATE(vv_[1], 9);
			vv_[1] = vv_[0];
			vv_[0] = TT1;
			vv_[7] = vv_[6];
			vv_[6] = this.ROTATE(vv_[5], 19);
			vv_[5] = vv_[4];
			vv_[4] = this.P0(TT2)
		}
		for (i = 0; i < 8; i++) {
			vv[i] ^= Int32.parse(vv_[i])
		}
		this.xOff = 0;
		Array.Copy(this.X0, 0, this.X, 0, this.X0.length)
	},
	ProcessWord : function(in_Renamed, inOff) {
		var n = in_Renamed[inOff] << 24;
		n |= (in_Renamed[++inOff] & 0xff) << 16;
		n |= (in_Renamed[++inOff] & 0xff) << 8;
		n |= (in_Renamed[++inOff] & 0xff);
		this.X[this.xOff] = n;
		if (++this.xOff == 16) {
			this.ProcessBlock()
		}
	},
	ProcessLength : function(bitLength) {
		if (this.xOff > 14) {
			this.ProcessBlock()
		}
		this.X[14] = (this.URShiftLong(bitLength, 32));
		this.X[15] = (bitLength & (0xffffffff))
	},
	IntToBigEndian : function(n, bs, off) {
		bs[off] = Int32.parseByte(this.URShift(n, 24));
		bs[++off] = Int32.parseByte(this.URShift(n, 16));
		bs[++off] = Int32.parseByte(this.URShift(n, 8));
		bs[++off] = Int32.parseByte(n)
	},
	DoFinal : function(out_Renamed, outOff) {
		this.Finish();
		for ( var i = 0; i < 8; i++) {
			this.IntToBigEndian(this.v[i], out_Renamed, outOff + i * 4)
		}
		this.Reset();
		//ADD BY longwx js会出现越界，所以跟oxff做与操作, 2016-4-19
		var len = out_Renamed.length;
		for(i=0;i<len;i++){
			out_Renamed[i] &= 0xff;
		}
		
		return this.DIGEST_LENGTH
	},
	Update : function(input) {
		this.xBuf[this.xBufOff++] = input;
		if (this.xBufOff == this.xBuf.length) {
			this.ProcessWord(this.xBuf, 0);
			this.xBufOff = 0
		}
		this.byteCount++
	},
	BlockUpdate : function(input, inOff, length) {
		// while ((this.xBufOff != 0) && (length > 0)) {
		// 	this.Update(input[inOff]);
		// 	inOff++;
		// 	length--
		// }
		// while (length > this.xBuf.length) {
		// 	this.ProcessWord(input, inOff);
		// 	inOff += this.xBuf.length;
		// 	length -= this.xBuf.length;
		// 	this.byteCount += this.xBuf.length
		// }
		// while (length > 0) {
		// 	this.Update(input[inOff]);
		// 	inOff++;
		// 	length--
		// }
        //
        for (var i = 0; i < length; i++) {
            this.Update(input[i + inOff]);
        }
        
	},
	Finish : function() {
		var bitLength = (this.byteCount << 3);
		this.Update((128));
		while (this.xBufOff != 0)
			this.Update((0));
		this.ProcessLength(bitLength);
		this.ProcessBlock()
	},
	ROTATE : function(x, n) {
		return (x << n) | (this.URShift(x, (32 - n)))
	},
	P0 : function(X) {
		return ((X) ^ this.ROTATE((X), 9) ^ this.ROTATE((X), 17))
	},
	P1 : function(X) {
		return ((X) ^ this.ROTATE((X), 15) ^ this.ROTATE((X), 23))
	},
	FF_00_15 : function(X, Y, Z) {
		return (X ^ Y ^ Z)
	},
	FF_16_63 : function(X, Y, Z) {
		return ((X & Y) | (X & Z) | (Y & Z))
	},
	GG_00_15 : function(X, Y, Z) {
		return (X ^ Y ^ Z)
	},
	GG_16_63 : function(X, Y, Z) {
		return ((X & Y) | (~X & Z))
	},
	URShift : function(number, bits) {
		if (number > Int32.maxValue || number < Int32.minValue) {
			number = Int32.parse(number)
		}
		if (number >= 0) {
			return number >> bits
		} else {
			return (number >> bits) + (2 << ~bits)
		}
	},
	URShiftLong : function(number, bits) {
		var returnV;
		var big = new BigInteger();
		big.fromInt(number);
		if (big.signum() >= 0) {
			returnV = big.shiftRight(bits).intValue()
		} else {
			var bigAdd = new BigInteger();
			bigAdd.fromInt(2);
			var shiftLeftBits = ~bits;
			var shiftLeftNumber = '';
			if (shiftLeftBits < 0) {
				var shiftRightBits = 64 + shiftLeftBits;
				for ( var i = 0; i < shiftRightBits; i++) {
					shiftLeftNumber += '0'
				}
				var shiftLeftNumberBigAdd = new BigInteger();
				shiftLeftNumberBigAdd.fromInt(number >> bits);
				var shiftLeftNumberBig = new BigInteger("10" + shiftLeftNumber,
						2);
				shiftLeftNumber = shiftLeftNumberBig.toRadix(10);
				var r = shiftLeftNumberBig.add(shiftLeftNumberBigAdd);
				returnV = r.toRadix(10)
			} else {
				shiftLeftNumber = bigAdd.shiftLeft((~bits)).intValue();
				returnV = (number >> bits) + shiftLeftNumber
			}
		}
		return returnV
	},
	GetZ : function(g, pubKeyHex) {
		var userId = CryptoJS.enc.Utf8.parse("1234567812345678");
		var len = userId.words.length * 4 * 8;
		this.Update((len >> 8 & 0x00ff));
		this.Update((len & 0x00ff));
		var userIdWords = this.GetWords(userId.toString());
		this.BlockUpdate(userIdWords, 0, userIdWords.length);
		var aWords = this.GetWords(g.curve.a.toBigInteger().toRadix(16));
		var bWords = this.GetWords(g.curve.b.toBigInteger().toRadix(16));
		var gxWords = this.GetWords(g.getX().toBigInteger().toRadix(16));
		var gyWords = this.GetWords(g.getY().toBigInteger().toRadix(16));
		var pxWords = this.GetWords(pubKeyHex.substr(0, 64));
		var pyWords = this.GetWords(pubKeyHex.substr(64, 64));
		this.BlockUpdate(aWords, 0, aWords.length);
		this.BlockUpdate(bWords, 0, bWords.length);
		this.BlockUpdate(gxWords, 0, gxWords.length);
		this.BlockUpdate(gyWords, 0, gyWords.length);
		this.BlockUpdate(pxWords, 0, pxWords.length);
		this.BlockUpdate(pyWords, 0, pyWords.length);
		var md = new Array(this.GetDigestSize());
		this.DoFinal(md, 0);
		return md
	},
	GetWords : function(hexStr) {
		var words = [];
		var hexStrLength = hexStr.length;
		for ( var i = 0; i < hexStrLength; i += 2) {
			words[words.length] = parseInt(hexStr.substr(i, 2), 16)
		}
		return words
	},
	GetHex : function(arr) {
		var words = [];
		var j = 0;
		for (var i = 0; i < arr.length * 2; i += 2) {
			words[i >>> 3] |= parseInt(arr[j]) << (24 - (i % 8) * 4);
			j++
		}
		
		var wordArray = new CryptoJS.lib.WordArray.init(words, arr.length);
		return wordArray
	}
};
Array.Clear = function(destinationArray, destinationIndex, length) {
	for (elm in destinationArray) {
		destinationArray[elm] = null
	}
};
Array.Copy = function(sourceArray, sourceIndex, destinationArray,
		destinationIndex, length) {
	var cloneArray = sourceArray.slice(sourceIndex, sourceIndex + length);
	for ( var i = 0; i < cloneArray.length; i++) {
		destinationArray[destinationIndex] = cloneArray[i];
		destinationIndex++
	}
};

this.Int32 = {
    minValue : -parseInt('10000000000000000000000000000000', 2),
    maxValue : parseInt('01111111111111111111111111111111', 2),
    parse : function(n) {
        if (n < this.minValue) {
            var bigInteger = new Number(-n);
            var bigIntegerRadix = bigInteger.toString(2);
            var subBigIntegerRadix = bigIntegerRadix.substr(
                    bigIntegerRadix.length - 31, 31);
            var reBigIntegerRadix = '';
            for ( var i = 0; i < subBigIntegerRadix.length; i++) {
                var subBigIntegerRadixItem = subBigIntegerRadix.substr(i, 1);
                reBigIntegerRadix += subBigIntegerRadixItem == '0' ? '1' : '0'
            }
            var result = parseInt(reBigIntegerRadix, 2);
            return (result + 1)
        } else if (n > this.maxValue) {
            var bigInteger = Number(n);
            var bigIntegerRadix = bigInteger.toString(2);
            var subBigIntegerRadix = bigIntegerRadix.substr(
                    bigIntegerRadix.length - 31, 31);
            var reBigIntegerRadix = '';
            for ( var i = 0; i < subBigIntegerRadix.length; i++) {
                var subBigIntegerRadixItem = subBigIntegerRadix.substr(i, 1);
                reBigIntegerRadix += subBigIntegerRadixItem == '0' ? '1' : '0'
            }
            var result = parseInt(reBigIntegerRadix, 2);
            return -(result + 1)
        } else {
            return n
        }
    },
    parseByte : function(n) {
        if (n < 0) {
            var bigInteger = new Number(-n);
            var bigIntegerRadix = bigInteger.toString(2);
            var subBigIntegerRadix = bigIntegerRadix.substr(
                    bigIntegerRadix.length - 8, 8);
            var reBigIntegerRadix = '';
            for ( var i = 0; i < subBigIntegerRadix.length; i++) {
                var subBigIntegerRadixItem = subBigIntegerRadix.substr(i, 1);
                reBigIntegerRadix += subBigIntegerRadixItem == '0' ? '1' : '0'
            }
            var result = parseInt(reBigIntegerRadix, 2);
            return (result + 1)
        } else if (n > 255) {
            var bigInteger = Number(n);
            var bigIntegerRadix = bigInteger.toString(2);
            return parseInt(bigIntegerRadix.substr(bigIntegerRadix.length - 8,
                    8), 2)
        } else {
            return n
        }
    }
};

/*****sm3-sm2-1.0.js*****/

/*! sm3-sm2-1.0.js (c) Jonllen Peng | http://www.jonllen.com/
 */
/*
 * sm3-sm2-1.0.js
 * 
 * Copyright (c) 2014 Jonllen Peng (www.jonllen.com)
 */
/**
 * @fileOverview
 * @name sm3-sm2-1.0.js
 * @author Jonllen (www.jonllen.com)
 * @version 1.0.0 (2014-06-18)
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * class for SM2 key generation,  sm3WithSM2 signing and verifcation
 * @name KJUR.crypto.SM3withSM2
 * @class class for SM2 key generation,  SM2 signing and verifcation
 * @description
 * <p>
 * CAUTION: Most of the case, you don't need to use this class except
 * for generating an SM2 key pair. Please use {@link KJUR.crypto.Signature} class instead.
 * </p>
 * <p>
 * This class was originally developped by Stefan Thomas for Bitcoin JavaScript library.
 * Currently this class supports following named curves and their aliases.
 * <ul>
 * <li>secp256r1, NIST P-256, P-256, prime256v1 (*)</li>
 * <li>secp256k1 (*)</li>
 * <li>secp384r1, NIST P-384, P-384 (*)</li>
  * <li>sm2</li>
 * </ul>
 * </p>
 */
KJUR.crypto.SM3withSM2 = function(params) {
    var curveName = "sm2";	// curve name default
    var ecparams = null;
    var prvKeyHex = null;
    var pubKeyHex = null;

    var rng = new SecureRandom();

    var P_OVER_FOUR = null;

    this.type = "SM2";

    function implShamirsTrick(P, k, Q, l) {
	var m = Math.max(k.bitLength(), l.bitLength());
	var Z = P.add2D(Q);
	var R = P.curve.getInfinity();

	for (var i = m - 1; i >= 0; --i) {
	    R = R.twice2D();

	    R.z = BigInteger.ONE;

	    if (k.testBit(i)) {
		if (l.testBit(i)) {
		    R = R.add2D(Z);
		} else {
		    R = R.add2D(P);
		}
	    } else {
		if (l.testBit(i)) {
		    R = R.add2D(Q);
		}
	    }
	}
	
	return R;
    };

    //===========================
    // PUBLIC METHODS
    //===========================
    this.getBigRandom = function (limit) {
	return new BigInteger(limit.bitLength(), rng)
	.mod(limit.subtract(BigInteger.ONE))
	.add(BigInteger.ONE)
	;
    };

    this.setNamedCurve = function(curveName) {
	this.ecparams = KJUR.crypto.ECParameterDB.getByName(curveName);
	this.prvKeyHex = null;
	this.pubKeyHex = null;
	this.curveName = curveName;
    }

    this.setPrivateKeyHex = function(prvKeyHex) {
        this.isPrivate = true;
	this.prvKeyHex = prvKeyHex;
    }

    this.setPublicKeyHex = function(pubKeyHex) {
        this.isPublic = true;
	this.pubKeyHex = pubKeyHex;
    }

    /**
     * generate a EC key pair
     * @name generateKeyPairHex
     * @memberOf KJUR.crypto.ECDSA
     * @function
     * @return {Array} associative array of hexadecimal string of private and public key
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.ECDSA({'curve': 'sm2'});
     * var keypair = ec.generateKeyPairHex();
     * var pubhex = keypair.ecpubhex; // hexadecimal string of EC private key (=d)
     * var prvhex = keypair.ecprvhex; // hexadecimal string of EC public key
     */
    this.generateKeyPairHex = function() {
	var biN = this.ecparams['n'];
	var biPrv = this.getBigRandom(biN);
	var epPub = this.ecparams['G'].multiply(biPrv);
	var biX = epPub.getX().toBigInteger();
	var biY = epPub.getY().toBigInteger();

	var charlen = this.ecparams['keylen'] / 4;
	var hPrv = ("0000000000" + biPrv.toString(16)).slice(- charlen);
	var hX   = ("0000000000" + biX.toString(16)).slice(- charlen);
	var hY   = ("0000000000" + biY.toString(16)).slice(- charlen);
	var hPub = "04" + hX + hY;

	this.setPrivateKeyHex(hPrv);
	this.setPublicKeyHex(hPub);
	return {'ecprvhex': hPrv, 'ecpubhex': hPub};
    };

    this.signWithMessageHash = function(hashHex) {
	return this.signHex(hashHex, this.prvKeyHex);
    };

    /**
     * signing to message hash
     * @name signHex
     * @memberOf KJUR.crypto.SM3withSM2
     * @function
     * @param {String} hashHex hexadecimal string of hash value of signing message
     * @param {String} privHex hexadecimal string of EC private key
     * @return {String} hexadecimal string of ECDSA signature
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.SM3withSM2({'curve': 'sm2'});
     * var sigValue = ec.signHex(hash, prvKey);
     */
    this.signHex = function (hashHex, privHex) {
	var d = new BigInteger(privHex, 16);
	var n = this.ecparams['n'];
	var e = new BigInteger(hashHex, 16);
	
	// k BigInteger
    var k = null;
    var kp = null;
    var r = null;
    var s = null;
    var userD = d;
    
    do
    {
        do
        {
			
			var keypair = this.generateKeyPairHex();
			
			k = new BigInteger(keypair.ecprvhex, 16);
			var pubkeyHex = keypair.ecpubhex;
			
  			kp = ECPointFp.decodeFromHex(this.ecparams['curve'], pubkeyHex);

            // r
            r = e.add(kp.getX().toBigInteger());
            r = r.mod(n);
        }
        while (r.equals(BigInteger.ZERO) || r.add(k).equals(n));

        // (1 + dA)~-1
        var da_1 = userD.add(BigInteger.ONE);
        da_1 = da_1.modInverse(n);
        // s
        s = r.multiply(userD);
        s = k.subtract(s).mod(n);
        s = da_1.multiply(s).mod(n);
    }
    while (s.equals(BigInteger.ZERO));
    

	return KJUR.crypto.ECDSA.biRSSigToASN1Sig(r, s);
    };

    this.sign = function (hash, priv) {
	var d = BigInteger.fromByteArrayUnsigned(priv);
	var n = this.ecparams['n'];
	//var e = BigInteger.fromByteArrayUnsigned(hash);
    var e = BigInteger.fromByteArrayUnsigned(hash);

	do {
	    var k = this.getBigRandom(n);
	    var G = this.ecparams['G'];
	    var Q = G.multiply(k);
	    var r = Q.getX().toBigInteger().mod(n);
	} while (r.compareTo(BigInteger.ZERO) <= 0);

	var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
	return this.serializeSig(r, s);
    };

    this.verifyWithMessageHash = function(hashHex, sigHex) {
	return this.verifyHex(hashHex, sigHex, this.pubKeyHex);
    };

    /**
     * verifying signature with message hash and public key
     * @name verifyHex
     * @memberOf KJUR.crypto.SM3withSM2
     * @function
     * @param {String} hashHex hexadecimal string of hash value of signing message
     * @param {String} sigHex hexadecimal string of signature value
     * @param {String} pubkeyHex hexadecimal string of public key
     * @return {Boolean} true if the signature is valid, otherwise false
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.SM3withSM2({'curve': 'sm2'});
     * var result = ec.verifyHex(msgHashHex, sigHex, pubkeyHex);
     */
    this.verifyHex = function(hashHex, sigHex, pubkeyHex) {
	var r,s;

	var obj = KJUR.crypto.ECDSA.parseSigHex(sigHex);
	r = obj.r;
	s = obj.s;

	var Q;
	Q = ECPointFp.decodeFromHex(this.ecparams['curve'], pubkeyHex);
	var e = new BigInteger(hashHex, 16);

	return this.verifyRaw(e, r, s, Q);
    };

    this.verify = function (hash, sig, pubkey) {
	var r,s;
	if (Array.isArray(sig)) { //Bitcoin.Util
	    var obj = this.parseSig(sig);
	    r = obj.r;
	    s = obj.s;
	} else if ("object" === typeof sig && sig.r && sig.s) {
	    r = sig.r;
	    s = sig.s;
	} else {
	    throw "Invalid value for signature";
	}

	var Q;
	if (pubkey instanceof ECPointFp) {
	    Q = pubkey;
	} else if (Array.isArray(pubkey)) { //Bitcoin.Util.isArray
	    Q = ECPointFp.decodeFrom(this.ecparams['curve'], pubkey);
	} else {
	    throw "Invalid format for pubkey value, must be byte array or ECPointFp";
	}
	var e = BigInteger.fromByteArrayUnsigned(hash);

	return this.verifyRaw(e, r, s, Q);
    };

    this.verifyRaw = function (e, r, s, Q) {
	var n = this.ecparams['n'];
	var G = this.ecparams['G'];
	
	var t = r.add(s).mod(n);
    if (t.equals(BigInteger.ZERO))
        return false;
        
    var x1y1 = G.multiply(s);
    x1y1 = x1y1.add(Q.multiply(t));

    var R = e.add(x1y1.getX().toBigInteger()).mod(n);
    return r.equals(R);
    };

    /**
     * Serialize a signature into DER format.
     *
     * Takes two BigIntegers representing r and s and returns a byte array.
     */
    this.serializeSig = function (r, s) {
	var rBa = r.toByteArraySigned();
	var sBa = s.toByteArraySigned();

	var sequence = [];
	sequence.push(0x02); // INTEGER
	sequence.push(rBa.length);
	sequence = sequence.concat(rBa);

	sequence.push(0x02); // INTEGER
	sequence.push(sBa.length);
	sequence = sequence.concat(sBa);

	sequence.unshift(sequence.length);
	sequence.unshift(0x30); // SEQUENCE
	return sequence;
    };

    /**
     * Parses a byte array containing a DER-encoded signature.
     *
     * This function will return an object of the form:
     *
     * {
     *   r: BigInteger,
     *   s: BigInteger
     * }
     */
    this.parseSig = function (sig) {
	var cursor;
	if (sig[0] != 0x30)
	    throw new Error("Signature not a valid DERSequence");

	cursor = 2;
	if (sig[cursor] != 0x02)
	    throw new Error("First element in signature must be a DERInteger");;
	var rBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

	cursor += 2+sig[cursor+1];
	if (sig[cursor] != 0x02)
	    throw new Error("Second element in signature must be a DERInteger");
	var sBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

	cursor += 2+sig[cursor+1];

	//if (cursor != sig.length)
	//  throw new Error("Extra bytes in signature");

	var r = BigInteger.fromByteArrayUnsigned(rBa);
	var s = BigInteger.fromByteArrayUnsigned(sBa);

	return {r: r, s: s};
    };

    this.parseSigCompact = function (sig) {
	if (sig.length !== 65) {
	    throw "Signature has the wrong length";
	}

	// Signature is prefixed with a type byte storing three bits of
	// information.
	var i = sig[0] - 27;
	if (i < 0 || i > 7) {
	    throw "Invalid signature type";
	}

	var n = this.ecparams['n'];
	var r = BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
	var s = BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);

	return {r: r, s: s, i: i};
    };

    if (params !== undefined) {
	if (params['curve'] !== undefined) {
	    this.curveName = params['curve'];
	}
    }
    if (this.curveName === undefined) this.curveName = curveName;
    this.setNamedCurve(this.curveName);
    if (params !== undefined) {
	if (params['prv'] !== undefined) this.setPrivateKeyHex(params['prv']);
	if (params['pub'] !== undefined) this.setPublicKeyHex(params['pub']);
    }
};

/*****ecparam-1.0.js*****/

/*! ecparam-1.0.0.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
/*
 * ecparam.js - Elliptic Curve Cryptography Curve Parameter Definition class
 *
 * Copyright (c) 2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsrsasign/license
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name ecparam-1.1.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 1.0.0 (2013-Jul-17)
 * @since jsrsasign 4.0
 * @license <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * static object for elliptic curve names and parameters
 * @name KJUR.crypto.ECParameterDB
 * @class static object for elliptic curve names and parameters
 * @description
 * This class provides parameters for named elliptic curves.
 * Currently it supoprts following curve names and aliases however 
 * the name marked (*) are available for {@link KJUR.crypto.ECDSA} and
 * {@link KJUR.crypto.Signature} classes.
 * <ul>
 * <li>secp128r1</li>
 * <li>secp160r1</li>
 * <li>secp160k1</li>
 * <li>secp192r1</li>
 * <li>secp192k1</li>
 * <li>secp224r1</li>
 * <li>secp256r1, NIST P-256, P-256, prime256v1 (*)</li>
 * <li>secp256k1 (*)</li>
 * <li>secp384r1, NIST P-384, P-384 (*)</li>
 * <li>secp521r1, NIST P-521, P-521</li>
 * </ul>
 * You can register new curves by using 'register' method.
 */
KJUR.crypto.ECParameterDB = new function() {
    var db = {};
    var aliasDB = {};

    function hex2bi(hex) {
        return new BigInteger(hex, 16);
    }
    
    /**
     * get curve inforamtion associative array for curve name or alias
     * @name getByName
     * @memberOf KJUR.crypto.ECParameterDB
     * @function
     * @param {String} nameOrAlias curve name or alias name
     * @return {Array} associative array of curve parameters
     * @example
     * var param = KJUR.crypto.ECParameterDB.getByName('prime256v1');
     * var keylen = param['keylen'];
     * var n = param['n'];
     */
    this.getByName = function(nameOrAlias) {
	var name = nameOrAlias;
	if (typeof aliasDB[name] != "undefined") {
	    name = aliasDB[nameOrAlias];
        }
	if (typeof db[name] != "undefined") {
	    return db[name];
	}
	throw "unregistered EC curve name: " + name;
    };

    /**
     * register new curve
     * @name regist
     * @memberOf KJUR.crypto.ECParameterDB
     * @function
     * @param {String} name name of curve
     * @param {Integer} keylen key length
     * @param {String} pHex hexadecimal value of p
     * @param {String} aHex hexadecimal value of a
     * @param {String} bHex hexadecimal value of b
     * @param {String} nHex hexadecimal value of n
     * @param {String} hHex hexadecimal value of h
     * @param {String} gxHex hexadecimal value of Gx
     * @param {String} gyHex hexadecimal value of Gy
     * @param {Array} aliasList array of string for curve names aliases
     * @param {String} oid Object Identifier for the curve
     * @param {String} info information string for the curve
     */
    this.regist = function(name, keylen, pHex, aHex, bHex, nHex, hHex, gxHex, gyHex, aliasList, oid, info) {
        db[name] = {};
	var p = hex2bi(pHex);
	var a = hex2bi(aHex);
	var b = hex2bi(bHex);
	var n = hex2bi(nHex);
	var h = hex2bi(hHex);
        var curve = new ECCurveFp(p, a, b);
        var G = curve.decodePointHex("04" + gxHex + gyHex);
	db[name]['name'] = name;
	db[name]['keylen'] = keylen;
        db[name]['curve'] = curve;
        db[name]['G'] = G;
        db[name]['n'] = n;
        db[name]['h'] = h;
        db[name]['oid'] = oid;
        db[name]['info'] = info;

        for (var i = 0; i < aliasList.length; i++) {
	    aliasDB[aliasList[i]] = name;
        }
    };
};

KJUR.crypto.ECParameterDB.regist(
  "secp128r1", // name / p = 2^128 - 2^97 - 1
  128,
  "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", // p
  "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", // a
  "E87579C11079F43DD824993C2CEE5ED3", // b
  "FFFFFFFE0000000075A30D1B9038A115", // n
  "1", // h
  "161FF7528B899B2D0C28607CA52C5B86", // gx
  "CF5AC8395BAFEB13C02DA292DDED7A83", // gy
  [], // alias
  "", // oid (underconstruction)
  "secp128r1 : SECG curve over a 128 bit prime field"); // info

KJUR.crypto.ECParameterDB.regist(
  "secp160k1", // name / p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
  160,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", // p
  "0", // a
  "7", // b
  "0100000000000000000001B8FA16DFAB9ACA16B6B3", // n
  "1", // h
  "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB", // gx
  "938CF935318FDCED6BC28286531733C3F03C4FEE", // gy
  [], // alias
  "", // oid
  "secp160k1 : SECG curve over a 160 bit prime field"); // info

KJUR.crypto.ECParameterDB.regist(
  "secp160r1", // name / p = 2^160 - 2^31 - 1
  160,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", // a
  "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", // b
  "0100000000000000000001F4C8F927AED3CA752257", // n
  "1", // h
  "4A96B5688EF573284664698968C38BB913CBFC82", // gx
  "23A628553168947D59DCC912042351377AC5FB32", // gy
  [], // alias
  "", // oid
  "secp160r1 : SECG curve over a 160 bit prime field"); // info

KJUR.crypto.ECParameterDB.regist(
  "secp192k1", // name / p = 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
  192,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", // p
  "0", // a
  "3", // b
  "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", // n
  "1", // h
  "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", // gx
  "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", // gy
  []); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp192r1", // name / p = 2^192 - 2^64 - 1
  192,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", // a
  "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", // b
  "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", // n
  "1", // h
  "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", // gx
  "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", // gy
  []); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp224r1", // name / p = 2^224 - 2^96 + 1
  224,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", // a
  "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", // b
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", // n
  "1", // h
  "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", // gx
  "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", // gy
  []); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp256k1", // name / p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
  256,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", // p
  "0", // a
  "7", // b
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", // n
  "1", // h
  "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", // gx
  "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", // gy
  []); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp256r1", // name / p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
  256,
  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", // p
  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", // a
  "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", // b
  "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", // n
  "1", // h
  "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", // gx
  "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", // gy
  ["NIST P-256", "P-256", "prime256v1"]); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp384r1", // name
  384,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", // a
  "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", // b
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", // n
  "1", // h
  "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", // gx
  "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", // gy
  ["NIST P-384", "P-384"]); // alias

KJUR.crypto.ECParameterDB.regist(
  "secp521r1", // name
  521,
  "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // p
  "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", // a
  "051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", // b
  "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", // n
  "1", // h
  "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", // gx
  "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", // gy
  ["NIST P-521", "P-521"]); // alias

KJUR.crypto.ECParameterDB.regist(
  "sm2", // name
  256,
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", // p
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", // a
  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", // b
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", // n
  "1", // h
  "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", // gx
  "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", // gy
  ["sm2", "SM2"]); // alias

/*****sm2.js*****/
(function (root) {
    var SM2Cipher = function (cipherMode) {
        //this.logger = null;
    	this.ct = 1;
    	this.p2 = null;
    	this.sm3keybase = null;
    	//this.sm3c3 = null;
        this.dataForc3 = new Array();
    	this.key = new Array(32);
    	this.keyOff = 0;
    	if (typeof (cipherMode) != 'undefined') {
    		this.cipherMode = cipherMode
    	} else {
    		this.cipherMode = SM2CipherMode.C1C3C2
    	}
    }
    SM2Cipher.prototype = {
        /*SetLogger : function(logger) {
            this.logger = logger;
        },
        printLogger : function(title, content) {
            if (this.logger != null) {
                this.logger.value += title + "\n" + content + " \n"
            }
        },*/  //add for test

    	Reset : function() {
    		this.sm3keybase = new SM3Digest();
    		//this.sm3c3 = new SM3Digest();
            this.dataForc3 = new Array();
    		//mod by huangzh 2016-4-14 p2x,p2y小于64位，前面需要补零
    		var p2x = this.p2.getX().toBigInteger().toRadix(16);
    		while(p2x.length<64){
    			p2x = "0"+p2x;
    		}
    		var xWords = this.GetWords(p2x);
    		var p2y = this.p2.getY().toBigInteger().toRadix(16);
    		while(p2y.length<64){
    			p2y = "0"+p2y;
    		}
    		var yWords = this.GetWords(p2y);
    		this.sm3keybase.BlockUpdate(xWords, 0, xWords.length);
    		//this.sm3c3.BlockUpdate(xWords, 0, xWords.length);
            for (var i = 0; i < xWords.length; i++) {
                this.dataForc3.push(xWords[i]);
            }
    		this.sm3keybase.BlockUpdate(yWords, 0, yWords.length);
    		this.ct = 1;
    		this.NextKey()
    	},
    	NextKey : function() {
    		var sm3keycur = new SM3Digest(this.sm3keybase);
    		sm3keycur.Update((this.ct >> 24 & 0x00ff));
    		sm3keycur.Update((this.ct >> 16 & 0x00ff));
    		sm3keycur.Update((this.ct >> 8 & 0x00ff));
    		sm3keycur.Update((this.ct & 0x00ff));
    		sm3keycur.DoFinal(this.key, 0);
    		this.keyOff = 0;
    		this.ct++
    	},
    	ArrayCopy : function(arr1, arr2, offset) {
            for(var i = 0; i < arr1.length; i++){
                if (arr2.length > (i+offset)) {
                    arr2[i+offset] = arr1[i];
                }else{
                    arr2.push(arr1[i]);
                }
            }
        },
        // add by longwx 2016.01.05
        KDF : function(len) {
            var t = new Array(len);
            //var sm3 = new SM3Digest();
            var SM3 = KeyouCryptography.algorithm.SM3;
            var sm3Ret = new Array(32);
            var ct = 1;
            var value = len / 32;
            var remainder = len % 32;
            //mod by huangzh 2016-4-14 p2x,p2y小于64位，前面需要补零
            var p2x = this.p2.getX().toBigInteger().toRadix(16);
            while(p2x.length<64){
                p2x = "0"+p2x;
            }
            var xWords = this.GetWords(p2x);
            var p2y = this.p2.getY().toBigInteger().toRadix(16);
            while(p2y.length<64){
                p2y = "0"+p2y;
            }
            var yWords = this.GetWords(p2y);
            var offset = 0;
            for (var i = 0; i < value; i++) {
                var data = new Array();
                for (var i = 0; i < xWords.length; i++) {
                    data.push(xWords[i]);
                }
                for (var i = 0; i < xWords.length; i++) {
                    data.push(yWords[i]);
                }
                data.push(ct >> 24 & 0x00ff);
                data.push(ct >> 16 & 0x00ff);
                data.push(ct >> 8 & 0x00ff);
                data.push(ct & 0x00ff);
                var temp = SM3.digest(data);
                this.ArrayCopy(temp, t, offset);
                offset += 32;
                ct++;
            }
            if (remainder != 0) {
                var data = new Array();
                for (var i = 0; i < xWords.length; i++) {
                    data.push(xWords[i]);
                }
                for (var i = 0; i < xWords.length; i++) {
                    data.push(yWords[i]);
                }
                data.push(ct >> 24 & 0x00ff);
                data.push(ct >> 16 & 0x00ff);
                data.push(ct >> 8 & 0x00ff);
                data.push(ct & 0x00ff);
                var temp = SM3.digest(data);
                this.ArrayCopy(temp, sm3Ret, 0);
            }
            Array.Copy(sm3Ret, 0, t, offset, remainder);
            
            for(var i = 0; i < t.length; i++) {
                t[i] = t[i] & 0xff;
            }
            return t;
        },
    	InitEncipher : function(userKey) {
    		var k = null;
    		var c1 = null;
    		var ec = new KJUR.crypto.ECDSA({
    			"curve" : "sm2"
    		});
    		var keypair = ec.generateKeyPairHex();
    		k = new BigInteger(keypair.ecprvhex, 16);
    		var pubkeyHex = keypair.ecpubhex;
    		c1 = ECPointFp.decodeFromHex(ec.ecparams['curve'], pubkeyHex);
    		this.p2 = userKey.multiply(k);
    		this.Reset();
    		return c1
    	},
    	EncryptBlock : function(data) {
            for (var i = 0; i < data.length; i++) {
                this.dataForc3.push(data[i]);
            }
    		//this.sm3c3.BlockUpdate(data, 0, data.length);
    		// del by longwx 2016.01.05
    		// for (var i = 0; i < data.length; i++) {
    		// if (this.keyOff == this.key.length) {
    		// this.NextKey()
    		// }
    		// data[i] ^= this.key[this.keyOff++]
    		// }
    		var t = this.KDF(data.length);
    		for (var i = 0; i < data.length; i++) {
    			data[i] ^= t[i];
                //useless for gft_TV by wx
                //data[i] = this.XORForTV(data[i], t[i]);
    		}
    	},
    	InitDecipher : function(userD, c1) {
    		this.p2 = c1.multiply(userD);	
    		var xWords = this.p2.getX().toBigInteger().toRadix(16);
    		var yWords = this.p2.getY().toBigInteger().toRadix(16);
    		this.Reset()
    	},
    	DecryptBlock : function(data) {
    		// del by longwx 2016.01.05
    		// for (var i = 0; i < data.length; i++) {
    		// if (this.keyOff == this.key.length) {
    		// this.NextKey()
    		// }
    		// data[i] ^= this.key[this.keyOff++]
    		// }
    		var t = this.KDF(data.length);	
    		var i = 0;
    		var temp ='';
    		for(i=0;i<t.length;i++){
    			temp +=t[i].toString(16);
    		}
    		for (var i = 0; i < data.length; i++) {
    			data[i] ^= t[i];
    		}
            for (var i = 0; i < data.length; i++) {
                this.dataForc3.push(data[i]);
            }
    		//this.sm3c3.BlockUpdate(data, 0, data.length)
    	},
    	Dofinal : function(c3) {
    		//mod by huangzh 2016-4-14 p2y小于64位，前面需要补零
    		var p2y = this.p2.getY().toBigInteger().toRadix(16);
    		while(p2y.length<64){
    			p2y = "0"+p2y;
    		}
    		var yWords = this.GetWords(p2y);
            //this.printLogger("after GetWords() yWords is ",yWords)
            var SM3 = KeyouCryptography.algorithm.SM3;

    		//this.sm3c3.BlockUpdate(yWords, 0, yWords.length);
            for (var i = 0; i < yWords.length; i++) {
                this.dataForc3.push(yWords[i]);
            }
    		var temp = SM3.digest(this.dataForc3);
            this.ArrayCopy(temp, c3, 0);
    		this.Reset()
    	},
    	Encrypt : function(pubKey, plaintext) {
    		
    		var data = new Array(plaintext.length);
    		Array.Copy(plaintext, 0, data, 0, plaintext.length);
    		var c1 = this.InitEncipher(pubKey);
    		this.EncryptBlock(data);
            //this.printLogger("after EncryptBlock() data is ",data)
    		var c3 = new Array(32);
    		this.Dofinal(c3);
            //this.printLogger("after Dofinal() c3 is ",c3)

    		// add by longwx 2016.01.04
    		var pubKeyX = c1.getX().toBigInteger().toRadix(16);
    		var pubKeyY = c1.getY().toBigInteger().toRadix(16);
    		while (pubKeyX.length < 64) {
    			pubKeyX = "0" + pubKeyX;
    		}
    		while (pubKeyY.length < 64) {
    			pubKeyY = "0" + pubKeyY;
    		}
    		var c1Hex = pubKeyX + pubKeyY;
    		var c2Hex = this.GetHex(data).toString();
    		if (c2Hex.length % 2 != 0) {
    			c2Hex = "0" + c2Hex;
    		}
    		var c3Hex = this.GetHex(c3).toString();

    		var hexString = c1Hex + c2Hex + c3Hex;
    		if (this.cipherMode == SM2CipherMode.C1C3C2) {
    			hexString = c1Hex + c3Hex + c2Hex;
    		}
    		return hexString
    	},
    	GetWords : function(hexStr) {
    		var words = [];
    		var hexStrLength = hexStr.length;
    		for (var i = 0; i < hexStrLength; i += 2) {
    			words[words.length] = parseInt(hexStr.substr(i, 2), 16);
    		}
    		return words;
    	},
    	GetHex : function(arr) {
    		var words = [];
    		var j = 0;
    		for (var i = 0; i < arr.length * 2; i += 2) {
    			words[i >>> 3] |= parseInt(arr[j]) << (24 - (i % 8) * 4);
    			j++
    		}
    		
    		var wordArray = new CryptoJS.lib.WordArray.init(words, arr.length);
    		return wordArray
    		 
    	},
    	Decrypt : function(privateKey, ciphertext) {
    		// var privateKey = new BigInteger(key, 16);
    		var hexString = ciphertext;
    		var c1X = hexString.substr(0, 64);
    		var c1Y = hexString.substr(0 + c1X.length, 64);
    		var encrypData = hexString.substr(c1X.length + c1Y.length,
    				hexString.length - c1X.length - c1Y.length - 64);
    		var c3 = hexString.substr(hexString.length - 64);
    		if (this.cipherMode == SM2CipherMode.C1C3C2) {
    			c3 = hexString.substr(c1X.length + c1Y.length, 64);
    			encrypData = hexString.substr(c1X.length + c1Y.length + 64)
    		}
    		var data = this.GetWords(encrypData);
    		var c1 = this.CreatePoint(c1X, c1Y);
    		this.InitDecipher(privateKey, c1);
    		this.DecryptBlock(data);

    		var c3_ = new Array(32);
    		
    		this.Dofinal(c3_);
    		var isDecrypt = this.GetHex(c3_).toString() == c3;
    		
    		if (isDecrypt) {
    			var wordArray = this.GetHex(data);
                // 直接返回16进制值
    			//var decryptData = CryptoJS.enc.Utf8.stringify(wordArray);
    			return wordArray.toString();
    		} else {
    			return '';
    		}
    	},
    	CreatePoint : function(x, y) {
    		var ec = new KJUR.crypto.ECDSA({
    			"curve" : "sm2"
    		});
    		var ecc_curve = ec.ecparams['curve'];
    		var pubkeyHex = '04' + x + y;
    		var point = ECPointFp.decodeFromHex(ec.ecparams['curve'], pubkeyHex);
    		return point
    	},
        XORForTV : function(x, y) {//贵服通机顶盒一代 异或运算替换函数 已废弃 
            var bitStr1 = x.toString(2);
            var bitStr2 = y.toString(2);
            var xArray = bitStr1.split("");
            var yArray = bitStr2.split("");
            var str = "";
            if (xArray.length >= yArray.length ) {
                for (var i = xArray.length; i > 0; i--) {
                    var index = xArray.length - i;
                    if (yArray.length < i) {
                        str += xArray[index];
                        continue;
                    }
                    var range = xArray.length - yArray.length;
                    if (xArray[index] == yArray[index - range]) {
                        str += '0';
                    }else{
                        str += '1';
                    }
                }
            }
            else{
                for (var i = yArray.length; i > 0; i--) {
                    var index = yArray.length - i;
                    if (xArray.length < i) {
                        str += yArray[index];
                        continue;
                    }
                    var range = yArray.length - xArray.length;
                    if (xArray[index - range] == yArray[index]) {
                        str += '0';
                    }else{
                        str += '1';
                    }
                }
            }
           
            var result = parseInt(str, 2);
            return result;
        }
    };
    root.SM2Cipher = SM2Cipher;
}(this));

this.SM2CipherMode = {
    C1C2C3 : '0',
    C1C3C2 : '1'
};

;
        /**
 * @required core.js
 * @required lib.js
 * @required hex.js
 * @required checker.js
 */
(function () {
    var KA = KeyouCryptography.algorithm;
    var Hex = KeyouCryptography.util.Hex;
    var Checker = KeyouCryptography.util.Checker;

    /**
     * SM2 国密非对称加密算法
     */
    var SM2 = KA.SM2 = (function () {

        var SM2_KEY_SIZE = 32;

        var SM2_C1_SIZE = 64;

        var SM2_C3_SIZE = 32;

        return {

            /**
             * 生成 SM2 公私钥对
             * 
             * @return {Object} 返回 SM2 密钥对，publicKey 中存放了 SM2 算法的公钥值，privateKey 中存放了 SM2 算法的私钥值
             *
             * @static
             *
             * @example
             *
             *      var keypair = KeyouCryptography.algorithm.SM2.generate()
             *      var publicKey = KeyouCryptography.util.Hex.stringify(keypair.publicKey)
             *      var privateKey = KeyouCryptography.util.Hex.stringify(keypair.privateKey)
             */
            generate: function () {
                var curve = 'SM2';
                var ec = new KJUR.crypto.ECDSA({
                    "curve": curve
                })
                var keypair = ec.generateKeyPairHex();
                return {
                    publicKey: Hex.parse(keypair.ecpubhex.substring(2, 130)),
                    privateKey: Hex.parse(keypair.ecprvhex)
                }
            },

            /**
             * SM2 公钥加密数据
             * 
             * @param  {Uint8Arrary} plaintext 二进制的明文数据
             * @param  {Uint8Array} publicKey 二进制的 SM2 公钥值，由 X + Y 构成，长度为 96 bytes
             * 
             * @return {Uint8Array}           二进制的密文数据，长度为明文数据长度加 96
             *
             * @throws {IllegalArgumentException} 参数错误
             *
             * @static
             *
             * @example
             *
             *      var plaintext = KeyouCryptography.util.Hex.parse("1231231Acdefb312423defb");
             *      var publicKey = KeyouCryptography.util.Hex.parse("C5F171CC415C5C2759FE4668F51C0D7DA2CB85AE754F29135FED90D50C3B437D2EEA0F54163C3880C13618FF0F7CA67201DFF244016F09F19F7C1EC5D4033546");
             *      var ciphertext = KeyouCryptography.algorithm.SM2.encrypt(plaintext, publicKey);
             */
            encrypt: function (plaintext, publicKey) {
                Checker.checkNotEmpty(plaintext, "plaintext is empty.");
                Checker.checkNotEmpty(publicKey, "publicKey is empty.");
                Checker.checkArgument(publicKey.length == 2 * SM2_KEY_SIZE, "illegal SM2 public key:" + Hex.stringify(publicKey));
                var key = Hex.stringify(publicKey);

                var x = key.substring(0, SM2_KEY_SIZE * 2);
                var y = key.substring(SM2_KEY_SIZE * 2, SM2_KEY_SIZE * 4);
                var mode = SM2CipherMode.C1C3C2;
                var cipher = new SM2Cipher(mode);
                var point = cipher.CreatePoint(x, y);
                var ciphertext = cipher.Encrypt(point, plaintext);
                return Hex.parse(ciphertext);
            },

            /**
             * SM2 私钥解密数据
             * 
             * @param  {Uint8Array} ciphertext 二进制的密文数据
             * @param  {Uint8Array} privateKey 二进制的 SM2 私钥，长度为 32 bytes
             * 
             * @return {Uint8Array}            二进制的明文数据，长度为密文数据长度 - 96
             *
             * @throws {IllegalArgumentException} 参数错误
             *
             * @static
             *
             * @example
             *
             *      var ciphertext = KeyouCryptography.util.Hex.parse("");
             *      var privateKey = KeyouCryptography.util.Hex.parse("32803B68C49C9285F31577ACA17B7EE92E0828707F12FF8EE74442F75D68C5C8");
             *      var plaintext = KeyouCryptography.algorithm.SM2.decrypt(ciphertext, privateKey);
             */
            decrypt: function (ciphertext, privateKey) {
                Checker.checkArgument(ciphertext != undefined && ciphertext.length > 0, "illegal ciphertext:" + Hex.stringify(ciphertext));
                Checker.checkArgument(privateKey != undefined && privateKey.length == SM2_KEY_SIZE, "illegal SM2 public key:" + Hex.stringify(privateKey));
                var hexCipher = Hex.stringify(ciphertext).toLowerCase();

                var mode = SM2CipherMode.C1C3C2;
                var cipher = new SM2Cipher(mode);
                var key = new BigInteger(Hex.stringify(privateKey), 16);
                var plaintext = cipher.Decrypt(key, hexCipher);     
                return Hex.parse(plaintext);
            },

            sign: function (data, privateKey) {
                Checker.checkArgument(data != undefined && data.length > 0, "illegal data:" + Hex.stringify(data));
                //var ec = KJUR.crypto.SM3withSM2({'curve': 'SM2'});
                var ec = new KJUR.crypto.ECDSA({
                    "curve": 'SM2'
                })
                var sigValue = ec.sign(data, privateKey);
                return sigValue;
            },

            verify: function (data, sig, pubkey) {
                //var ec = KJUR.crypto.SM3withSM2({'curve': 'SM2'});
                var ec = new KJUR.crypto.ECDSA({
                    "curve": 'SM2'
                })
                var verify = ec.verify(data, sig, pubkey);
                return verify;
            },

            signWithoutHash:function(data, privateKey) {
                var ec = new KJUR.crypto.ECDSA({
                    "curve": 'SM2'
                })
                var sigValue = ec.signWithoutHash(data, privateKey);
                return sigValue;
            },

            verifyWithoutHash: function(data, sig, pubkey) {
                var ec = new KJUR.crypto.ECDSA({
                    "curve": 'SM2'
                })
                var verify = ec.verifyWithoutHash(data, sig, pubkey);
                return verify;
            },

            name: "SM2 algorithm",

            mode: "C1C3C2",

            testKeypair: {
                publicKey: "C5F171CC415C5C2759FE4668F51C0D7DA2CB85AE754F29135FED90D50C3B437D2EEA0F54163C3880C13618FF0F7CA67201DFF244016F09F19F7C1EC5D4033546",

                privateKey: "32803B68C49C9285F31577ACA17B7EE92E0828707F12FF8EE74442F75D68C5C8"
            },

            SM2_KEY_SIZE: SM2_KEY_SIZE
        };

    }()); 
}());;
    

    
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
    

    
        /**
 * @required core.js
 * @required checker.js
 */
(function () {
    var KA = KeyouCryptography.algorithm;
    var Checker = KeyouCryptography.util.Checker;

    /**
     * SM4 国密对称加密算法
     */
    var SM4 = KA.SM4 = (function () {

        var ENCRYPT_MODE = 0;

        var DECRYPT_MODE = 1;

        var BLOCK_SIZE = 16;
        
        var Sbox = [ 0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
                     0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
                     0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
                     0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
                     0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
                     0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
                     0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
                     0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
                     0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
                     0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
                     0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
                     0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
                     0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
                     0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
                     0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
                     0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48 
                   ];

               
        var CK = [ 0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
                   0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
                   0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
                   0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
                   0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
                   0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
                   0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
                   0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
                 ];
        
             
        var FK = [ 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC ];
        
        
        function rollLeftMove(word, counts) {
            return (word << counts) | (word >>> (32 - counts));
        }
        
        
        function transformL(word) {
            return word ^ rollLeftMove(word, 2) ^ rollLeftMove(word, 10)
                    ^ rollLeftMove(word, 18) ^ rollLeftMove(word, 24);
        }
        
        
        function transformLEX(word) {
            return word ^ rollLeftMove(word, 13) ^ rollLeftMove(word, 23);
        }
        
        
        function transformT(word) {
            return ((Sbox[(word >>> 24) & 0xFF] & 0xFF) << 24) | ((Sbox[(word >>> 16) & 0xFF] & 0xFF) << 16)
                    | ((Sbox[(word >>> 8) & 0xFF] & 0xFF) << 8) | (Sbox[word & 0xFF] & 0xFF);
        }
        
        
        function compSwapT(word, flag) {
            if(flag) {
                return transformL(transformT(word));
            } else {
                return transformLEX(transformT(word));
            }
        }
        
        
        function roundF(x0, x1, x2, x3, rk) {
            return x0 ^ compSwapT(x1 ^ x2 ^ x3 ^ rk, true);
        }
        
        function generateRK(key) {
            var rk = new Array(32);
            var mk = new Array(4);
            for(var i = 0; i < 4; i++) {
                mk[i] = fourBytesToOneWord(key, i * 4);
            }
            var k = new Array(4);
            for(var i = 0; i < 4; i++) {
                k[i] = mk[i] ^ FK[i];
            }
            for(var i = 0; i < 32; i += 4) {
                rk[i] = k[0] = k[0] ^ compSwapT(k[1] ^ k[2] ^ k[3] ^ CK[i], false);
                rk[i + 1] = k[1] = k[1] ^ compSwapT(k[2] ^ k[3] ^ k[0] ^ CK[i + 1], false);
                rk[i + 2] = k[2] = k[2] ^ compSwapT(k[3] ^ k[0] ^ k[1] ^ CK[i + 2], false);
                rk[i + 3] = k[3] = k[3] ^ compSwapT(k[0] ^ k[1] ^ k[2] ^ CK[i + 3], false);
            }
            return rk;
        }
        
        
        function cryptBlock(input, inOffset, output, outOffset, rk, cipherMode) {
            var x = new Array(4);
            for(var i = 0; i < 4; i++) {
                x[i] = fourBytesToOneWord(input, inOffset + i * 4);
            }
            for(var i = 0; i < 32; i += 4) {
                if(cipherMode == ENCRYPT_MODE) {
                    x[0] = roundF(x[0], x[1], x[2], x[3], rk[i]);
                    x[1] = roundF(x[1], x[2], x[3], x[0], rk[i + 1]);
                    x[2] = roundF(x[2], x[3], x[0], x[1], rk[i + 2]);
                    x[3] = roundF(x[3], x[0], x[1], x[2], rk[i + 3]);
                } else {
                    x[0] = roundF(x[0], x[1], x[2], x[3], rk[31 - i]);
                    x[1] = roundF(x[1], x[2], x[3], x[0], rk[30 - i]);
                    x[2] = roundF(x[2], x[3], x[0], x[1], rk[29 - i]);
                    x[3] = roundF(x[3], x[0], x[1], x[2], rk[28 - i]);
                }
            }
            for(var i = 0; i < 4; i++) {
                oneWordToFourBytes(x[3 - i], output, outOffset + i * 4);
            }
        }
        
        
        function fourBytesToOneWord(byteArray, offset) {
            return ((byteArray[offset] & 0x000000ff) << 24)
            | ((byteArray[offset + 1] & 0x000000ff) << 16)
            | ((byteArray[offset + 2] & 0x000000ff) << 8)
            | (byteArray[offset + 3] & 0x000000ff);
        }
        
        
        function oneWordToFourBytes(word, byteArray, offset) {
            byteArray[offset] = (word & 0xff000000) >>> 24;
            byteArray[offset+1] = (word & 0x00ff0000) >>> 16;
            byteArray[offset+2] = (word & 0x0000ff00) >>> 8;
            byteArray[offset+3] = word & 0x000000ff;
        }

        var XOR = function (data, iv) {
            var xor = new Array(BLOCK_SIZE);
            for (var i = 0; i < BLOCK_SIZE; i++) {
                xor[i] = data[i] ^ iv[i];
            }
            return xor;
        }

        var Copy = function (src, srcOffset, des, desOffset, length) {
            for (var i = 0; i < length; i++) {
                des[i + desOffset] = src[i + srcOffset];
            }
            return src;
        }

        return {
            name: "SM4 algorithm",

            // 密钥长度 16 bytes
            KEY_SIZE: BLOCK_SIZE,

            /**
             * SM4 ECB 模式加密数据
             * 
             * @param  {Uint8Array} plaintext 二进制的明文数据字节数组，数据长度必须是 16 的倍数
             * @param  {Uint8Array} key       二进制的 SM4 密钥，长度为 16 字节
             * 
             * @return {Uint8Array}           二进制的密文字节数组
             *
             * @throws {IllegalArgumentException} 参数错误
             *
             * @static
             *
             * @example
             *
             *      var plaintext = KeyouCryptography.util.Hex.parse("12345678901234560987654321098765")
             *      var key = KeyouCryptography.util.Hex.parse("ABCDEF12345678900987654321ABCDEF");
             *      var ciphertext = KeyouCryptography.algorithm.SM4.encryptWithECB(plaintext, key);
             *      assert(KeyouCryptography.util.Hex.stringify(ciphertext) === "73b369d0b366daa87a9f3a08698b3b24")
             */
            encryptWithECB: function (plaintext, key) {
                Checker.checkArgument(typeof(plaintext) != "undefined" && plaintext.length % BLOCK_SIZE === 0, 
                    "illegal plaintext:the length of plaintext must be the multiple of 16.");
                Checker.checkArgument(typeof(key) != "undefined" && key.length === BLOCK_SIZE,
                    "illegal key:the length of sm4Key must be 16 bytes.");

                var rk = generateRK(key);
                var length = plaintext.length;
                var ciphertext = new Array(length);
                var offset = 0;
                while(offset < length) {
                    cryptBlock(plaintext, offset, ciphertext, offset, rk, ENCRYPT_MODE);
                    offset += 16;
                }
                return ciphertext;
            },

            /**
             * SM4 ECB 模式解密数据
             * 
             * @param  {Uint8Array} ciphertext 二进制的密文字节数组，长度必须为 16 的倍数
             * @param  {Uint8Array} key        二进制的 SM4 密钥，长度为 16 字节
             * 
             * @return {Uint8Array}            二进制的明文字节数组
             *
             * @throws {IllegalArgumentException} 参数错误
             *
             * @static
             *
             * @example
             *
             *      var ciphertext = KeyouCryptography.util.Hex.parse("73b369d0b366daa87a9f3a08698b3b24")
             *      var key = KeyouCryptography.util.Hex.parse("ABCDEF12345678900987654321ABCDEF");
             *      var plaintext = KeyouCryptography.algorithm.SM4.decryptWithECB(ciphertext, key);
             *      assert(KeyouCryptography.util.Hex.stringify(plaintext) === "12345678901234560987654321098765")
             */
            decryptWithECB: function (ciphertext, key) {
                Checker.checkArgument(typeof(ciphertext) != "undefined" && ciphertext.length % BLOCK_SIZE === 0, 
                    "illegal ciphertext:the length of ciphertext must be the multiple of 16.");
                Checker.checkArgument(typeof(key) != "undefined" && key.length === BLOCK_SIZE,
                    "illegal key:the length of sm4Key must be 16 bytes.");

                var rk = generateRK(key);
                var plaintext = new Array(ciphertext.length);
                var offset = 0;
                while(offset < ciphertext.length) {
                    cryptBlock(ciphertext, offset, plaintext, offset, rk, DECRYPT_MODE);
                    offset += 16;
                }
                return plaintext;
            },

            encryptWithCBC: function (data, key, iv) {
                Checker.checkArgument(typeof(data) != undefined && data.length % BLOCK_SIZE == 0, 
                    "illegal plaintext:the length of plaintext must be the multiple of 16.")
                Checker.checkArgument(typeof(key) != "undefined" && key.length === BLOCK_SIZE,
                    "illegal key:the length of sm4Key must be 16 bytes.");
                Checker.checkArgument(typeof(iv) != "undefined" && iv.length === BLOCK_SIZE,
                    "illegal iv:the length of sm4 iv must be 16 bytes.");
                
                var rk = generateRK(key);
                var output = new Array(data.length);
                for (var i = 0; i < data.length; i += 16) {
                    var d = data.slice(i, i + 16);
                    var xor = XOR(d, iv);
                    var out = new Array(BLOCK_SIZE);
                    cryptBlock(xor, 0, out, 0, rk, ENCRYPT_MODE);
                    Copy(out, 0, output, i, BLOCK_SIZE);
                    iv = out;
                }
                return output;
            },

            decryptWithCBC: function (data, key, iv) {
                Checker.checkArgument(typeof(data) != undefined && data.length % BLOCK_SIZE == 0, 
                    "illegal plaintext:the length of plaintext must be the multiple of 16.")
                Checker.checkArgument(typeof(key) != "undefined" && key.length === BLOCK_SIZE,
                    "illegal key:the length of sm4Key must be 16 bytes.");
                Checker.checkArgument(typeof(iv) != "undefined" && iv.length === BLOCK_SIZE,
                    "illegal iv:the length of sm4 iv must be 16 bytes.");

                var rk = generateRK(key);
                var output = new Array(data.length);
                for (var i = 0; i < data.length; i += 16) {
                    var d = data.slice(i, i + 16);
                    var out = new Array(BLOCK_SIZE);
                    cryptBlock(d, 0, out, 0, rk, DECRYPT_MODE);
                    var xor = XOR(out, iv);
                    iv = data.slice(i, i + 16);
                    Copy(xor, 0, output, i, BLOCK_SIZE);
                }
                return output;
            }
        };
    }());
}());;
    

    

    
    
    

    
    

    

    

    

    
    
    
    
    return KeyouCryptography;
}));