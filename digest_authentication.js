function parseAuthorization(header) {
    let ixDigest = header.indexOf('Digest');
    let value = header.substring(ixDigest + 6);
    let parts = value.split(',');
    let map = {};
    for (let part of parts) {
        part = part.trim();
        let ixEquals = part.indexOf('=');
        let key = part.substring(0, ixEquals).trim();
        let val = part.substring(ixEquals + 1).trim();
        if (val.startsWith('"'))
            val = val.substring(1, val.length - 1);
        map[key] = val;
    }
    return map;
}

function calculateResponse({ method, map, body }, { username, password }) {
    // HA1 = MD5(A1) = MD5(username:realm:password).
    let ha1 = calculateMD5(`${username}:${map.realm}:${password}`);

    let a2;
    let ha2;

    // "auth", "auth-int", ""
    let response;
    if (map.qop === 'auth') {
        // HA2 = MD5(A2) = MD5(method:digestURI).
        a2 = `${method}:${map.uri}`;
        ha2 = calculateMD5(a2);
        // Response = MD5(HA1:nonce:nonceCount:credentialsNonce:qop:HA2).
        response = calculateMD5(`${ha1}:${map.nonce}:${map.nc}:${map.cnonce}:auth:${ha2}`);
    } else if (map.qop === 'auth-int') {
        // HA2 = MD5(A2) = MD5(method:digestURI:MD5(entityBody)).
        a2 = `${method}:${map.uri}:${calculateMD5(body ? body : '')}`;
        ha2 = calculateMD5(a2);
        // Response = MD5(HA1:nonce:nonceCount:credentialsNonce:qop:HA2).
        response = calculateMD5(`${ha1}:${map.nonce}:${map.nc}:${map.cnonce}:auth-int:${ha2}`);
    } else if (map.qop === null) {
        // HA2 = MD5(A2) = MD5(method:digestURI).
        a2 = `${method}:${map.uri}`;
        ha2 = calculateMD5(a2);
        // Response = MD5(HA1:nonce:HA2).
        response = calculateMD5(`${ha1}:${map.nonce}:${ha2}`);
    }
    return response;
}

// MD5 (Message-Digest Algorithm) https://www.webtoolkit.info.
function calculateMD5(string) {
    function rotateLeft(lValue, iShiftBits) {
        return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }

    function addUnsigned(lX, lY) {
        const lX8 = (lX & 0x80000000);
        const lY8 = (lY & 0x80000000);
        const lX4 = (lX & 0x40000000);
        const lY4 = (lY & 0x40000000);
        const lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);

        if (lX4 & lY4) {
            return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        }
        if (lX4 | lY4) {
            if (lResult & 0x40000000) {
                return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            }
            else {
                return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
            }
        }
        else {
            return (lResult ^ lX8 ^ lY8);
        }
    }

    function doF(x, y, z) {
        return (x & y) | ((~x) & z);
    }

    function doG(x, y, z) {
        return (x & z) | (y & (~z));
    }

    function doH(x, y, z) {
        return (x ^ y ^ z);
    }

    function doI(x, y, z) {
        return (y ^ (x | (~z)));
    }

    function doFF(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(doF(b, c, d), x), ac));

        return addUnsigned(rotateLeft(a, s), b);
    }

    function doGG(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(doG(b, c, d), x), ac));

        return addUnsigned(rotateLeft(a, s), b);
    }

    function doHH(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(doH(b, c, d), x), ac));

        return addUnsigned(rotateLeft(a, s), b);
    }

    function doII(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(doI(b, c, d), x), ac));

        return addUnsigned(rotateLeft(a, s), b);
    }

    function convertToWordArray(str) {
        let lWordCount;
        const lMessageLength = str.length;
        const lNumberOfWords_temp1 = lMessageLength + 8;
        const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
        const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
        const lWordArray = new Array(lNumberOfWords - 1);
        let lBytePosition = 0;
        let lByteCount = 0;

        while (lByteCount < lMessageLength) {
            lWordCount = (lByteCount - (lByteCount % 4)) / 4;
            lBytePosition = (lByteCount % 4) * 8;
            lWordArray[lWordCount] = (lWordArray[lWordCount] |
                (str.charCodeAt(lByteCount) << lBytePosition));
            lByteCount++;
        }
        lWordCount = (lByteCount - (lByteCount % 4)) / 4;
        lBytePosition = (lByteCount % 4) * 8;
        lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
        lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
        lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;

        return lWordArray;
    }

    function wordToHex(lValue) {
        let wordToHexValue = '', wordToHexValue_temp = '', lByte, lCount;

        for (lCount = 0; lCount <= 3; lCount++) {
            lByte = (lValue >>> (lCount * 8)) & 255;
            wordToHexValue_temp = `0${lByte.toString(16)}`;
            wordToHexValue = wordToHexValue +
                wordToHexValue_temp.substr(wordToHexValue_temp.length - 2, 2);
        }

        return wordToHexValue;
    }

    function utf8Encode(str) {
        // Igor's fix to correctly calculate auth-int
        // str = str.replace(/\r\n/g, '\n');
        let utftext = '';

        for (let n = 0; n < str.length; n++) {
            const c = str.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            }
            else if ((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            }
            else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }
        }

        return utftext;
    }

    let x = [];
    let k, AA, BB, CC, DD, a, b, c, d;
    const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
    const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
    const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
    const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

    string = utf8Encode(string);

    x = convertToWordArray(string);

    a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;

    for (k = 0; k < x.length; k += 16) {
        AA = a; BB = b; CC = c; DD = d;
        a = doFF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
        d = doFF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
        c = doFF(c, d, a, b, x[k + 2], S13, 0x242070DB);
        b = doFF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
        a = doFF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
        d = doFF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
        c = doFF(c, d, a, b, x[k + 6], S13, 0xA8304613);
        b = doFF(b, c, d, a, x[k + 7], S14, 0xFD469501);
        a = doFF(a, b, c, d, x[k + 8], S11, 0x698098D8);
        d = doFF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
        c = doFF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
        b = doFF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
        a = doFF(a, b, c, d, x[k + 12], S11, 0x6B901122);
        d = doFF(d, a, b, c, x[k + 13], S12, 0xFD987193);
        c = doFF(c, d, a, b, x[k + 14], S13, 0xA679438E);
        b = doFF(b, c, d, a, x[k + 15], S14, 0x49B40821);
        a = doGG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
        d = doGG(d, a, b, c, x[k + 6], S22, 0xC040B340);
        c = doGG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
        b = doGG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
        a = doGG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
        d = doGG(d, a, b, c, x[k + 10], S22, 0x2441453);
        c = doGG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
        b = doGG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
        a = doGG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
        d = doGG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
        c = doGG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
        b = doGG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
        a = doGG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
        d = doGG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
        c = doGG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
        b = doGG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
        a = doHH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
        d = doHH(d, a, b, c, x[k + 8], S32, 0x8771F681);
        c = doHH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
        b = doHH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
        a = doHH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
        d = doHH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
        c = doHH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
        b = doHH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
        a = doHH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
        d = doHH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
        c = doHH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
        b = doHH(b, c, d, a, x[k + 6], S34, 0x4881D05);
        a = doHH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
        d = doHH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
        c = doHH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
        b = doHH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
        a = doII(a, b, c, d, x[k + 0], S41, 0xF4292244);
        d = doII(d, a, b, c, x[k + 7], S42, 0x432AFF97);
        c = doII(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
        b = doII(b, c, d, a, x[k + 5], S44, 0xFC93A039);
        a = doII(a, b, c, d, x[k + 12], S41, 0x655B59C3);
        d = doII(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
        c = doII(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
        b = doII(b, c, d, a, x[k + 1], S44, 0x85845DD1);
        a = doII(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
        d = doII(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
        c = doII(c, d, a, b, x[k + 6], S43, 0xA3014314);
        b = doII(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
        a = doII(a, b, c, d, x[k + 4], S41, 0xF7537E82);
        d = doII(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
        c = doII(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
        b = doII(b, c, d, a, x[k + 9], S44, 0xEB86D391);
        a = addUnsigned(a, AA);
        b = addUnsigned(b, BB);
        c = addUnsigned(c, CC);
        d = addUnsigned(d, DD);
    }

    const temp = wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d);

    return temp.toLowerCase();
}

export { parseAuthorization, calculateResponse };