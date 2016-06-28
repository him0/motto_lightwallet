var Address = {};

function PassSHA3(password, count) {
	var data = password;
	for (var i = 0; i < count; ++i) {
		data = CryptoJS.SHA3(data, {
			outputLength: 256
		});
	}
	var r = CryptoJS.enc.Hex.stringify(data);
	return r;
}

function calcPrivkey(p) {
	var privatekey = PassSHA3(p, 6000);
	return privatekey;
}

function hashfunc(dest, data, dataLength) {
	var convertedData = ua2words(data, dataLength);
	var hash = CryptoJS.SHA3(convertedData, {
		outputLength: 512
	});
	words2ua(dest, hash);
}

function hex2a(hexx) {
	var hex = hexx.toString();
	var str = '';
	for (var i = 0; i < hex.length; i += 2) str += String.fromCharCode(parseInt(
		hex.substr(i, 2), 16));
	return str;
}

function b32decode(s) {
	var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	var r = new ArrayBuffer(s.length * 5 / 8);
	var b = new Uint8Array(r);
	for (var j = 0; j < s.length / 8; j++) {
		var v = [0, 0, 0, 0, 0, 0, 0, 0];
		for (var i = 0; i < 8; ++i) {
			v[i] = alphabet.indexOf(s[j * 8 + i]);
		}
		var i = 0;
		b[j * 5 + 0] = (v[i + 0] << 3) | (v[i + 1] >> 2);
		b[j * 5 + 1] = ((v[i + 1] & 0x3) << 6) | (v[i + 2] << 1) | (v[i + 3] >> 4);
		b[j * 5 + 2] = ((v[i + 3] & 0xf) << 4) | (v[i + 4] >> 1);
		b[j * 5 + 3] = ((v[i + 4] & 0x1) << 7) | (v[i + 5] << 2) | (v[i + 6] >> 3);
		b[j * 5 + 4] = ((v[i + 6] & 0x7) << 5) | (v[i + 7]);
	}
	return b;
}

function b32encode(s) {
	/* encodes a string s to base32 and returns the encoded string */
	var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	var parts = [];
	var quanta = Math.floor((s.length / 5));
	var leftover = s.length % 5;
	if (leftover != 0) {
		for (var i = 0; i < (5 - leftover); i++) {
			s += '\x00';
		}
		quanta += 1;
	}
	for (i = 0; i < quanta; i++) {
		parts.push(alphabet.charAt(s.charCodeAt(i * 5) >> 3));
		parts.push(alphabet.charAt(((s.charCodeAt(i * 5) & 0x07) << 2) | (s.charCodeAt(
			i * 5 + 1) >> 6)));
		parts.push(alphabet.charAt(((s.charCodeAt(i * 5 + 1) & 0x3F) >> 1)));
		parts.push(alphabet.charAt(((s.charCodeAt(i * 5 + 1) & 0x01) << 4) | (s.charCodeAt(
			i * 5 + 2) >> 4)));
		parts.push(alphabet.charAt(((s.charCodeAt(i * 5 + 2) & 0x0F) << 1) | (s.charCodeAt(
			i * 5 + 3) >> 7)));
		parts.push(alphabet.charAt(((s.charCodeAt(i * 5 + 3) & 0x7F) >> 2)));
		parts.push(alphabet.charAt(((s.charCodeAt(i * 5 + 3) & 0x03) << 3) | (s.charCodeAt(
			i * 5 + 4) >> 5)));
		parts.push(alphabet.charAt(((s.charCodeAt(i * 5 + 4) & 0x1F))));
	}
	var replace = 0;
	if (leftover == 1) replace = 6;
	else if (leftover == 2) replace = 4;
	else if (leftover == 3) replace = 3;
	else if (leftover == 4) replace = 1;
	for (i = 0; i < replace; i++) parts.pop();
	for (i = 0; i < replace; i++) parts.push("=");
	return parts.join("");
}
Address.toAddress = function(publicKey, networkId) {
	var binPubKey = CryptoJS.enc.Hex.parse(publicKey);
	var hash = CryptoJS.SHA3(binPubKey, {
		outputLength: 256
	});
	var hash2 = CryptoJS.RIPEMD160(hash);
	// 98 is for testnet
	var networkPrefix = (networkId === -104) ? '98' : (networkId === 104 ? '68' :
		'60');
	var versionPrefixedRipemd160Hash = networkPrefix + CryptoJS.enc.Hex.stringify(
		hash2);
	var tempHash = CryptoJS.SHA3(CryptoJS.enc.Hex.parse(
		versionPrefixedRipemd160Hash), {
		outputLength: 256
	});
	var stepThreeChecksum = CryptoJS.enc.Hex.stringify(tempHash).substr(0, 8);
	var concatStepThreeAndStepSix = hex2a(versionPrefixedRipemd160Hash +
		stepThreeChecksum);
	var ret = b32encode(concatStepThreeAndStepSix);
	var buff = "";
	for (var i = 0; i < 6; i++) {
		var replacestr = ret.slice(0, 6);
		ret = ret.replace(replacestr, "");
		buff += replacestr + "-";
	}
	buff += ret;
	return buff;
}
Address.getaddress = function(privkey, type) {
	var kp = KeyPair.create(privkey);
	return Address.toAddress(kp.publicKey.toString(), type);
}
Address.isValid = function(_address) {
	var address = Address.format(_address);
	if (!address || address.length !== 40) {
		return false;
	}
	var decoded = ua2hex(b32decode(address));
	var versionPrefixedRipemd160Hash = CryptoJS.enc.Hex.parse(decoded.slice(0, 42));
	var tempHash = CryptoJS.SHA3(versionPrefixedRipemd160Hash, {
		outputLength: 256
	});
	var stepThreeChecksum = CryptoJS.enc.Hex.stringify(tempHash).substr(0, 8);
	return stepThreeChecksum === decoded.slice(42);
}
Address.format = function(address) {
	return address.toString().toUpperCase().replace(/-/g, '');
}
Address.formatfordisplay = function(_address) {
	var buff = "";
	for (var i = 0; i < 6; i++) {
		var replacestr = _address.slice(0, 6);
		_address = _address.replace(replacestr, "");
		buff += replacestr + "-";
	}
	buff += _address;
	return buff;
}
Address.cut = function(address) {
	return address.slice(0,13) + "...";
}
function decode(recipientPrivate, senderPublic, payload) {
        var binPayload = hex2ua(payload);
        var salt = new Uint8Array(binPayload.buffer, 0, 32);
        var iv = new Uint8Array(binPayload.buffer, 32, 16);
        var payload = new Uint8Array(binPayload.buffer, 48);

        var sk = hex2ua_reversed(recipientPrivate);
        var pk = hex2ua(senderPublic);
        var shared = new Uint8Array(32);
        var r = key_derive(shared, salt, sk, pk);

        var encKey = r;
        var encIv = { iv: ua2words(iv, 16) };

        var encrypted = {'ciphertext':ua2words(payload, payload.length)};
        var plain = CryptoJS.AES.decrypt(encrypted, encKey, encIv);
        var hexplain = CryptoJS.enc.Hex.stringify(plain);
        return hexplain;
}

function toDoubleDigits(num) {
  num += "";
  if (num.length === 1)num = "0" + num;
 return num;     
}
function toLocaltime(nemtime) {
  var date = new Date(nemtime * 1000 + NEM_EPOCH);
  var yyyy = date.getFullYear();
  var mm = toDoubleDigits(date.getMonth() + 1);
  var dd = toDoubleDigits(date.getDate());
  var hh = toDoubleDigits(date.getHours());
  var mi = toDoubleDigits(date.getMinutes());
  var ss = toDoubleDigits(date.getSeconds());
  return yyyy + '/' + mm + '/' + dd + ' ' + hh + ':' + mi + ':' + ss;
}
function fmtHexToUtf8(data) {
	if (data === undefined) return data;
	var o = data;
	if (o && o.length > 2 && o[0]==='f' && o[1]==='e') {
		return "HEX:" + o.slice(2);
	}
	return decodeURIComponent(escape( hex2a(o) ));
}
function string_to_utf8_hex_string(text){
	var bytes1 = string_to_utf8_bytes(text);
	var hex_str1 = bytes_to_hex_string(bytes1);
	return hex_str1;
}
function utf8_hex_string_to_string(hex_str1){
	var bytes2 = hex_string_to_bytes(hex_str1);
	var str2 = utf8_bytes_to_string(bytes2);
	return str2;
}
function string_to_utf8_bytes(text){
    var result = [];
    if (text == null)
        return result;
    for (var i = 0; i < text.length; i++) {
        var c = text.charCodeAt(i);
        if (c <= 0x7f) {
            result.push(c);
        } else if (c <= 0x07ff) {
            result.push(((c >> 6) & 0x1F) | 0xC0);
            result.push((c & 0x3F) | 0x80);
        } else {
            result.push(((c >> 12) & 0x0F) | 0xE0);
            result.push(((c >> 6) & 0x3F) | 0x80);
            result.push((c & 0x3F) | 0x80);
        }
    }
    return result;
}
function byte_to_hex(byte_num){
	var digits = (byte_num).toString(16);
    if (byte_num < 16) return '0' + digits;
    return digits;
}
function bytes_to_hex_string(bytes){
	var	result = "";
	for (var i = 0; i < bytes.length; i++) {
		result += byte_to_hex(bytes[i]);
	}
	return result;
}
