/*
Usage: frida -p <pid> -l PyCrypto_hook.js

Hook <AESNI_start_operation> from <_raw_aesni.pyd> to get the key
Hook mode_encrypt or mode_decrypt from _raw_mode.pyd to get the message content
Hook mode_start_operation to get iv
For example, hook <CBC_decrypt> from <_raw_cbc.pyd> if CBC mode is used in the Python code

References:
- https://github.com/Legrandin/pycryptodome/blob/master/src/AESNI.c#L382
- https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Cipher/AES.py#L127
- https://github.com/Legrandin/pycryptodome/blob/master/src/raw_cbc.c#L114
- https://github.com/Legrandin/pycryptodome/blob/master/src/raw_cbc.c#L47
*/

var aesModes = ['_raw_ecb', '_raw_cbc', '_raw_cfb', '_raw_ofb', '_raw_ctr', '_raw_ocb'];
var AESNI = null;
var AES_start_operation = null;
var AESNI_start_operation = null;
var key = null;
var iv = null;
var nonce = null;
var secret = null;
/*
var payload = null;
var alg = null;
var action = null;
*/


function resetSpec() {
    key = null;
    iv = null;
    nonce = null;
    secret = null;
}


function onDisplay(t_action, t_payload, t_alg) {
    console.warn(`\n[*] AES called from => ${JSON.stringify({
        method: t_action, key: key, iv: iv, payload: t_payload, nonce: nonce, secret: secret, alg: t_alg })}`);
    resetSpec();
}


function pretty(argBytes) {
  const hexArray = [...new Uint8Array(argBytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'));
  const hexString = hexArray.join('');
  const byteArray = hexArray.map((hex) => parseInt(hex, 16));
  return {
    hexArray: hexArray,
    hexString: hexString,
    byteArray: byteArray
  };
}


function formatSpec(arg, argLen) {
  var formattedKey = "0x";
  var isAscii = true;
  var isZero = false;
  var argBytes = Memory.readByteArray(arg, argLen);
  var formattedArray = pretty(argBytes);
  const argHexString = formattedArray.hexString;
  const argBytesArray = formattedArray.byteArray;
  //    var argString =  Memory.readCString(arg);
  for (var i = 0; i < argBytesArray.length; i++) {
    var byte = argBytesArray[i];
    if (byte < 32 || byte > 126) {
        isAscii = false;
    }
  }
  if (!isAscii) {
    //  return Memory.readCString(arg);
    return formattedKey + argHexString; //   Display non readable content as hexadecimal string
  }
  return Memory.readCString(arg);
}


function findModule(moduleName) {
    // Find a module from its name regarding the OS running Frida
    var modules = Process.enumerateModulesSync();
    for (var i = 0; i < modules.length; i++) {
        var module = modules[i];
        if (module.name.indexOf(moduleName) > -1) {
            return module;
        }
    }
    return null;
}


function findExportedFunction(module, functionName) {
    var exports = module.enumerateExports();
    for (var i = 0; i < exports.length; i++) {
      var exported = exports[i];
      //    console.log(exported.name);
      if (exported.name.indexOf(functionName) > -1) return exported;
    }
    return false;
}


function getCipherKey() {
  //    Retrieve AES key by hooking AESNI function. If not, swap to <AES_start_operation>
  AESNI_start_operation = findExportedFunction(AESNI, "AESNI_start_operation");
  if (AESNI_start_operation == null) {
    // TODO: Implement AES_start_operation, similar to NI
    return false;
  }
  Interceptor.attach(AESNI_start_operation.address, {
      onEnter: function (args) {
        var keyPtr = args[0];
        var keyLen = args[1].toInt32();
        key = formatSpec(keyPtr, keyLen);
      }
    });
}


function hookVariousEncryption() {
    var exportedFunctions = [];
    aesModes.forEach(function (moduleName) {
        let module = findModule(moduleName);
        if (module) {
            let mode_encrypt = findExportedFunction(module, "_encrypt");
            let mode_decrypt = findExportedFunction(module, "_decrypt");
            let mode_start_operation = findExportedFunction(module, "_start_operation");
            if (mode_encrypt) exportedFunctions.push(mode_encrypt);
            if (mode_decrypt) exportedFunctions.push(mode_decrypt);
            if (mode_start_operation) exportedFunctions.push(mode_start_operation);
        }
    });
    exportedFunctions.forEach(function (aesFunction) {
        Interceptor.attach(aesFunction.address, {
            onEnter: function (args) {
                if (aesFunction.name.indexOf('start_operation') > -1) {
                    var ivPtr = args[1];
                    var ivLen = args[2].toInt32();
                    iv = formatSpec(ivPtr, ivLen);
                } else {
                    var doMethod = aesFunction.name.split("_");
                    var alg = doMethod[0];
                    var action = doMethod[1];
                    var payloadPtr = args[1];
                    var payloadLen = args[3].toInt32();
                    var payload = formatSpec(payloadPtr, payloadLen);
                    onDisplay(action, payload, alg);
                }
            }
        });
    });
}


function searchVariousEncryption() {
    AESNI = findModule("_raw_aesni");
    if (AESNI == null) {
        console.error("[*] PyCrypto reference not found !");
        return false;
    }
    console.warn(`[*] PyCrypto reference found at ${AESNI.base}`);
    getCipherKey();
    hookVariousEncryption();
}


searchVariousEncryption();
