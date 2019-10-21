/*
Software Security - Cryptography challenge
Ahraoui Anas
*/


// load sodium-wrappers module
const sodium = require('libsodium-wrappers');
let key = null;

// generates a key
module.exports.setKey = async function setKey(newKey) {
    key = newKey;
}
// decrypts the encrypted message only if you have the key
module.exports.decrypt = async function decrypt(ciphertext, nonce) {
    if (key == null) {
        throw 'no key found';
    }
    else {
        return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
    }
}

//Bronnen:
// https://github.com/wilhelmmatilainen/natrium
// https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures
// https://www.npmjs.com/package/libsodium-wrappers
