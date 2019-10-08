/*
Software Security - Cryptography challenge
Ahraoui Anas
*/


// Load sodium-wrappers module
const sodium = require('libsodium-wrappers');
let keypair = null;
let loadLibsodium = async () => await sodium.ready;

// Generates a public and secret key)
(async () => {
    await loadLibsodium();
    keypair = sodium.crypto_sign_keypair();
})();

// Verifies the keypair if ok => return public key
module.exports.verifyingKey = async function verifyingKey() {
    await loadLibsodium();
    return keypair.publicKey;
};

// Apply pk of the pair to message
module.exports.sign = async function sign(msg) {
    return sodium.crypto_sign(msg, keypair.privateKey);
};

//Bronnen:
// https://github.com/wilhelmmatilainen/natrium
// https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures
// https://www.npmjs.com/package/libsodium-wrappers
