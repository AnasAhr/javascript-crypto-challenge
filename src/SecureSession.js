// Ahraoui Anas
// Netwerk & Security

// Load sodium-wrappers module
const sodium = require('libsodium-wrappers');

var rx = null;
var tx = null;
var privateKey = null;
var publicKey = null;
var clientPublicKey = null;

module.exports.setClientPublicKey = function(key) {
	// Check if Client public key is already set
	if (clientPublicKey === key) return;

	// Disable the ability to modify the client public key
	if (clientPublicKey !== null && clientPublicKey !== key) throw 'client public key already set';

	clientPublicKey = key;

	// Generate server key exchange keypair
	const keypair = sodium.crypto_kx_keypair();
	privateKey = keypair.privateKey;
	publicKey = keypair.publicKey;

	// Generate shared keys
	sharedKeys = sodium.crypto_kx_server_session_keys(publicKey, privateKey, key);

	// Set rx + tx
	rx = sharedKeys.sharedRx;
	tx = sharedKeys.sharedTx;
};

module.exports.serverPublicKey = async function() {
	await sodium.ready;

	// Return pk
	return publicKey;
};

module.exports.encrypt = async function(msg) {
	await sodium.ready;

	// Generate nonce + encrypt
	nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
	ciphertext = sodium.crypto_secretbox_easy(msg, nonce, tx);

	// Return cipher + nonce
	return { ciphertext, nonce };
};

module.exports.decrypt = async function(ciphertext, nonce) {
	await sodium.ready;

	// Await + decrypt the message given then cipher & nonce, encoder
	return await sodium.crypto_secretbox_open_easy(ciphertext, nonce, rx);
};




// Sources:
// https://github.com/wilhelmmatilainen/natrium
// https://libsodium.gitbook.io/doc/key_exchange
// https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption
