const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const config = require('../config');

function appendCreatedAt (obj) {
  Object.assign(obj, {
    createdAt: (new Date()).toString()
  });
}

function appendUpdatedAt (obj) {
  Object.assign(obj, {
    updatedAt: (new Date()).toString()
  });
}

// derive a key from system configuration for encrypt/decrypt
const encryptionKey = (function() {
  const { algorithm, cipherKey, cipherSalt } = config.systemConfig.crypto;
  const { keyLength } = crypto.getCipherInfo(algorithm);
  return crypto.scryptSync(cipherKey, cipherSalt, keyLength);
})();

function encrypt(text) {
  const { algorithm } = config.systemConfig.crypto;
  const { ivLength } = crypto.getCipherInfo(algorithm);

  // create initialization vector and a Cipheriv instance to encrypt data
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);

  // run cipher
  let encrypted = cipher.update(Buffer.from(text, 'utf8'));
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  // combine iv and encrypted text in to cipher text
  return Buffer.concat([iv, encrypted]).toString('hex');
}

function decrypt (ciphertext) {
  const { algorithm } = config.systemConfig.crypto;
  const { ivLength } = crypto.getCipherInfo(algorithm);

  // split into initialization vector and encrypted text
  const b = Buffer.from(ciphertext, 'hex');
  const iv = b.subarray(0, ivLength);
  const encrypted = b.subarray(ivLength);

  // create a Decipheriv instance to decrypt data
  const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);

  // run decipher
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString('utf8');
}

function compareSaltAndHashed (password, hash) {
  return (!password || !hash) ? null : bcrypt.compare(password, hash);
}

function saltAndHash (password) {
  if (!password || typeof password !== 'string') {
    return Promise.reject(new Error('invalid arguments'));
  }

  return bcrypt
    .genSalt(config.systemConfig.crypto.saltRounds)
    .then((salt) => bcrypt.hash(password, salt));
}

module.exports = {
  appendCreatedAt,
  appendUpdatedAt,
  encrypt,
  decrypt,
  compareSaltAndHashed,
  saltAndHash
};
