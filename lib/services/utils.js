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

function fixKeyLength(key, keyLength) {
  return Buffer.concat([Buffer.from(key), Buffer.alloc(keyLength)], keyLength);
}

function encrypt(text) {
  const { algorithm, cipherKey } = config.systemConfig.crypto;
  const { ivLength, keyLength } = crypto.getCipherInfo(algorithm);
  const iv = crypto.randomBytes(ivLength);
  const key = fixKeyLength(cipherKey, keyLength);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt (password) {
  const { algorithm, cipherKey } = config.systemConfig.crypto;
  const { keyLength } = crypto.getCipherInfo(algorithm);
  const [iv, encryptedText] = password.split(':');
  const key = fixKeyLength(cipherKey, keyLength);
  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(Buffer.from(encryptedText, 'hex'));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
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
