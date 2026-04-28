const { randomUUID } = require('crypto');
const baseX = require('base-x').default;

const base62 = baseX('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');

module.exports = {
  v4: () => (
    base62.encode(
      Buffer.from(
        randomUUID().replace(/-/g, ''), 'hex')
    )
  )
};
