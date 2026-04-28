const baseX = require('base-x').default;
const uuid = require('uuid');

const base62 = baseX('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');

module.exports = {
  v4: () => (
    base62.encode(
      Buffer.from(
        uuid.v4().replace(/-/g, ''), 'hex')
    )
  )
};
