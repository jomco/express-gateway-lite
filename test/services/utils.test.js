require('should');
const utils = require('../../lib/services/utils');

describe('Encrypt / decrypt', function () {
  it('should encrypt to a ciphertext', () => {
    const text = 'some random text';
    utils.encrypt(text).should.not.eql(text);
  });

  it('should decrypt what is encrypted', () => {
    const text = 'some random text';
    const ciphertext = utils.encrypt(text);
    utils.decrypt(ciphertext).should.eql(text);
  });
});
