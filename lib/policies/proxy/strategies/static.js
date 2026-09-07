const { parseUrl } = require('../../../services/utils');

module.exports = class StaticProxy {
  constructor (proxyOptions, endpoints) {
    this.proxyOptions = proxyOptions;
    this.endpoints = endpoints;
    this.target = parseUrl(this.endpoints[0]);
  }

  nextTarget () {
    return Object.assign({}, this.proxyOptions.target, this.target);
  }
};
