const session = require('supertest-session');
const should = require('should');
const express = require('express');
const sinon = require('sinon');
const assert = require('assert');

const logger = require('../../lib/policies/log/instance');
const db = require('../../lib/db');

const testHelper = require('../common/routing.helper');
const config = require('../../lib/config');
const originalGatewayConfig = config.gatewayConfig;

describe('E2E: proxy, log, expression, rate-limit policies', () => {
  const helper = testHelper();
  const spy = sinon.spy();
  let app, backendServer;

  before('setup', (done) => {
    sinon.spy(logger, 'info');

    config.gatewayConfig = {
      http: { port: 0 },
      serviceEndpoints: {
        backend: {
          url: 'http://localhost:7777'
        }
      },
      apiEndpoints: {
        testEndpoint: {
          host: '*',
          paths: ['/test']
        }
      },
      policies: ['proxy', 'log', 'expression', 'rate-limit'],
      pipelines: {
        pipeline1: {
          apiEndpoints: ['testEndpoint'],
          policies: [
            {
              expression: {
                action: {
                  jscode: 'req.url = req.url + "/67"'
                }
              }
            },
            {
              log: [
                {
                  action: {
                    // eslint-disable-next-line no-template-curly-in-string
                    message: '${req.url} ${egContext.req.method}'
                  }
                },
                {
                  condition: {
                    name: 'never'
                  },
                  action: {
                    // eslint-disable-next-line no-template-curly-in-string
                    message: '${req.url} ${egContext.req.method}'
                  }
                }
              ]
            },
            {
              'rate-limit': {
                action: {
                  max: 1,
                  // eslint-disable-next-line no-template-curly-in-string
                  rateLimitBy: '${req.hostname}'
                }
              }
            },
            {
              proxy: {
                action: { serviceEndpoint: 'backend' }
              }
            }
          ]
        }
      }
    };

    db
      .flushdb()
      .then(() => helper.setup())
      .then(apps => {
        app = apps.app;

        const backendApp = express();
        backendApp.all('{*path}', (req, res) => {
          spy(req.headers);
          res.send();
        });

        const runningBackendApp = backendApp.listen(7777, () => {
          backendServer = runningBackendApp;
          done();
        });
      })
      .catch(done);
  });

  after('cleanup', () => {
    config.gatewayConfig = originalGatewayConfig;
    logger.info.restore();
    backendServer.close();
    return helper.cleanup();
  });

  it('should execute proxy, log, expression, rate-limit policies and return 200', function (done) {
    const request = session(app);

    request
      .get('/test')
      .expect(200)
      .end(function (err) {
        should.not.exist(err);
        assert(spy.calledOnce);
        assert.strictEqual(logger.info.getCall(0).args[0], '/test/67 GET');
        should.not.exist(logger.info.getCall(1));
        done();
      });
  });

  it('should execute proxy, log, expression, rate-limit policies and return 429 as rate limit is reached', function (done) {
    const request = session(app);

    request
      .get('/test')
      .expect(429)
      .end(function (err) {
        should.not.exist(err);
        assert(spy.calledOnce);
        assert.strictEqual(logger.info.getCall(1).args[0], '/test/67 GET');
        done();
      });
  });
});
