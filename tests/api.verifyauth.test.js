'use strict';

var request = require('supertest');
var language = require('../lib/language')();

require('should');

describe('Verifyauth REST api', function ( ) {
  var self = this;
  
  this.timeout(10000);
  var known = '53c518a05766fff2241444d377d73379ca8fdea4718fb79985ace86662e459f0';

  var api = require('../lib/api/');
  before(function (done) {
    delete process.env.API_SECRET;
    process.env.API_SECRET = 'this is my long pass phrase';
    self.env = require('../lib/server/env')( );
    self.env.settings.authDefaultRoles = 'denied';
    this.wares = require('../lib/middleware/')(self.env);
    self.app = require('express')( );
    self.app.enable('api');
    require('../lib/server/bootevent')(self.env, language).boot(function booted (ctx) {
      self.app.use('/api', api(self.env, ctx));
      done();
    });
  });

  it('/verifyauth should return UNAUTHORIZED', function (done) {
    request(self.app)
      .get('/api/verifyauth')
      .expect(200)
      .end(function(err, res) {
        res.body.message.message.should.equal('UNAUTHORIZED');
        done();
      });
  });

  it('/verifyauth should return OK', function (done) {
    request(self.app)
      .get('/api/verifyauth')
      .set('api-secret', known || '')
      .expect(200)
      .end(function(err, res) {
        res.body.message.message.should.equal('OK');
        done();
      });
  });


});

