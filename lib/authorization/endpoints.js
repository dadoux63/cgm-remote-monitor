'use strict';

var _ = require('lodash');
var express = require('express');
var forwarded = require('forwarded-for');

var consts = require('./../constants');

function getRemoteIP (req) {
  return forwarded(req, req.headers).ip;
}

function auditLog (action, req, details) {
  var ip = getRemoteIP(req);
  var subject = req.subject ? req.subject.name : 'unknown';
  console.info('[AUDIT]', new Date().toISOString(), 'action=' + action, 'subject=' + subject, 'ip=' + ip, JSON.stringify(details || {}));
}

function init (env, authorization) {
  var endpoints = express( );

  var wares = require('./../middleware/index')(env);

  endpoints.use(wares.sendJSONStatus);
  // text body types get handled as raw buffer stream
  endpoints.use(wares.bodyParser.raw());
  // json body types get handled as parsed json
  endpoints.use(wares.bodyParser.json());
  // also support url-encoded content-type
  endpoints.use(wares.bodyParser.urlencoded({ extended: true }));

  endpoints.get('/request/:accessToken', function requestAuthorize (req, res) {
    var authorized = authorization.authorize(req.params.accessToken);

    if (authorized) {
      res.json(authorized);
    } else {
      res.sendJSONStatus(res, consts.HTTP_UNAUTHORIZED, 'Unauthorized', 'Invalid/Missing');
    }
  });

  endpoints.get('/permissions', authorization.isPermitted('admin:api:permissions:read'), function getSubjects (req, res) {
    res.json(authorization.seenPermissions);
  });

  endpoints.get('/permissions/trie', authorization.isPermitted('admin:api:permissions:read'), function getSubjects (req, res) {
    res.json(authorization.expandedPermissions());
  });

  endpoints.get('/subjects', authorization.isPermitted('admin:api:subjects:read'), function getSubjects (req, res) {
    res.json(_.map(authorization.storage.subjects, function eachSubject (subject) {
      return _.pick(subject, ['_id', 'name', 'accessToken', 'roles']);
    }));
  });

  endpoints.post('/subjects', authorization.isPermitted('admin:api:subjects:create'), function createSubject (req, res) {
    auditLog('subjects:create', req, { name: req.body && req.body.name });
    authorization.storage.createSubject(req.body, function created (err, created) {
      if (err) {
        res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'Mongo Error', err);
      } else {
        res.json(created);
      }
    });
  });

  endpoints.put('/subjects', authorization.isPermitted('admin:api:subjects:update'), function saveSubject (req, res) {
    auditLog('subjects:update', req, { _id: req.body && req.body._id, name: req.body && req.body.name });
    authorization.storage.saveSubject(req.body, function saved (err, saved) {
      if (err) {
        res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'Mongo Error', err);
      } else {
        res.json(saved);
      }
    });
  });

  endpoints.delete('/subjects/:_id', authorization.isPermitted('admin:api:subjects:delete'), function deleteSubject (req, res) {
    auditLog('subjects:delete', req, { _id: req.params._id });
    authorization.storage.removeSubject(req.params._id, function deleted (err) {
      if (err) {
        res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'Mongo Error', err);
      } else {
        res.json({ });
      }
    });
  });

  endpoints.get('/roles', authorization.isPermitted('admin:api:roles:list'), function getRoles (req, res) {
    res.json(authorization.storage.roles);
  });

  endpoints.post('/roles', authorization.isPermitted('admin:api:roles:create'), function createSubject (req, res) {
    auditLog('roles:create', req, { name: req.body && req.body.name });
    authorization.storage.createRole(req.body, function created (err, created) {
      if (err) {
        res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'Mongo Error', err);
      } else {
        res.json(created);
      }
    });
  });

  endpoints.put('/roles', authorization.isPermitted('admin:api:roles:update'), function saveRole (req, res) {
    auditLog('roles:update', req, { _id: req.body && req.body._id, name: req.body && req.body.name });
    authorization.storage.saveRole(req.body, function saved (err, saved) {
      if (err) {
        res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'Mongo Error', err);
      } else {
        res.json(saved);
      }
    });
  });

  endpoints.delete('/roles/:_id', authorization.isPermitted('admin:api:roles:delete'), function deleteRole (req, res) {
    auditLog('roles:delete', req, { _id: req.params._id });
    authorization.storage.removeRole(req.params._id, function deleted (err) {
      if (err) {
        res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'Mongo Error', err);
      } else {
        res.json({ });
      }
    });
  });

  return endpoints;
}

module.exports = init;
