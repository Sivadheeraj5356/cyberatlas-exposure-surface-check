const test = require('node:test');
const assert = require('node:assert/strict');
const { check } = require('../exposure.js');
const codes = (r) => r.findings.map((f) => f.code);

test('flags public database port', () => {
  assert.ok(codes(check('db.example.com | 5432 | PostgreSQL 14 ready')).includes('DATABASE_PORT_PUBLIC'));
});

test('does not flag a normal web port', () => {
  assert.ok(!codes(check('www.example.com | 443 | nginx https')).includes('DATABASE_PORT_PUBLIC'));
});

test('flags admin panel without auth hint', () => {
  assert.ok(codes(check('ops.example.com | 443 | Grafana dashboard v10')).includes('ADMIN_PANEL_NO_AUTH_HINT'));
});

test('does not flag admin panel with login hint', () => {
  assert.ok(!codes(check('ops.example.com | 443 | Grafana dashboard - login required')).includes('ADMIN_PANEL_NO_AUTH_HINT'));
});

test('flags dev host visible in scan', () => {
  assert.ok(codes(check('staging.example.com | 443 | nginx')).includes('DEV_HOST_PUBLIC'));
});

test('flags TLS issue and legacy service', () => {
  const r = check('mail.example.com | 443 | cert expired 2024\nold.example.com | 23 | telnet banner');
  assert.ok(codes(r).includes('TLS_ISSUE'));
  assert.ok(codes(r).includes('LEGACY_PLAINTEXT_SERVICE'));
});

test('clean surface passes', () => {
  const r = check('www.example.com | 443 | nginx https\napi.example.com | 443 | envoy https');
  assert.deepEqual(codes(r), ['SURFACE_CLEAN']);
  assert.equal(r.stats.hosts, 2);
});
