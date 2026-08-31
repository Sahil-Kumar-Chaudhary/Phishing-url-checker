import test from 'node:test';
import assert from 'node:assert/strict';

import {
  validateHostnameForNetwork,
  validateNetworkTarget,
  isBlockedIpAddress,
} from '../lib/security/networkValidation.ts';

test('blocks localhost and private IPv4 destinations', async () => {
  const blocked = [
    'localhost',
    '127.0.0.1',
    '10.0.0.1',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '::1',
    'fc00::1',
    'fe80::1',
  ];

  for (const target of blocked) {
    const result = await validateHostnameForNetwork(target);
    assert.equal(result.ok, false, `${target} should be rejected`);
  }
});

test('allows public hosts', async () => {
  const result = await validateNetworkTarget('https://example.com');
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.hostname, 'example.com');
  }
});

test('rejects unsupported protocols', async () => {
  const result = await validateNetworkTarget('ftp://example.com');
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.code, 'UNSUPPORTED_PROTOCOL');
  }
});

test('detects blocked IP ranges directly', () => {
  assert.equal(isBlockedIpAddress('127.0.0.1'), true);
  assert.equal(isBlockedIpAddress('10.0.0.1'), true);
  assert.equal(isBlockedIpAddress('1.1.1.1'), false);
});

test('validates redirect targets independently', async () => {
  const current = 'https://example.com/redirect';
  const invalid = 'http://127.0.0.1/admin';
  const result = await validateNetworkTarget(new URL(invalid, current).toString());
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.code, 'BLOCKED_DESTINATION');
  }
});
