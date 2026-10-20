// BDR Group. Pruebas de reparacion de metadatos, sin red ni claves reales.
import { strict as assert } from 'node:assert';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { repairManifest, verifyOriginal } from './repair-release-metadata.mjs';

const identity = 'Developer ID Installer: BDR Group (ABCDEFGHIJ)';
const team = 'ABCDEFGHIJ';
const names = ['breeze-agent-darwin-amd64.pkg', 'breeze-agent-darwin-arm64.pkg'];
function fixture(fn) {
  const directory = mkdtempSync(join(tmpdir(), 'bdr-efg-firma-'));
  try {
    const assets = names.map(name => {
      const bytes = Buffer.from(name);
      writeFileSync(join(directory, name), bytes);
      return { name, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
        platformTrust: 'macos-developer-id-notarization-required' };
    });
    const manifest = { schemaVersion: 1, repository: 'BDR-INFORMATICA/bdr-breeze-firma',
      release: 'v9.9.9', sourceCommit: 'a'.repeat(40), assets };
    const attestations = names.map(name => `${name}\tmacos-developer-id-notarization-required\t${identity}\t${team}`).join('\n');
    fn(directory, manifest, attestations);
  } finally { rmSync(directory, { recursive: true }); }
}
const expected = { repository: 'BDR-INFORMATICA/bdr-breeze-firma', release: 'v9.9.9', identity, team };

test('adds only edition and verified publisher, preserving binary hashes and release identity', () => fixture((dir, old, att) => {
  const original = structuredClone(old);
  const fixed = repairManifest(old, dir, att, expected);
  assert.deepEqual(old, original);
  assert.equal(fixed.sourceCommit, old.sourceCommit);
  for (let i = 0; i < fixed.assets.length; i++) {
    assert.deepEqual(fixed.assets[i], { ...old.assets[i], edition: 'self-host', signingIdentity: identity, signingTeamId: team });
    assert.equal(readFileSync(join(dir, names[i]), 'utf8'), names[i]);
  }
}));
test('rejects changed binary bytes', () => fixture((dir, old, att) => {
  writeFileSync(join(dir, names[0]), 'changed');
  assert.throws(() => repairManifest(old, dir, att, expected), /hash|size/);
}));
test('requires independently verified publisher for both packages', () => fixture((dir, old, att) => {
  assert.throws(() => repairManifest(old, dir, att.split('\n')[0], expected), /attestation/);
}));
test('rejects commercial edition relabeling', () => fixture((dir, old, att) => {
  old.assets[0].edition = 'commercial';
  assert.throws(() => repairManifest(old, dir, att, expected), /edition/);
}));
test('rejects another publisher or Apple team', () => fixture((dir, old, att) => {
  assert.throws(() => repairManifest(old, dir, att.replaceAll(team, 'XXXXXXXXXX'), expected), /publisher/);
}));
test('rejects duplicate assets and path traversal', () => fixture((dir, old, att) => {
  old.assets.push({ ...old.assets[0] });
  assert.throws(() => repairManifest(old, dir, att, expected), /duplicate/);
  old.assets.pop(); old.assets[0].name = '../other.pkg';
  assert.throws(() => repairManifest(old, dir, att, expected), /name/);
}));
test('handles GitHub normalization of the existing installer ZIP name without renaming manifest entries', () => fixture((dir, old, att) => {
  const bytes = Buffer.from('installer');
  writeFileSync(join(dir, 'Breeze.Installer.app.zip'), bytes);
  old.assets.push({ name: 'Breeze Installer.app.zip', size: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'), platformTrust: 'macos-developer-id-notarization-required' });
  const fixed = repairManifest(old, dir, att, expected);
  assert.equal(fixed.assets[2].name, 'Breeze Installer.app.zip');
  assert.equal(fixed.assets[2].edition, 'self-host');
}));
test('metadata repair is idempotent', () => fixture((dir, old, att) => {
  const fixed = repairManifest(old, dir, att, expected);
  assert.deepEqual(repairManifest(fixed, dir, att, expected), fixed);
}));
test('original signature must verify against the pinned public key', () => {
  const key = generateKeyPairSync('ed25519');
  const other = generateKeyPairSync('ed25519');
  const raw = Buffer.from('{"schemaVersion":1}');
  const signature = sign(null, raw, key.privateKey);
  assert.equal(verifyOriginal(raw, signature, key.publicKey), true);
  assert.throws(() => verifyOriginal(raw, signature, other.publicKey), /signature/);
  assert.throws(() => verifyOriginal(Buffer.from('{}'), signature, key.publicKey), /signature/);
});

test('signing CLI accepts only metadata repair with the pinned key', () => fixture((dir, old, att) => {
  const key = generateKeyPairSync('ed25519');
  const other = generateKeyPairSync('ed25519');
  const original = Buffer.from(JSON.stringify(old));
  const fixed = repairManifest(old, dir, att, expected);
  const manifestPath = join(dir, 'fixed.json');
  const output = join(dir, 'fixed.sig');
  writeFileSync(join(dir, 'original.json'), original);
  writeFileSync(join(dir, 'original.sig'), sign(null, original, key.privateKey).toString('base64'));
  writeFileSync(join(dir, 'public.key'), key.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'));
  writeFileSync(join(dir, 'attest.tsv'), att);
  writeFileSync(manifestPath, JSON.stringify(fixed));
  const script = fileURLToPath(new URL('./repair-release-metadata.mjs', import.meta.url));
  const args = [script, 'sign', '--original', join(dir, 'original.json'), '--original-signature', join(dir, 'original.sig'),
    '--manifest', manifestPath, '--key', join(dir, 'public.key'), '--attest', join(dir, 'attest.tsv'),
    '--repository', expected.repository, '--release', expected.release, '--identity', identity, '--team', team, '--output', output];
  const run = privateKey => spawnSync(process.execPath, args, { encoding: 'utf8',
    env: { ...process.env, RELEASE_MANIFEST_ED25519_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }) } });
  let result = run(key.privateKey);
  assert.equal(result.status, 0, result.stderr);
  verifyOriginal(readFileSync(manifestPath), Buffer.from(readFileSync(output, 'utf8'), 'base64'), key.publicKey);
  result = run(other.privateKey);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not match pinned public key/);
  fixed.assets[0].sha256 = 'b'.repeat(64);
  writeFileSync(manifestPath, JSON.stringify(fixed));
  result = run(key.privateKey);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /exceed verified metadata repair/);
}));
