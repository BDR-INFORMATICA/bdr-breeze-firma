// BDR Group. Repara solo metadatos de una publicacion existente y verificada.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const PKGS = ['breeze-agent-darwin-amd64.pkg', 'breeze-agent-darwin-arm64.pkg'];
const TRUST = 'macos-developer-id-notarization-required';

export function verifyOriginal(bytes, signature, publicKey) {
  if (!verify(null, bytes, publicKey, signature)) throw new Error('Original manifest signature rejected');
  return true;
}

function publisherRows(text, expected) {
  const rows = new Map();
  for (const line of text.split(/\r?\n/).filter(Boolean)) {
    const fields = line.split('\t');
    if (fields.length !== 4 || !PKGS.includes(fields[0]) || rows.has(fields[0])) {
      throw new Error('Invalid or duplicate package attestation');
    }
    const [name, trust, identity, team] = fields;
    if (trust !== TRUST || identity !== expected.identity || team !== expected.team
        || !/^[A-Z0-9]{10}$/.test(team)
        || !identity.startsWith('Developer ID Installer: ') || !identity.endsWith(` (${team})`)) {
      throw new Error('Package publisher mismatch');
    }
    rows.set(name, { identity, team });
  }
  if (PKGS.some(name => !rows.has(name))) throw new Error('Package attestation missing');
  return rows;
}

function withMetadata(manifest, attestations, expected) {
  if (manifest.schemaVersion !== 1 || manifest.repository.toLowerCase() !== expected.repository.toLowerCase()
      || manifest.release !== expected.release || !/^[a-f0-9]{40}$/.test(manifest.sourceCommit)
      || !Array.isArray(manifest.assets) || !manifest.assets.length) {
    throw new Error('Unexpected manifest identity');
  }
  const publishers = publisherRows(attestations, expected);
  const seen = new Set();
  const assets = manifest.assets.map(asset => {
    if (typeof asset.name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(asset.name)
        || asset.name.includes('..')) throw new Error('Invalid asset name');
    if (seen.has(asset.name)) throw new Error('duplicate asset name');
    seen.add(asset.name);
    if (asset.edition !== undefined && asset.edition !== 'self-host') throw new Error('Unexpected asset edition');
    if (asset.intendedUse === 'signing-input' || !asset.platformTrust
        || !/^[a-f0-9]{64}$/.test(asset.sha256) || !Number.isSafeInteger(asset.size) || asset.size < 0) {
      throw new Error('Invalid distributable asset');
    }
    const fixed = { ...asset, edition: 'self-host' };
    if (asset.name.endsWith('.pkg')) {
      const publisher = publishers.get(asset.name);
      if (!publisher || asset.platformTrust !== TRUST) throw new Error('Package attestation or trust missing');
      fixed.signingIdentity = publisher.identity;
      fixed.signingTeamId = publisher.team;
    }
    return fixed;
  });
  if (PKGS.some(name => !seen.has(name))) throw new Error('Package asset missing');
  return { ...manifest, assets };
}

export function repairManifest(manifest, directory, attestations, expected) {
  const fixed = withMetadata(manifest, attestations, expected);
  for (const asset of manifest.assets) {
    const filename = asset.name === 'Breeze Installer.app.zip' ? 'Breeze.Installer.app.zip' : asset.name;
    const bytes = readFileSync(join(directory, filename));
    if (bytes.length !== asset.size || createHash('sha256').update(bytes).digest('hex') !== asset.sha256) {
      throw new Error('Asset hash or size mismatch: ' + asset.name);
    }
  }
  return fixed;
}

function loadPublic(path) {
  const raw = readFileSync(path, 'utf8').trim();
  if (raw.includes('BEGIN PUBLIC KEY')) return createPublicKey(raw);
  const key = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw, 'base64')]);
  return createPublicKey({ key, format: 'der', type: 'spki' });
}

function main() {
  const args = process.argv.slice(2);
  const command = args.shift();
  const flags = new Map();
  const allowed = new Set(['--manifest', '--signature', '--key', '--assets', '--attest', '--repository', '--release', '--identity', '--team', '--output', '--original', '--original-signature']);
  while (args.length) {
    const key = args.shift(), value = args.shift();
    if (!allowed.has(key) || flags.has(key) || !value) throw new Error('Invalid arguments');
    flags.set(key, value);
  }
  const arg = name => { if (!flags.has(name)) throw new Error('Missing ' + name); return flags.get(name); };
  const expected = { repository: arg('--repository'), release: arg('--release'), identity: arg('--identity'), team: arg('--team') };
  const publicKey = loadPublic(arg('--key'));
  const attestations = readFileSync(arg('--attest'), 'utf8');
  if (command === 'build') {
    const raw = readFileSync(arg('--manifest'));
    verifyOriginal(raw, Buffer.from(readFileSync(arg('--signature'), 'utf8').trim(), 'base64'), publicKey);
    const fixed = repairManifest(JSON.parse(raw), arg('--assets'), attestations, expected);
    writeFileSync(arg('--output'), JSON.stringify(fixed, null, 2) + '\n');
    console.log(`Verified ${fixed.assets.length} unchanged assets; metadata repaired`);
  } else if (command === 'sign') {
    const original = readFileSync(arg('--original'));
    verifyOriginal(original, Buffer.from(readFileSync(arg('--original-signature'), 'utf8').trim(), 'base64'), publicKey);
    const raw = readFileSync(arg('--manifest'));
    const expectedManifest = withMetadata(JSON.parse(original), attestations, expected);
    if (!isDeepStrictEqual(JSON.parse(raw), expectedManifest)) throw new Error('Changes exceed verified metadata repair');
    const secret = (process.env.RELEASE_MANIFEST_ED25519_PRIVATE_KEY || '').trim();
    if (!secret) throw new Error('Signing key missing');
    const key = secret.includes('BEGIN PRIVATE KEY') ? createPrivateKey(secret)
      : createPrivateKey({ key: Buffer.from(secret, 'base64'), format: 'der', type: 'pkcs8' });
    if (!createPublicKey(key).export({ type: 'spki', format: 'der' }).equals(publicKey.export({ type: 'spki', format: 'der' }))) {
      throw new Error('Signing key does not match pinned public key');
    }
    const signature = sign(null, raw, key);
    verifyOriginal(raw, signature, publicKey);
    writeFileSync(arg('--output'), signature.toString('base64') + '\n');
    console.log('Repaired manifest signed with the existing verified key');
  } else throw new Error('Expected build or sign');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
