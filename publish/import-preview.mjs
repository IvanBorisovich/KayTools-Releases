// One-time, bounded transfer into an existing Preview draft. This never publishes a release.
import { createDecipheriv, createHash } from 'node:crypto';
import { readFile, mkdtemp, open, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const REPOSITORY = 'IvanBorisovich/KayTools-Releases';
const RELEASE_ID = 393449056;
const RELEASE_TAG = 'preview-2.0.0-rc.1';
const CONTEXT = 'KayTools-preview-transfer-v1';
const MAX_BYTES = 2 * 1024 ** 3;
const NAMES = new Set([
  'KayTools-2.0.0-RC1-win-x64-Setup.exe', 'setup-descriptor.json',
  ...['tools', 'search', 'backup', 'tester'].flatMap(id => [
    `${id}-2.0.0-win-x64.zip`, `${id}-2.0.0.release.json`]),
]);
const HOSTS = new Set(['release-assets.githubusercontent.com', 'objects.githubusercontent.com']);

function check(condition, code) { if (!condition) throw new Error(code); }
function keys(value, expected) {
  check(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('|') === [...expected].sort().join('|'), 'SCHEMA');
}
function base64(value, bytes) {
  check(typeof value === 'string' && value.length > 0 && value.length <= 1024 * 1024
    && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value), 'BASE64');
  const decoded = Buffer.from(value, 'base64');
  check(decoded.toString('base64') === value && (bytes === undefined || decoded.length === bytes), 'BASE64_LENGTH');
  return decoded;
}
export function validateUrl(value) {
  check(typeof value === 'string' && value.length <= 16384, 'CDN_URL');
  const url = new URL(value);
  check(url.protocol === 'https:' && HOSTS.has(url.hostname) && !url.username
    && !url.password && !url.port && !url.hash, 'CDN_HOST');
  return url;
}
function validateManifest(value, inner) {
  keys(value, inner ? ['schema', 'repository', 'releaseId', 'tag', 'assets']
    : ['schema', 'repository', 'releaseId', 'tag', 'assets', 'encrypted']);
  check(value.schema === 1 && value.repository === REPOSITORY
    && value.releaseId === RELEASE_ID && value.tag === RELEASE_TAG, 'TARGET');
  check(Array.isArray(value.assets) && value.assets.length > 0 && value.assets.length <= NAMES.size, 'ASSET_COUNT');
  const seen = new Set();
  for (const asset of value.assets) {
    keys(asset, inner ? ['name', 'size', 'sha256', 'url'] : ['name', 'size', 'sha256']);
    check(NAMES.has(asset.name) && !seen.has(asset.name), 'ASSET_NAME');
    seen.add(asset.name);
    check(Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size <= MAX_BYTES, 'ASSET_SIZE');
    check(typeof asset.sha256 === 'string' && /^[a-f0-9]{64}$/.test(asset.sha256), 'ASSET_SHA256');
    if (inner) validateUrl(asset.url);
  }
}
export function decryptManifest(outer, keyText) {
  validateManifest(outer, false);
  keys(outer.encrypted, ['iv', 'tag', 'ciphertext']);
  check(typeof keyText === 'string' && /^[a-fA-F0-9]{64}$/.test(keyText), 'KEY_LENGTH');
  const key = Buffer.from(keyText, 'hex');
  let plaintext;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, base64(outer.encrypted.iv, 12), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(CONTEXT, 'utf8'));
    decipher.setAuthTag(base64(outer.encrypted.tag, 16));
    plaintext = Buffer.concat([decipher.update(base64(outer.encrypted.ciphertext)), decipher.final()]);
    check(plaintext.length <= 256 * 1024, 'PLAINTEXT_SIZE');
    const inner = JSON.parse(plaintext.toString('utf8'));
    validateManifest(inner, true);
    check(inner.assets.length === outer.assets.length, 'ASSET_MISMATCH');
    for (let i = 0; i < inner.assets.length; i++) {
      const { name, size, sha256 } = inner.assets[i];
      check(name === outer.assets[i].name && size === outer.assets[i].size
        && sha256 === outer.assets[i].sha256, 'ASSET_MISMATCH');
    }
    return inner;
  } finally {
    key.fill(0);
    plaintext?.fill(0);
  }
}

async function api(suffix) {
  const response = await fetch(`https://api.github.com/repos/${REPOSITORY}${suffix}`, {
    headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${process.env.GH_TOKEN}`,
      'X-GitHub-Api-Version': '2022-11-28' },
    redirect: 'error', signal: AbortSignal.timeout(30000),
  });
  check(response.ok, 'GITHUB_API');
  const text = await response.text();
  check(text.length <= 2 * 1024 ** 2, 'API_RESPONSE_SIZE');
  return JSON.parse(text);
}
async function draftAssets() {
  const release = await api(`/releases/${RELEASE_ID}`);
  check(release.id === RELEASE_ID && release.tag_name === RELEASE_TAG
    && release.draft === true && release.prerelease === true, 'RELEASE_NOT_APPROVED_DRAFT');
  const assets = await api(`/releases/${RELEASE_ID}/assets?per_page=100`);
  check(Array.isArray(assets) && assets.length < 100, 'EXISTING_ASSET_COUNT');
  return assets;
}
function matchingAsset(existing, expected) {
  const matches = existing.filter(asset => asset.name === expected.name);
  check(matches.length <= 1, 'DUPLICATE_EXISTING_ASSET');
  if (!matches.length) return false;
  const actual = matches[0];
  // No clobber: an unavailable digest is not evidence of identical contents.
  check(actual.state === 'uploaded' && actual.size === expected.size
    && actual.digest?.toLowerCase() === `sha256:${expected.sha256}`, 'EXISTING_ASSET_MISMATCH');
  return true;
}
async function download(asset, destination) {
  let url = validateUrl(asset.url);
  let response;
  const signal = AbortSignal.timeout(15 * 60 * 1000);
  for (let redirects = 0; redirects <= 3; redirects++) {
    // CDN requests deliberately contain no GitHub token or other authorization.
    response = await fetch(url, { redirect: 'manual', signal });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      await response.body?.cancel();
      check(redirects < 3 && location, 'CDN_REDIRECT');
      url = validateUrl(new URL(location, url).href);
      continue;
    }
    break;
  }
  check(response?.status === 200 && response.body, 'CDN_DOWNLOAD');
  const length = response.headers.get('content-length');
  check(length === null || Number(length) === asset.size, 'CDN_LENGTH');
  const hash = createHash('sha256');
  let received = 0;
  const file = await open(destination, 'wx', 0o600);
  try {
    for await (const chunk of response.body) {
      received += chunk.length;
      check(received <= asset.size, 'DOWNLOAD_TOO_LARGE');
      hash.update(chunk);
      let offset = 0;
      while (offset < chunk.length) {
        const { bytesWritten } = await file.write(chunk, offset, chunk.length - offset);
        check(bytesWritten > 0, 'DOWNLOAD_WRITE');
        offset += bytesWritten;
      }
    }
  } finally { await file.close(); }
  check(received === asset.size && hash.digest('hex') === asset.sha256, 'DOWNLOAD_INTEGRITY');
}

export async function main() {
  check(process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_REPOSITORY === REPOSITORY
    && process.env.GITHUB_EVENT_NAME === 'push' && process.env.GITHUB_REF === 'refs/heads/main', 'ACTIONS_CONTEXT');
  check(process.env.GH_TOKEN && process.env.KAYTOOLS_PREVIEW_TRANSFER_KEY, 'MISSING_SECRET');
  const text = await readFile(new URL('./preview-transfer.json', import.meta.url), 'utf8');
  check(text.length <= 1024 * 1024, 'ENVELOPE_SIZE');
  const manifest = decryptManifest(JSON.parse(text), process.env.KAYTOOLS_PREVIEW_TRANSFER_KEY);
  delete process.env.KAYTOOLS_PREVIEW_TRANSFER_KEY;
  const repository = await api('');
  check(repository.full_name === REPOSITORY && repository.private === false, 'REPOSITORY_MISMATCH');
  let existing = await draftAssets();
  for (const asset of manifest.assets) matchingAsset(existing, asset);
  const folder = await mkdtemp(path.join(process.env.RUNNER_TEMP || tmpdir(), 'kaytools-preview-'));
  try {
    // Verify all new payloads before making any release changes.
    for (const asset of manifest.assets) {
      if (!matchingAsset(existing, asset)) await download(asset, path.join(folder, asset.name));
      delete asset.url;
    }
    for (const asset of manifest.assets) {
      existing = await draftAssets();
      if (matchingAsset(existing, asset)) {
        console.log(`Already verified: ${asset.name} (${asset.size} bytes, SHA256 ${asset.sha256})`);
        continue;
      }
      const result = spawnSync('gh', ['release', 'upload', RELEASE_TAG, path.join(folder, asset.name),
        '--repo', REPOSITORY], { encoding: 'utf8', timeout: 15 * 60 * 1000, maxBuffer: 1024 * 1024,
        env: { ...process.env, GH_HOST: 'github.com', GH_DEBUG: '' } });
      check(result.status === 0 && !result.error, 'ASSET_UPLOAD');
      check(matchingAsset(await draftAssets(), asset), 'UPLOADED_ASSET_MISSING');
      console.log(`Uploaded and verified: ${asset.name} (${asset.size} bytes, SHA256 ${asset.sha256})`);
    }
    existing = await draftAssets();
    for (const asset of manifest.assets) check(matchingAsset(existing, asset), 'FINAL_ASSET_MISSING');
    console.log(`All ${manifest.assets.length} approved assets verified. Release remains a draft; nothing was published.`);
  } finally {
    // Only this script's unique temporary download directory; no source/user data.
    await rm(folder, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    // Fetch/crypto/CLI error messages can contain bearer URLs. Never print them.
    console.error('Approved Preview transfer failed. No release was published. Check approved metadata, secret and URL expiry.');
    process.exitCode = 1;
  });
}
