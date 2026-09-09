import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = join(root, 'dist');
const config = JSON.parse(readFileSync(join(root, 'vercel.json'), 'utf8'));
const html = readFileSync(join(dist, 'index.html'), 'utf8');
const refs = [...html.matchAll(/(?:src|href)=["'](\/[^"']*)["']/g)].map(m => m[1]);
const filesystemIndex = config.routes.findIndex(route => route.handle === 'filesystem');
const fallbackIndex = config.routes.findIndex(route => route.dest === '/index.html');

// Only a local model of the configured rules; production HTTP checks are separate.
function resolveRoute(path) {
  for (const route of config.routes) {
    if (route.handle === 'filesystem') {
      const file = resolve(dist, '.' + (path === '/' ? '/index.html' : path));
      if (file.startsWith(dist) && existsSync(file) && statSync(file).isFile()) return { file: path, status: 200 };
    } else if (new RegExp('^(?:' + route.src + ')$').test(path)) {
      if (route.continue) continue;
      return { file: route.dest || null, status: route.status || 200 };
    }
  }
  return { file: null, status: 404 };
}

test('real files take priority over the SPA fallback', () => {
  assert.ok(filesystemIndex >= 0 && filesystemIndex < fallbackIndex);
  assert.ok(config.routes.slice(0, filesystemIndex).every(route => route.continue === true));
});

test('the deployed config is identical to the source config', () => {
  assert.deepEqual(JSON.parse(readFileSync(join(dist, 'vercel.json'), 'utf8')), config);
});

test('all local references in the built HTML exist', () => {
  assert.ok(refs.length >= 4);
  for (const ref of refs) assert.ok(existsSync(join(dist, ref)), `Missing: ${ref}`);
});

test('module scripts are actual JavaScript, not HTML', () => {
  const scripts = [...html.matchAll(/<script\b[^>]*src=["']([^"']+\.js)["']/g)].map(m => m[1]);
  assert.ok(scripts.length > 0);
  for (const script of scripts) {
    const text = readFileSync(join(dist, script), 'utf8');
    assert.ok(text.length > 100);
    assert.doesNotMatch(text, /^\s*<(?:!doctype|html)/i);
    assert.deepEqual(resolveRoute(script), { file: script, status: 200 });
  }
});

test('stylesheets are actual CSS, not HTML', () => {
  const styles = refs.filter(ref => ref.endsWith('.css'));
  assert.ok(styles.length > 0);
  for (const style of styles) {
    const text = readFileSync(join(dist, style), 'utf8');
    assert.match(text, /\{/);
    assert.doesNotMatch(text, /^\s*<(?:!doctype|html)/i);
    assert.deepEqual(resolveRoute(style), { file: style, status: 200 });
  }
});

test('missing assets and API paths return 404, never index.html with 200', () => {
  for (const path of ['/assets/missing.js', '/assets/missing.css', '/assets/no-extension', '/missing.js', '/missing.json', '/api/unknown']) {
    assert.deepEqual(resolveRoute(path), { file: null, status: 404 }, path);
  }
});

test('extensionless client navigation retains the SPA fallback', () => {
  assert.deepEqual(resolveRoute('/ajustes/conexion'), { file: '/index.html', status: 200 });
});

test('PWA manifest has a stable URL and real PNG icons with matching dimensions', () => {
  assert.match(html, /rel="manifest" href="\/manifest\.json"/);
  const manifest = JSON.parse(readFileSync(join(dist, 'manifest.json'), 'utf8'));
  assert.equal(manifest.start_url, '/');
  for (const icon of manifest.icons) {
    const image = readFileSync(join(dist, icon.src));
    assert.equal(image.subarray(1, 4).toString('ascii'), 'PNG');
    assert.equal(`${image.readUInt32BE(16)}x${image.readUInt32BE(20)}`, icon.sizes);
  }
});

test('service worker is included in a clean build as JavaScript', () => {
  const text = readFileSync(join(dist, 'sw.js'), 'utf8');
  assert.match(text, /addEventListener/);
  assert.doesNotMatch(text, /^\s*<(?:!doctype|html)/i);
  assert.deepEqual(resolveRoute('/sw.js'), { file: '/sw.js', status: 200 });
});

test('nosniff is kept; MIME is not forged with Content-Type overrides', () => {
  assert.equal(config.routes[0].headers['X-Content-Type-Options'], 'nosniff');
  for (const route of config.routes) {
    assert.ok(!Object.keys(route.headers || {}).some(key => key.toLowerCase() === 'content-type'));
  }
});

test('HTML entry point and service worker must revalidate', () => {
  for (const path of ['/', '/index.html', '/sw.js', '/manifest.json']) {
    assert.ok(config.routes.some(route => route.src && new RegExp('^(?:' + route.src + ')$').test(path) && /no-cache/.test(route.headers?.['Cache-Control'] || '')), path);
  }
});

test('deployable files contain no Vercel or Supabase management tokens', () => {
  const scan = folder => {
    for (const name of readdirSync(folder)) {
      const path = join(folder, name);
      if (statSync(path).isDirectory()) scan(path);
      else if (/\.(?:json|html|js|css|map)$/.test(name)) {
        assert.doesNotMatch(readFileSync(path, 'utf8'), /(?:vcp_|sbp_)[A-Za-z0-9]{20,}/, `Management credential in ${name}`);
      }
    }
  };
  scan(dist);
});
