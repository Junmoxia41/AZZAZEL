import { copyFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// The REST deployment uploads dist/. Keep routing config in the artifact,
// rather than relying on manual copies after each Vite build.
const root = new URL('../', import.meta.url);
const required = ['index.html', 'manifest.json', 'sw.js', 'icon-192.png', 'icon-512.png'];
for (const file of required) {
  await access(new URL(`dist/${file}`, root));
}
await copyFile(new URL('vercel.json', root), new URL('dist/vercel.json', root));
console.log(`Deployment artifact prepared: ${fileURLToPath(new URL('dist/', root))}`);
