import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

const outputDirectory = join(process.cwd(), 'out');
const packageJson = JSON.parse(await readFile(join(process.cwd(), 'package.json'), 'utf8'));

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nestedFiles = await Promise.all(
    entries.map((entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory() ? collectFiles(path) : [path];
    }),
  );
  return nestedFiles.flat();
}

function getPublicUrl(filePath) {
  const file = relative(outputDirectory, filePath).split(sep).join('/');
  if (file === 'sw.js') return null;
  if (file === 'index.html') return '/';
  if (file.endsWith('/index.html')) return `/${file.slice(0, -'index.html'.length)}`;
  return `/${file}`;
}

const files = await collectFiles(outputDirectory);
const urls = files.map(getPublicUrl).filter((url) => url !== null).sort();
const payloadAliases = {};
for (const file of files) {
  const relativePath = relative(outputDirectory, file).split(sep).join('/');
  const segments = relativePath.split('/');
  const nextSegmentIndex = segments.findIndex((segment) => segment.startsWith('__next.'));
  if (nextSegmentIndex === -1) continue;

  const payloadPath = segments.slice(nextSegmentIndex + 1).join('/');
  if (!payloadPath.endsWith('__PAGE__.txt')) continue;

  const routePrefix = segments.slice(0, nextSegmentIndex).join('/');
  const nextSegment = segments[nextSegmentIndex];
  const aliasSuffix = payloadPath.replaceAll('/', '.');
  const aliasPath = `${routePrefix ? `${routePrefix}/` : ''}${nextSegment}.${aliasSuffix}`;
  payloadAliases[`/${aliasPath}`] = `/${relativePath}`;
}

const appPaths = files
  .filter((file) => {
    const relativePath = relative(outputDirectory, file).split(sep).join('/');
    return (
      relativePath.endsWith('index.html') &&
      relativePath !== '404/index.html' &&
      relativePath !== '_not-found/index.html'
    );
  })
  .map(getPublicUrl)
  .filter((url) => url !== null)
  .sort();
const serviceWorkerPath = join(process.cwd(), 'public', 'sw.js');
const serviceWorkerTemplate = await readFile(serviceWorkerPath, 'utf8');
const contentHash = createHash('sha256').update(packageJson.version).update(serviceWorkerTemplate);

for (const file of files) {
  const publicUrl = getPublicUrl(file);
  if (publicUrl === null) continue;
  contentHash.update(publicUrl).update(await readFile(file));
}

const revision = contentHash.digest('hex').slice(0, 12);
const cacheName = `pichu-shell-${packageJson.version}-${revision}`;
const serviceWorker = serviceWorkerTemplate
  .replace('__PICHU_CACHE_NAME__', cacheName)
  .replace('__PICHU_PRECACHE_URLS__', JSON.stringify(urls))
  .replace('__PICHU_PAYLOAD_ALIASES__', JSON.stringify(payloadAliases))
  .replace('__PICHU_APP_PATHS__', JSON.stringify(appPaths));

if (serviceWorker.includes('__PICHU_')) {
  throw new Error('No se pudieron reemplazar todos los valores del precache PWA.');
}

await writeFile(join(outputDirectory, 'sw.js'), serviceWorker);
console.log(`Service worker PWA generado con ${urls.length} recursos públicos.`);
