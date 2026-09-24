import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const bin = (name) => path.join(root, 'node_modules', '.bin', name);
const viteArgs = process.argv.slice(2);

const api = spawn(bin('tsx'), ['src/server/index.ts'], {
  cwd: root,
  stdio: 'inherit',
  env: { ...process.env, API_PORT: process.env.API_PORT || '5371' },
});
const vite = spawn(bin('vite'), viteArgs, { cwd: root, stdio: 'inherit' });

let shuttingDown = false;
function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  api.kill('SIGTERM');
  vite.kill('SIGTERM');
  setTimeout(() => process.exit(code ?? 0), 300);
}
api.on('exit', (code) => { if (!shuttingDown) { console.error(`[dev] api exited (${code})`); shutdown(code ?? 1); } });
vite.on('exit', (code) => { if (!shuttingDown) shutdown(code ?? 0); });
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
