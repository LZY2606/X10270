import { spawn } from 'node:child_process';

const viteArgs = process.argv.slice(2);
const api = spawn('npx', ['tsx', 'src/server/index.ts'], {
  stdio: 'inherit',
  env: { ...process.env, PORT: process.env.PORT ?? '5371', DB_PATH: process.env.DB_PATH ?? 'data/app.db' }
});
const vite = spawn('npx', ['vite', ...viteArgs], { stdio: 'inherit' });

const shutdown = () => { api.kill('SIGTERM'); vite.kill('SIGTERM'); process.exit(0); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
api.on('exit', (code) => { if (code && code !== 0) console.error(`[dev] api server exited ${code}`); });
