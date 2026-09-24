/** 共享运行时：数据库位置、服务装配、导出/删除/再导入。 */

import { resolve } from "node:path";
import { rmSync } from "node:fs";
import { SessionStore } from "./store.js";
import { SessionService } from "./session-service.js";
import type { ExportBundle } from "./store.js";

export const DB_PATH = resolve(process.cwd(), "data/app.sqlite");

export interface Runtime {
  store: SessionStore;
  service: SessionService;
  resetDatabase: (bundle?: ExportBundle) => void;
}

let current: Runtime | null = null;

export function getRuntime(dbPath = DB_PATH): Runtime {
  if (current) return current;
  const store = new SessionStore(dbPath);
  const service = new SessionService(store);
  const resetDatabase = (bundle?: ExportBundle) => {
    store.close();
    for (const suffix of ["", "-wal", "-shm"]) {
      try {
        rmSync(dbPath + suffix, { force: true });
      } catch {
        // ignore
      }
    }
    const reopened = new SessionStore(dbPath);
    if (bundle) reopened.importBundleAt(bundle, dbPath);
    const freshStore = new SessionStore(dbPath);
    // 替换内部对象
    (store as any).db = freshStore.db;
    void reopened;
  };
  current = { store, service, resetDatabase };
  // 启动时先恢复任何半写事务
  store.recoverHalfWrites();
  return current;
}
