import { storeName } from "../constants";
import { type SmokeContext } from "../context";
import { writeStoreFixture } from "../fixtures";
import { expectStartupRefusal, killAndWait } from "../process";
import { type Subprocess } from "bun";
import { rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";

export async function checkStrictStore(
  context: SmokeContext,
  server: Subprocess,
) {
  const {
    tempRoot,
    port,
    dataDir,
    configPath,
    binaryPath,
    backendDir,
    processes,
    results,
  } = context;
  await killAndWait(server);

  const storePath = join(dataDir, storeName);
  writeStoreFixture(storePath, "{malformed");
  await expectStartupRefusal(
    binaryPath,
    configPath,
    backendDir,
    port,
    processes,
    "malformed session store",
    "decode auth session store",
  );
  writeStoreFixture(storePath, JSON.stringify({ version: 2, sessions: {} }));
  await expectStartupRefusal(
    binaryPath,
    configPath,
    backendDir,
    port,
    processes,
    "future-version session store",
    "unsupported auth session store version 2",
  );
  writeStoreFixture(storePath, JSON.stringify({ version: 1 }));
  await expectStartupRefusal(
    binaryPath,
    configPath,
    backendDir,
    port,
    processes,
    "missing sessions map",
    "auth session store is missing required sessions map",
  );
  writeStoreFixture(
    storePath,
    JSON.stringify({ version: 1, sessions: {}, unexpected: true }),
  );
  await expectStartupRefusal(
    binaryPath,
    configPath,
    backendDir,
    port,
    processes,
    "unknown session store field",
    "unknown field",
  );

  const symlinkTarget = join(tempRoot, "symlink-target.json");
  writeStoreFixture(
    symlinkTarget,
    JSON.stringify({ version: 1, sessions: {} }),
  );
  rmSync(storePath, { force: true });
  symlinkSync(symlinkTarget, storePath);
  await expectStartupRefusal(
    binaryPath,
    configPath,
    backendDir,
    port,
    processes,
    "symlink session store",
    "auth session store is not a regular file",
  );
  results.push({
    scenario: "Strict session-store startup validation",
    outcome: "PASS",
    evidence:
      "Malformed JSON, future version 2, missing required sessions map, unknown top-level field, and a symlink at auth-sessions.json each exited before /health became ready with the matching auth-session-store initialization diagnostic.",
  });
}
