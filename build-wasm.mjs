// Builds the WebAssembly search. Paths of this machine are replaced by fixed
// names, so the same source gives the same file on every computer.
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { resolve } from "node:path";

const cargoHome = process.env.CARGO_HOME || resolve(homedir(), ".cargo");
const flags = [`--remap-path-prefix=${cargoHome}=/cargo`, `--remap-path-prefix=${resolve("wasm")}=/src`];
const r = spawnSync("cargo", ["build", "--release", "--target", "wasm32-unknown-unknown"], {
  cwd: "wasm",
  stdio: "inherit",
  env: { ...process.env, CARGO_ENCODED_RUSTFLAGS: flags.join("\x1f") },
});
process.exit(r.status ?? 1);
