// Builds dist/digibyte-vanity-address.html: one self-contained file with the page, the search
// worker and the WebAssembly search inside it, plus dist/SHA256SUMS.
//
//   npm run build      (builds the WebAssembly first, then this script)
//
// The output is the same on every machine for the same source, so anyone can
// rebuild it and compare the SHA-256 with the released file.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { build } from "esbuild";

const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const version = `v${pkg.version}`;
const wasm = readFileSync("wasm/target/wasm32-unknown-unknown/release/vanity_search.wasm");

async function bundle(entry, define) {
  const out = await build({
    entryPoints: [entry],
    bundle: true,
    format: "iife",
    minify: true,
    target: "es2022",
    write: false,
    legalComments: "inline",
    define,
    logLevel: "warning",
  });
  // A "</script" inside the code would end the inline script early.
  return out.outputFiles[0].text.replaceAll("</script", "<\\/script");
}

const worker = await bundle("src/worker.ts", { WASM_BASE64: JSON.stringify(wasm.toString("base64")) });
const script = (await bundle("src/main.ts", { WORKER_SOURCE: JSON.stringify(worker) })).trimEnd();

const scriptHash = createHash("sha256").update(script, "utf8").digest("base64");
const csp = [
  "default-src 'none'",
  `script-src 'sha256-${scriptHash}' 'wasm-unsafe-eval'`,
  "worker-src blob:",
  "style-src 'unsafe-inline'",
  "img-src data:",
  "connect-src 'none'",
  "form-action 'none'",
  "base-uri 'none'",
].join("; ");

const template = readFileSync("src/index.html", "utf8");
if (template.split("__SCRIPT__").length !== 2) throw new Error("template must contain __SCRIPT__ once");
const html = template
  .replace("__CSP__", csp)
  .replaceAll("__VERSION__", version)
  .replace("__SCRIPT__", () => script);

mkdirSync("dist", { recursive: true });
writeFileSync("dist/digibyte-vanity-address.html", html);
writeFileSync("dist/csp.txt", csp + "\n");
const sum = createHash("sha256").update(html).digest("hex");
writeFileSync("dist/SHA256SUMS", `${sum}  digibyte-vanity-address.html\n`);
console.log(`dist/digibyte-vanity-address.html  ${version}  ${(html.length / 1024).toFixed(0)} KB  sha256 ${sum}`);
