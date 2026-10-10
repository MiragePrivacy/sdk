import { readFileSync } from "node:fs";
const path = process.argv[2];
if (!path) throw new Error("Usage: node scripts/check-workspace-vectors.mjs /path/to/api/tests/vectors/workspaces.json");
const sdk = readFileSync(new URL("../test/fixtures/workspaces.json", import.meta.url));
const api = readFileSync(path);
if (!sdk.equals(api)) throw new Error("API and SDK workspace vectors differ; copy the reviewed file verbatim");
console.log("API and SDK workspace vectors are byte-identical");
