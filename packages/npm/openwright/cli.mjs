#!/usr/bin/env node
// openwright-verify <report.json> <public_key.pem>
import { readFileSync } from "node:fs";
import { verifyReport } from "./index.mjs";

const [, , reportPath, pemPath] = process.argv;
if (!reportPath || !pemPath) {
  console.error("usage: openwright-verify <report.json> <public_key.pem>");
  process.exit(2);
}
const report = JSON.parse(readFileSync(reportPath, "utf8"));
const pem = readFileSync(pemPath, "utf8");
const { valid, checks } = await verifyReport(report, pem);
console.log("VALID:", valid);
for (const [name, ok] of checks) console.log(`  [${ok ? "OK" : "FAIL"}] ${name}`);
process.exit(valid ? 0 : 1);
