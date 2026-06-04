// Smoke test for the npm verifier (B16). Verifies a fixture report and confirms
// a tampered one is rejected. Run: npm test
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyReport } from "./index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixtureReport = join(here, "fixtures", "report.json");
const fixturePem = join(here, "fixtures", "public_key.pem");

if (!existsSync(fixtureReport) || !existsSync(fixturePem)) {
  console.error("missing fixtures/report.json + fixtures/public_key.pem (generate with openwright)");
  process.exit(2);
}

const report = JSON.parse(readFileSync(fixtureReport, "utf8"));
const pem = readFileSync(fixturePem, "utf8");

const honest = await verifyReport(report, pem);
if (!honest.valid) {
  console.error("FAIL: honest report did not verify", honest.checks);
  process.exit(1);
}

const tampered = JSON.parse(JSON.stringify(report));
for (const item of tampered.events || []) {
  if (item.event?.io?.output_ref) { item.event.io.output_ref = "sha256:" + "00".repeat(32); break; }
}
const bad = await verifyReport(tampered, pem);
if (bad.valid) {
  console.error("FAIL: tampered report was accepted");
  process.exit(1);
}

console.log("OK: npm verifier verified honest report and rejected tampered one");
process.exit(0);
