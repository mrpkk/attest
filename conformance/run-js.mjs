/* Прогон векторов через браузерную реализацию.
 *
 * Смысл не в том, что «JS тоже умеет», а в том, что две реализации, написанные
 * независимо, дают один и тот же вердикт на одних и тех же байтах. Расхождение
 * здесь — не баг одной из них, а место, где формат описан неоднозначно.
 *
 * Запуск: node conformance/run-js.mjs
 */

import { readFileSync } from "node:fs";
import { verifyReceiptText } from "../attest/web/verify.js";

const file = process.argv[2] || "conformance/receipt-vectors.json";
const data = JSON.parse(readFileSync(file, "utf8"));

let pass = 0;
const failures = [];

for (const vector of data.vectors) {
  const result = await verifyReceiptText(vector.text, data.public_key);
  const ok = result.ok === vector.expect_ok;
  if (ok) {
    pass += 1;
  } else {
    failures.push({
      name: vector.name,
      expected: vector.expect_ok ? "valid" : "invalid",
      got: result.status,
      why: result.rejections.join("; "),
    });
  }
}

console.log(`векторов: ${data.vectors.length} · совпало: ${pass}`);
if (failures.length) {
  console.log("РАСХОЖДЕНИЯ:");
  for (const f of failures) console.log(" ", f.name, "→", f.got, f.why);
  process.exit(1);
}
console.log("браузерная реализация и Python согласны на всех векторах");
