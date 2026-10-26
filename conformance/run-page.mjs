/* Прогон собранной страницы без браузера.
 *
 * Браузерный бэкенд может быть недоступен, а страница при этом обязана
 * работать. Поэтому скрипт из offline.html исполняется здесь же, с минимальным
 * DOM: те же строки, что увидит человек, только без окна.
 *
 * Проверяется ровно то, что ломается тихо: модуль вообще исполнился, баннер
 * возможностей заполнился, пример проверяется, подделка отвергается.
 *
 * Запуск: node conformance/run-page.mjs
 */

import { readFileSync } from "node:fs";

const html = readFileSync("attest/web/offline.html", "utf8");
const match = html.match(/<script type="module">([\s\S]*?)<\/script>/);
if (!match) {
  console.log("НЕТ МОДУЛЯ на странице");
  process.exit(1);
}
const code = match[1];

// Минимальный DOM: только то, к чему обращается страница.
const elements = {};
function el(id) {
  if (!elements[id]) elements[id] = { id, textContent: "", className: "", value: "" };
  return elements[id];
}
globalThis.window = globalThis;
globalThis.document = {
  getElementById: el,
  documentElement: { outerHTML: html },
};

const run = new Function(`${code}\nreturn { example: window.example, run: window.run };`);
const page = run();

if (typeof page.example !== "function" || typeof page.run !== "function") {
  console.log("страница не выставила обработчики");
  process.exit(1);
}

await new Promise((r) => setTimeout(r, 50));

const caps = el("caps").textContent;
if (!caps) {
  console.log("баннер возможностей пуст: модуль не доехал до конца");
  process.exit(1);
}
console.log("баннер:", caps.slice(0, 90));

page.example();
await page.run();
const verdict = el("out").textContent;
if (!verdict.startsWith("VALID")) {
  console.log("пример не проверяется:", verdict.slice(0, 120));
  process.exit(1);
}
console.log("пример:", verdict.split("\n")[0]);

// Подделка должна отвергаться теми же строками, что и в браузере.
const ta = el("receipt");
ta.value = ta.value.replace('"riskClass":"HIGH"', '"riskClass":"LOW"');
await page.run();
const bad = el("out").textContent;
if (!bad.startsWith("NOT VALID")) {
  console.log("подделка принята — это провал:", bad.slice(0, 120));
  process.exit(1);
}
console.log("подделка:", bad.split("\n")[0]);
console.log("страница исполняется и проверяет без браузера");
