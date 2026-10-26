/* Проверка квитанции в браузере: без сети, без сборки, без зависимостей.
 *
 * Зачем вторая реализация: если проверку умеет только один код, это не
 * стандарт, а доверие к этому коду. Две независимые реализации, сходящиеся
 * на одних байтах, — единственное доказательство, что формат описан, а не
 * угадан.
 *
 * Что проверяется: каноничность (JCS), схема, точные словари, границы,
 * пересчёт chain.hash, подпись Ed25519 через WebCrypto.
 *
 * Чего здесь нет намеренно: цепей, контрольных точек, манифестов. Это
 * следующий шаг; страница обещает ровно то, что делает.
 */

const SPEC = "noa.receipt/0.1";
const MAX_ID = 128;
const PRINCIPAL = ["HUMAN", "SERVICE", "POLICY", "SANDBOX_SIM"];
const VERDICT = ["ALLOWED", "BLOCKED", "DEFERRED", "EXECUTED", "FAILED", "ROLLED_BACK", "SIMULATED"];
const RISK = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE"];
const MODE = ["off", "shadow", "approvals_on", "on"];
const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const HMAC_RE = /^hmac-sha256:[0-9a-f]{64}$/;
const TS_RE = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/;
const FORBIDDEN = new Set(["__proto__", "prototype", "constructor"]);

/* --- JCS: ключи по единицам UTF-16, только целые ------------------------- */

function utf16Key(s) {
  const out = [];
  for (let i = 0; i < s.length; i += 1) out.push(s.charCodeAt(i));
  return out;
}

function cmpUtf16(a, b) {
  const x = utf16Key(a), y = utf16Key(b);
  for (let i = 0; i < Math.min(x.length, y.length); i += 1) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

function escapeString(s) {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\r") out += "\\r";
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function jcs(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("non-integer number");
    if (!Number.isSafeInteger(value)) throw new Error("integer out of range");
    return String(value);
  }
  if (typeof value === "string") return escapeString(value);
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort(cmpUtf16);
    return "{" + keys.map((k) => escapeString(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  throw new Error("type not representable in JSON");
}

/* --- разбор с отказами на границе ---------------------------------------- */

function parseStrict(text) {
  // Дубли имён JSON.parse схлопывает молча, поэтому отдельного разбора не
  // нужно: ниже каноничность сверяется с исходным текстом, и дубль не
  // переживает эту сверку (JCS(parse(text)) !== text). Остаётся запрет имён,
  // которые меняют поведение объекта ещё до проверки.
  return JSON.parse(text, function reviver(key, value) {
    if (key !== "" && FORBIDDEN.has(key)) throw new Error(`forbidden member: ${key}`);
    return value;
  });
}

function validTimestamp(text) {
  if (typeof text !== "string") return "not a string";
  const m = TS_RE.exec(text);
  if (!m) return "not RFC 3339";
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  if (month < 1 || month > 12) return `month ${month} outside 1..12`;
  const last = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (day < 1 || day > last) return `day ${day} outside 1..${last}`;
  if (hour > 23) return `hour ${hour} outside 0..23`;
  if (minute > 59) return `minute ${minute} outside 0..59`;
  if (second > 59) return "second 60 is forbidden by the profile";
  return "";
}

/* --- схема --------------------------------------------------------------- */

export function checkSchema(receipt) {
  const bad = [];
  const want = (cond, path, rule) => { if (!cond) bad.push(`${path}: ${rule}`); };

  want(receipt && typeof receipt === "object" && !Array.isArray(receipt), "$", "object required");
  if (bad.length) return bad;

  const allowed = ["spec", "id", "ts", "scope", "agent", "action", "governance", "chain", "sig"];
  for (const key of Object.keys(receipt)) {
    want(allowed.includes(key), `$.${key}`, "unknown member is rejected");
  }
  want(receipt.spec === SPEC, "$.spec", `expected ${SPEC}`);
  want(typeof receipt.id === "string" && receipt.id.length > 0, "$.id", "non-empty string");
  want(typeof receipt.id === "string" && receipt.id.length <= MAX_ID, "$.id", `<= ${MAX_ID} code points`);
  const tsWhy = validTimestamp(receipt.ts);
  want(!tsWhy, "$.ts", tsWhy);

  const scope = receipt.scope || {};
  want(typeof scope.chain === "string" && scope.chain.length > 0, "$.scope.chain", "non-empty string");

  const agent = receipt.agent || {};
  want(typeof agent.id === "string" && agent.id.length > 0, "$.agent.id", "non-empty string");
  want(PRINCIPAL.includes(agent.principal), "$.agent.principal", "vocabulary");

  const action = receipt.action || {};
  want(typeof action.id === "string" && action.id, "$.action.id", "non-empty string");
  want(typeof action.canonical === "string" && action.canonical, "$.action.canonical", "non-empty string");
  want(RISK.includes(action.riskClass), "$.action.riskClass", "vocabulary");
  want(typeof action.paramsHash === "string" && (HASH_RE.test(action.paramsHash) || HMAC_RE.test(action.paramsHash)),
    "$.action.paramsHash", "sha256:<64 lowercase hex>");
  want(typeof action.reversible === "boolean", "$.action.reversible", "boolean literal");

  const gov = receipt.governance || {};
  want(MODE.includes(gov.mode), "$.governance.mode", "vocabulary");
  want(VERDICT.includes(gov.verdict), "$.governance.verdict", "vocabulary");
  want(typeof gov.sandboxed === "boolean", "$.governance.sandboxed", "boolean literal");

  const chainPart = receipt.chain || {};
  want(Number.isInteger(chainPart.seq) && chainPart.seq >= 0, "$.chain.seq", "integer >= 0");
  want(typeof chainPart.hash === "string" && HASH_RE.test(chainPart.hash), "$.chain.hash", "digest");
  if (chainPart.prevHash !== null && chainPart.prevHash !== undefined) {
    want(typeof chainPart.prevHash === "string" && HASH_RE.test(chainPart.prevHash), "$.chain.prevHash", "digest");
  }

  const sig = receipt.sig || {};
  want(sig.alg === "ed25519", "$.sig.alg", "exact lowercase 'ed25519'");
  want(typeof sig.kid === "string" && sig.kid, "$.sig.kid", "non-empty string");
  want(typeof sig.value === "string" && sig.value, "$.sig.value", "non-empty string");

  // Перекрёстные правила: квитанция не может говорить две вещи сразу.
  if ((agent.principal === "SANDBOX_SIM" || gov.verdict === "SIMULATED") && gov.sandboxed === false) {
    bad.push("$.governance.sandboxed: must be true when principal is SANDBOX_SIM or verdict is SIMULATED");
  }
  if (action.rollbackRef != null && action.reversible !== true) {
    bad.push("$.action.rollbackRef: only allowed when reversible is true");
  }
  if (gov.verdict === "ROLLED_BACK" && action.reversible !== true) {
    bad.push("$.governance.verdict: ROLLED_BACK requires reversible: true");
  }
  return bad;
}

/* --- хеш-вход и подпись -------------------------------------------------- */

export function hashInput(receipt) {
  const body = { ...receipt };
  delete body.chain;
  delete body.sig;
  const chain = { ...(receipt.chain || {}) };
  delete chain.hash;
  const sig = { ...(receipt.sig || {}) };
  delete sig.value;
  if (Object.keys(chain).length) body.chain = chain;
  if (Object.keys(sig).length) body.sig = sig;
  return jcs(body);
}

export async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return new Uint8Array(digest);
}

function hex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64decode(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export async function verifyReceiptText(text, publicKeyB64) {
  const result = { ok: false, status: "malformed", rejections: [], detail: {} };
  let receipt;
  try {
    receipt = parseStrict(text);
  } catch (err) {
    result.rejections.push(`parse: ${err.message}`);
    return result;
  }

  if (jcs(receipt) !== text) {
    result.status = "tampered";
    result.rejections.push("payload is not canonical: JCS(parse(text)) != text");
  }

  const schemaErrors = checkSchema(receipt);
  if (schemaErrors.length) {
    result.status = "malformed";
    result.rejections.push(...schemaErrors);
    return result;
  }
  if (result.rejections.length) return result;

  const expected = "sha256:" + hex(await sha256(hashInput(receipt)));
  if (expected !== receipt.chain.hash) {
    result.status = "tampered";
    result.rejections.push("chain.hash does not match the recomputed hash");
    return result;
  }

  const raw = b64decode(receipt.sig.value);
  if (btoa(String.fromCharCode(...raw)) !== receipt.sig.value) {
    result.rejections.push("sig.value is not canonical base64");
    return result;
  }

  try {
    const key = await crypto.subtle.importKey("raw", b64decode(publicKeyB64),
      { name: "Ed25519" }, false, ["verify"]);
    const message = concat(new TextEncoder().encode("NOA-Receipt-v0.1-sig:"),
      await sha256(hashInput(receipt)));
    const good = await crypto.subtle.verify({ name: "Ed25519" }, key, raw, message);
    if (!good) {
      result.status = "tampered";
      result.rejections.push("signature does not verify");
      return result;
    }
  } catch (err) {
    result.rejections.push(`key: ${err.message}`);
    return result;
  }

  result.ok = true;
  result.status = "valid";
  return result;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function exactBytes(bytes) {
  return new TextDecoder().decode(bytes);
}
