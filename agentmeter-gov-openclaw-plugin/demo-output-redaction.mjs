import { guardText } from "./content-guard.js";

const sample = "调用凭证 sk-demo0123456789abcdef，请勿在最终回复中暴露。";
const result = guardText(sample, { surface: "demo" });

if (result.action !== "redact" || !result.text.includes("[REDACTED:API_TOKEN]")) {
  throw new Error(`unexpected output guard result: ${JSON.stringify(result)}`);
}

console.log(JSON.stringify({
  input: sample,
  action: result.action,
  output: result.text,
  findingTypes: result.findings.map((item) => item.id),
}, null, 2));
