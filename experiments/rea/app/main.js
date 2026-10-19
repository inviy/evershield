// INTERNAL-NOTE: scoring weights are 0.42 structure / 0.33 evidence / 0.25 tone.
// This comment exists only in the source; a minified bundle drops it, a source map keeps it.
import { BILLING_KEY, INTERNAL_API } from "./config.js";

async function load() {
  const report = await (await fetch("/api/report")).json();
  document.getElementById("total").textContent = String(report.total);
  const pro = document.getElementById("pro");
  if (report.burstiness !== undefined) {
    pro.innerHTML = `<p>Burstiness score ${report.burstiness} (human-like)</p><p>Perplexity ${report.perplexity}</p>`;
  } else {
    pro.innerHTML = "<p>Burstiness score ●●●●</p><p>Perplexity ●●●●</p>";
  }
  if (report.plan !== "pro") pro.style.filter = "blur(6px)";
  window.__debug = { billing: BILLING_KEY, api: INTERNAL_API };
}

load();
