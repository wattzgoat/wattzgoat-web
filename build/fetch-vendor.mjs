// Vendors Chart.js at image-build time (when the build host has internet)
// so the running container never needs to reach jsdelivr at runtime.
import { writeFile, mkdir } from "node:fs/promises";

const CHART_JS_URL = "https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js";

const res = await fetch(CHART_JS_URL);
if (!res.ok) throw new Error(`Failed to fetch chart.js: ${res.status}`);
const body = await res.text();

await mkdir("dist", { recursive: true });
await writeFile("dist/chart.umd.min.js", body);
console.log(`Vendored chart.js (${body.length} bytes)`);
