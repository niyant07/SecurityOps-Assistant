// The hosted version requires an access code; it is kept for this browser tab only.
const CODE_KEY = "securityops-access-code";

export function getAccessCode() {
  try { return sessionStorage.getItem(CODE_KEY) || ""; } catch { return ""; }
}

export function setAccessCode(code) {
  try { sessionStorage.setItem(CODE_KEY, code); } catch { /* storage unavailable */ }
}

export class AccessCodeRequired extends Error {}

function headers(extra = {}) {
  const code = getAccessCode();
  return code ? { ...extra, "X-Access-Code": code } : extra;
}

async function failure(response) {
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && data.code_required) {
    return new AccessCodeRequired(data.error || "Access code required.");
  }
  return new Error(data.error || `Request failed (${response.status})`);
}

// All writes are JSON POSTs: the backend rejects anything else (CSRF guard).
export async function request(path, body) {
  const response = await fetch(path, body ? {
    method: "POST",
    headers: headers({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  } : { cache: "no-store", headers: headers() });
  if (!response.ok) throw await failure(response);
  return response.json();
}

// Downloads go through fetch so errors (e.g. PDF unavailable) can be shown.
export async function download(path) {
  const response = await fetch(path, { cache: "no-store", headers: headers() });
  if (!response.ok) throw await failure(response);
  const disposition = response.headers.get("Content-Disposition") || "";
  const name = decodeURIComponent((disposition.match(/filename\*=UTF-8''([^;]+)/) || [])[1] || "report");
  const url = URL.createObjectURL(await response.blob());
  const link = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
