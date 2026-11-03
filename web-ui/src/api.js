// All writes are JSON POSTs: the backend rejects anything else (CSRF guard).
export async function request(path, body) {
  const response = await fetch(path, body ? {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  } : { cache: "no-store" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

// Downloads go through fetch so a server error (e.g. PDF unavailable) can be shown.
export async function download(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || `Download failed (${response.status})`);
  }
  const disposition = response.headers.get("Content-Disposition") || "";
  const name = decodeURIComponent((disposition.match(/filename\*=UTF-8''([^;]+)/) || [])[1] || "report");
  const url = URL.createObjectURL(await response.blob());
  const link = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
