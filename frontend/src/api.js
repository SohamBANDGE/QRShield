const BASE = import.meta.env.VITE_API_URL || "";

async function request(path, options) {
  let res;
  try {
    res = await fetch(BASE + path, options);
  } catch {
    throw new Error("Cannot reach the QRShield server. Check that the backend is running.");
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || "Something went wrong. Try again.");
  return body;
}

export const analyzeUrl = (url) =>
  request("/api/analyze/url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

export const analyzeImage = (file) => {
  const form = new FormData();
  form.append("file", file);
  return request("/api/analyze/image", { method: "POST", body: form });
};

export const getHistory = () => request("/api/history?limit=8");
export const getScan = (id) => request(`/api/scans/${id}`);
export const getStats = () => request("/api/stats");
export const sendFeedback = (id, helpful) =>
  request(`/api/scans/${id}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ helpful }),
  });
