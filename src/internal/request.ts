import { ApiError } from "../errors.js";

export async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);

  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    let body: unknown = raw || undefined;
    let detail = "";
    try {
      const parsed = JSON.parse(raw) as { error?: string; details?: string };
      body = parsed;
      detail = parsed.error ?? parsed.details ?? "";
    } catch {
      detail = raw;
    }
    throw new ApiError(
      res.status,
      detail || `API request failed: ${res.status} ${res.statusText}`,
      body,
    );
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}
