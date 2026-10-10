import { api, seg } from "@/lib/client/api";
export type Account = { uuid: string; id: string | null; kind?: "carbon" | "silicon" };
export type SiliconEntry = { silicon: Account; access: "self" | "custodian" | "manage" | "view"; custodian: string | null };
export type PageResult<T> = { items: T[]; next_cursor?: string | null };
export type Signature = { required: boolean; algorithm: string; payload: string; signature: string; signature_encoding: string; secret_encoding: string; public_key: string | null; has_secret?: boolean };
export type Hook = { id: string; silicon: Account; name: string; description: string | null; endpoint_url: string; endpoint_key: string; status: "active" | "disabled" | "deleted"; signature: Signature; time_zone: string; created_by: Account; created_at: string; last_received_at: string | null; last_blocked_at: string | null; deleted_at: string | null; recoverable_until: string | null; signing_secret?: string | null };
export type CapturedRequest = { method: string; url: string; path: string; query_string: string; headers: [string, string][]; content_type: string | null; body: string | null; body_base64: string | null; remote_ip: string };
export type HookEvent = { id: string; silicon: Account; hook_id: string; provider: string; received_at: string; summary?: string; delivery_sequence?: number; reason_code?: string; reason_detail?: string; request: CapturedRequest };
export type Grant = { account: Account; level: "view" | "manage"; granted_by: Account; created_at: string };
export type Access = { silicon: Account; you: { account: Account; access: string }; custodian: Account | null; grants: Grant[] };
export type AllowList = { silicon: Account; items: { account: Account; created_by: Account; created_at: string }[] };
export const scope = (uuid: string, suffix = "") => `/api/v3/silicons/${seg(uuid)}${suffix}`;
export const listSilicons = () => api.get<{ items: SiliconEntry[] }>("/api/v3/silicons");
export function downloadJson(value: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
