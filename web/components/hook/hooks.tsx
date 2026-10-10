"use client";
import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Webhook } from "lucide-react";
import { api, seg, newIdempotencyKey } from "@/lib/client/api";
import { scope, downloadJson, type Hook, type PageResult, type Signature } from "@/lib/hook/api";
import { useHookScope } from "./context";
import { Blank, Copy, Modal, Status } from "./common";
import { Page, PageHeader, Surface } from "@/components/foundation/layout/layout";
import { ErrorAlert } from "@/components/foundation/feedback/error-alert";
import { Button } from "@/components/arc/button/button";
import { Input } from "@/components/arc/input/input";
import { Textarea } from "@/components/arc/textarea/textarea";
import { Checkbox } from "@/components/arc/checkbox/checkbox";
import { Select } from "@/components/arc/select/select";
import { ConfirmMorph } from "@/components/arc/confirm-morph/confirm-morph";

const algorithms = ["HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "SHA1", "SHA256", "SHA384", "SHA512", "Ed25519", "ECDSA-SHA256", "RSA-SHA1", "RSA-SHA256"];
const options = (values: string[]) => values.map(value => ({ value, label: value }));
const defaults: Signature = { required: true, algorithm: "HMAC-SHA256", payload: 'concat(request.headers["webhook-id"], ".", request.headers["webhook-timestamp"], ".", request.raw_body)', signature: 'request.headers["webhook-signature"]', signature_encoding: "base64", secret_encoding: "utf8", public_key: null };
export function HooksPage() {
  const { selected } = useHookScope();
  return <Page><PageHeader title="Hooks" description="A verified endpoint for every signal your Silicon receives." />{selected ? <Hooks key={selected.silicon.uuid} uuid={selected.silicon.uuid} manage={selected.access !== "view"} /> : <Blank title="Choose a Silicon">Silicons you look after or have access to appear above.</Blank>}</Page>;
}
function Hooks({ uuid, manage }: { uuid: string; manage: boolean }) {
  const client = useQueryClient();
  const operationKeys = useRef(new Map<string, string>());
  const keyFor = (operation: string) => { if (!operationKeys.current.has(operation)) operationKeys.current.set(operation, newIdempotencyKey()); return operationKeys.current.get(operation)!; };
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [checked, setChecked] = useState<string[]>([]);
  const [edit, setEdit] = useState<Hook | "new" | null>(null);
  const [detail, setDetail] = useState<Hook | null>(null);
  const [reveal, setReveal] = useState<{ endpoint?: string; secret?: string | null; instructions?: string[] } | null>(null);
  const query = useQuery({ queryKey: ["hooks", uuid], queryFn: () => api.get<PageResult<Hook>>(scope(uuid, "/hooks"), { query: { include_deleted: true } }) });
  const refresh = async () => { await client.invalidateQueries({ queryKey: ["hooks", uuid] }); };
  const change = useMutation({ mutationFn: async ({ hook, action }: { hook: Hook; action: string }) => {
    const path = scope(uuid, `/hooks/${seg(hook.id)}`);
    const operation = `${hook.id}:${action}`;
    const options = { idempotencyKey: keyFor(operation) };
    if (action === "delete") await api.delete(path);
    else if (action === "restore") await api.post(path + "/restore", undefined, options);
    else if (action === "secret") { const data = await api.post<{ signing_secret: string }>(path + "/secret/rotate", undefined, options); setReveal({ endpoint: hook.endpoint_url, secret: data.signing_secret }); }
    else if (action === "endpoint") { const data = await api.post<Hook>(path + "/endpoint/rotate", undefined, options); setReveal({ endpoint: data.endpoint_url }); }
    else await api.patch(path, { enabled: action === "enable" });
    operationKeys.current.delete(operation); setDetail(null); await refresh();
  } });
  const bulk = useMutation({ mutationFn: async (enabled: boolean) => { await api.patch(scope(uuid, "/hooks"), { hook_ids: checked, enabled }); setChecked([]); await refresh(); } });
  const connect = useMutation({ mutationFn: async () => { const data = await api.post<{ hook: Hook; next_steps: { set_webhook: string; store_secret: string; explanation: string } }>(scope(uuid, "/hooks/accounts"), undefined, { idempotencyKey: keyFor("accounts") }); operationKeys.current.delete("accounts"); setReveal({ endpoint: data.hook.endpoint_url, secret: data.hook.signing_secret, instructions: Object.values(data.next_steps) }); await refresh(); } });
  const all = query.data?.items ?? [];
  const filtered = all.filter(h => (status === "all" || h.status === status) && `${h.name} ${h.description ?? ""} ${h.endpoint_url}`.toLowerCase().includes(search.toLowerCase()));
  const editable = filtered.filter(h => h.status !== "deleted");
  return <div className="hook-stack">
    <div className="hook-toolbar"><p className="hook-muted">{all.filter(h => h.status === "active").length} active · {all.filter(h => h.status === "disabled").length} disabled · {all.filter(h => h.status === "deleted").length} in recovery</p><div className="hook-actions"><Button variant="secondary" onClick={() => void query.refetch()} loading={query.isFetching}>Refresh</Button>{manage && <><Button variant="secondary" onClick={() => connect.mutate()} loading={connect.isPending}>Connect Accounts</Button><Button onClick={() => setEdit("new")}><Plus size={16} />New hook</Button></>}</div></div>
    <div className="hook-filters"><Input label="Search hooks" placeholder="Name, description or endpoint" value={search} onChange={e => setSearch(e.target.value)} /><Select label="Status" value={status} onValueChange={setStatus} options={options(["all", "active", "disabled", "deleted"])} /></div>
    {[query.error, change.error, bulk.error, connect.error].filter(Boolean).map((error, index) => <ErrorAlert key={index} error={error!} />)}
    {manage && editable.length > 0 && <div className="hook-toolbar"><Checkbox label="Select visible hooks" checked={editable.every(h => checked.includes(h.id))} onCheckedChange={on => setChecked(on === true ? editable.map(h => h.id) : [])} /><div className="hook-actions"><span>{checked.length} selected</span><Button variant="secondary" size="sm" disabled={!checked.length} loading={bulk.isPending} onClick={() => bulk.mutate(true)}>Enable selected</Button><Button variant="secondary" size="sm" disabled={!checked.length} loading={bulk.isPending} onClick={() => bulk.mutate(false)}>Disable selected</Button></div></div>}
    {query.isLoading ? <p role="status">Loading hooks…</p> : !filtered.length ? <Blank title={all.length ? "No matching hooks" : "Your next signal starts here"}>{all.length ? "Try another search or status." : "Create a hook, then add its endpoint and signing secret to your provider."}</Blank> : <div className="hook-list">{filtered.map(h => <Surface key={h.id} className="hook-card"><div className="hook-card-head"><div className="hook-actions">{manage && h.status !== "deleted" && <Checkbox aria-label={`Select ${h.name}`} checked={checked.includes(h.id)} onCheckedChange={on => setChecked(on === true ? [...checked, h.id] : checked.filter(id => id !== h.id))} />}<Webhook size={20} aria-hidden /><div><Button variant="ghost" onClick={() => setDetail(h)}>{h.name}</Button><p className="hook-muted">{h.description || "Webhook endpoint"}</p></div></div><Status value={h.status} /></div><Copy value={h.endpoint_url} /><div className="hook-toolbar hook-muted"><span>{h.signature.required ? h.signature.algorithm : "Signature optional"} · {h.time_zone}</span><span>{h.last_received_at ? `Last received ${new Date(h.last_received_at).toLocaleString()}` : "Waiting for the first request"}</span></div><div className="hook-actions"><Button variant="secondary" size="sm" onClick={() => setDetail(h)}>View details</Button>{manage && (h.status === "deleted" ? <Button size="sm" variant="secondary" onClick={() => change.mutate({ hook: h, action: "restore" })} disabled={change.isPending}>Restore</Button> : <><Button size="sm" variant="secondary" onClick={() => setEdit(h)}>Edit</Button><Button size="sm" variant="ghost" disabled={change.isPending} onClick={() => change.mutate({ hook: h, action: h.status === "active" ? "disable" : "enable" })}>{h.status === "active" ? "Disable" : "Enable"}</Button></>)}</div></Surface>)}</div>}
    {edit && <HookEditor uuid={uuid} hook={edit === "new" ? undefined : edit} close={() => setEdit(null)} saved={async h => { setEdit(null); if (h.signing_secret) setReveal({ endpoint: h.endpoint_url, secret: h.signing_secret }); await refresh(); }} />}
    {reveal && <Modal title={reveal.secret ? "Save your signing secret" : "Endpoint ready"} description={reveal.secret ? "The secret is shown once. Copy it to your provider before closing." : "Use this endpoint in your provider configuration."} close={() => setReveal(null)}><div className="hook-stack">{reveal.endpoint && <Copy value={reveal.endpoint} />}{reveal.secret && <Copy value={reveal.secret} />}{reveal.instructions?.map((line, i) => <p key={i}>{line}</p>)}<Button variant="secondary" onClick={() => downloadJson(reveal, "hook-connection.json")}>Download connection details</Button><Button onClick={() => setReveal(null)}>Done</Button></div></Modal>}
    {detail && <Modal title={detail.name} description={detail.description ?? "Webhook configuration"} close={() => setDetail(null)}><div className="hook-stack"><Status value={detail.status} /><Copy value={detail.endpoint_url} /><dl className="hook-facts"><dt>Created</dt><dd>{new Date(detail.created_at).toLocaleString()}</dd><dt>Time zone</dt><dd>{detail.time_zone}</dd><dt>Signature</dt><dd>{detail.signature.required ? detail.signature.algorithm : "Optional"}</dd>{detail.recoverable_until && <><dt>Recoverable until</dt><dd>{new Date(detail.recoverable_until).toLocaleString()}</dd></>}</dl><details><summary>Signature expressions</summary><pre>{JSON.stringify(detail.signature, null, 2)}</pre></details>{manage && detail.status !== "deleted" && <><ConfirmMorph label="Rotate signing secret" prompt="Replace the secret? Update your provider afterwards." confirmLabel="Rotate" pendingLabel="Rotating" doneLabel="Rotated" tone="neutral" onConfirm={() => change.mutateAsync({ hook: detail, action: "secret" })} /><ConfirmMorph label="Rotate endpoint URL" prompt="Replace this URL? The current endpoint will stop working." confirmLabel="Rotate URL" pendingLabel="Rotating" doneLabel="Rotated" tone="neutral" onConfirm={() => change.mutateAsync({ hook: detail, action: "endpoint" })} /><ConfirmMorph label="Delete hook" prompt="Delete this hook? It can be restored for 45 days." onConfirm={() => change.mutateAsync({ hook: detail, action: "delete" })} /></>}</div></Modal>}
  </div>;
}
function HookEditor({ uuid, hook, close, saved }: { uuid: string; hook?: Hook; close: () => void; saved: (hook: Hook) => Promise<void> }) {
  const [createKey] = useState(newIdempotencyKey);
  const [name, setName] = useState(hook?.name ?? "");
  const [description, setDescription] = useState(hook?.description ?? "");
  const [zone, setZone] = useState(hook?.time_zone ?? Intl.DateTimeFormat().resolvedOptions().timeZone);
  const [signature, setSignature] = useState<Signature>(hook?.signature ?? defaults);
  const [secret, setSecret] = useState("");
  const set = <K extends keyof Signature>(key: K, value: Signature[K]) => setSignature(old => ({ ...old, [key]: value }));
  const mutation = useMutation({ mutationFn: async () => {
    const body = { name, description: description || null, time_zone: zone, signature: { required: signature.required, algorithm: signature.algorithm, payload: signature.payload, signature: signature.signature, signature_encoding: signature.signature_encoding, secret_encoding: signature.secret_encoding, public_key: signature.public_key || null, ...(secret ? { secret } : {}) } };
    const result = hook ? await api.patch<Hook>(scope(uuid, `/hooks/${seg(hook.id)}`), body) : await api.post<Hook>(scope(uuid, "/hooks"), body, { idempotencyKey: createKey });
    await saved(result);
  } });
  return <Modal title={hook ? "Edit hook" : "Create a hook"} description="Start with Standard Webhooks, or match your provider’s signing convention." close={close}><form className="hook-stack" onSubmit={e => { e.preventDefault(); mutation.mutate(); }}>
    <Input label="Name" required maxLength={200} value={name} onChange={e => setName(e.target.value)} autoFocus /><Textarea label="Description" value={description} onChange={e => setDescription(e.target.value)} /><Input label="Time zone" required value={zone} onChange={e => setZone(e.target.value)} />
    <Checkbox label="Require a valid signature" description="Unsigned or invalid requests are kept in Blocked requests." checked={signature.required} onCheckedChange={on => set("required", on === true)} />
    <Select label="Signature algorithm" value={signature.algorithm} onValueChange={value => set("algorithm", value)} options={options(algorithms)} />
    <Textarea label="Signed payload expression" required value={signature.payload} onChange={e => set("payload", e.target.value)} /><Textarea label="Signature expression" required value={signature.signature} onChange={e => set("signature", e.target.value)} />
    <div className="hook-grid"><Select label="Signature encoding" value={signature.signature_encoding} onValueChange={value => set("signature_encoding", value)} options={options(["hex", "base64", "base64url", "raw"])} /><Select label="Secret encoding" value={signature.secret_encoding} onValueChange={value => set("secret_encoding", value)} options={options(["utf8", "ascii", "hex", "base64", "base64url", "raw"])} /></div>
    {signature.algorithm.startsWith("HMAC") || signature.algorithm.startsWith("SHA") ? <Input label={hook ? "Replace signing secret (optional)" : "Your signing secret (optional)"} type="password" autoComplete="new-password" value={secret} onChange={e => setSecret(e.target.value)} description={hook ? "Leave empty to keep the current secret." : "Leave empty for a generated secret."} /> : <Textarea label="Public key (PEM)" value={signature.public_key ?? ""} onChange={e => set("public_key", e.target.value)} />}
    {mutation.error && <ErrorAlert error={mutation.error} />}<div className="hook-actions"><Button type="submit" loading={mutation.isPending}>{hook ? "Save changes" : "Create hook"}</Button><Button variant="secondary" onClick={close}>Cancel</Button></div>
  </form></Modal>;
}
