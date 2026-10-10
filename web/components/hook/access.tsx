"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, seg } from "@/lib/client/api";
import { scope, type Access, type AllowList } from "@/lib/hook/api";
import { useHookScope } from "./context";
import { Blank, Status } from "./common";
import { Page, PageHeader, Section, Surface } from "@/components/foundation/layout/layout";
import { ErrorAlert } from "@/components/foundation/feedback/error-alert";
import { Button } from "@/components/arc/button/button";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { ConfirmMorph } from "@/components/arc/confirm-morph/confirm-morph";
export function AccessPage() {
  const { selected } = useHookScope();
  return <Page width="reading"><PageHeader title="Access" description="Choose exactly which Carbons and Silicons can use this Silicon’s hooks." />{selected ? <AccessEditor key={selected.silicon.uuid} uuid={selected.silicon.uuid} /> : <Blank title="Choose a Silicon">Select a Silicon to see its access and allow-list.</Blank>}</Page>;
}
function AccessEditor({ uuid }: { uuid: string }) {
  const client = useQueryClient();
  const [account, setAccount] = useState("");
  const [allowed, setAllowed] = useState("");
  const [level, setLevel] = useState("view");
  const access = useQuery({ queryKey: ["access", uuid], queryFn: () => api.get<Access>(scope(uuid, "/access")) });
  const list = useQuery({ queryKey: ["allow-list", uuid], queryFn: () => api.get<AllowList>(scope(uuid, "/allow-list")) });
  const owner = access.data?.you.access === "custodian" || access.data?.you.access === "self";
  const mutation = useMutation({ mutationFn: async ({ group, id, remove, accessLevel }: { group: "access" | "allow-list"; id: string; remove?: boolean; accessLevel?: string }) => {
    const path = scope(uuid, `/${group}/${seg(id.trim())}`);
    if (remove) await api.delete(path); else await api.put(path, group === "access" ? { level: accessLevel ?? level } : undefined);
    setAccount(""); setAllowed(""); await Promise.all([client.invalidateQueries({ queryKey: [group, uuid] }), client.invalidateQueries({ queryKey: ["silicons"] })]);
  } });
  return <div className="hook-stack">{[access.error, list.error, mutation.error].filter(Boolean).map((error, index) => <ErrorAlert key={index} error={error!} />)}{access.data && <Surface><div className="hook-toolbar"><div><h2 className="hook-panel-title">{access.data.silicon.id || uuid}</h2><p className="hook-muted">Custodian: {access.data.custodian?.id || access.data.custodian?.uuid || "None"}</p></div><Status value={access.data.you.access} /></div>{!owner && <p className="hook-muted">Only the Silicon and its custodian can change grants and the allow-list.</p>}</Surface>}
    <Section title="Shared access" description="View reads hooks, requests and deliveries. Manage also creates and changes hooks."><Surface><div className="hook-stack">{owner && <form className="hook-stack" onSubmit={e => { e.preventDefault(); mutation.mutate({ group: "access", id: account }); }}><div className="hook-grid"><Input label="Carbon or Silicon ID" placeholder="c:ada or si:scout" value={account} onChange={e => setAccount(e.target.value)} required /><Select label="Access level" value={level} onValueChange={setLevel} options={[{ value: "view", label: "View" }, { value: "manage", label: "Manage" }]} /></div><Button type="submit" loading={mutation.isPending}>Grant access</Button></form>}<div>{access.data?.grants.length ? access.data.grants.map(grant => <div className="hook-account" key={grant.account.uuid}><div><strong>{grant.account.id || grant.account.uuid}</strong><small>Granted by {grant.granted_by.id || grant.granted_by.uuid}</small></div><div className="hook-actions">{owner ? <Select label={`Access for ${grant.account.id || grant.account.uuid}`} value={grant.level} onValueChange={value => mutation.mutate({ group: "access", id: grant.account.uuid, accessLevel: value })} options={[{ value: "view", label: "View" }, { value: "manage", label: "Manage" }]} /> : <Status value={grant.level} />}{(owner || grant.account.uuid === access.data?.you.account.uuid) && <ConfirmMorph label={owner ? "Revoke" : "Leave"} prompt="End this account’s shared access?" confirmLabel="Revoke" pendingLabel="Revoking" doneLabel="Revoked" disabled={mutation.isPending} onConfirm={() => mutation.mutateAsync({ group: "access", id: grant.account.uuid, remove: true })} />}</div></div>) : <p className="hook-muted">No explicit grants. The Silicon and its custodian retain access.</p>}</div></div></Surface></Section>
    <Section title="Allow-list" description="Let accounts outside the custodian circle grant access into this Silicon."><Surface><div className="hook-stack">{owner && <form className="hook-stack" onSubmit={e => { e.preventDefault(); mutation.mutate({ group: "allow-list", id: allowed }); }}><Input label="Allow Carbon or Silicon" placeholder="c:ada or si:scout" value={allowed} onChange={e => setAllowed(e.target.value)} required /><Button type="submit" loading={mutation.isPending}>Allow account</Button></form>}<div>{list.data?.items.length ? list.data.items.map(entry => <div className="hook-account" key={entry.account.uuid}><strong>{entry.account.id || entry.account.uuid}</strong>{owner && <ConfirmMorph label="Remove" prompt="Remove this account from the allow-list?" confirmLabel="Remove" doneLabel="Removed" onConfirm={() => mutation.mutateAsync({ group: "allow-list", id: entry.account.uuid, remove: true })} />}</div>) : <p className="hook-muted">No accounts outside the circle are allowed.</p>}</div></div></Surface></Section></div>;
}
