"use client";
import { createContext, useContext, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { listSilicons, type SiliconEntry } from "@/lib/hook/api";
import { Select } from "@/components/arc/select/select";
import { Button } from "@/components/arc/button/button";
import { ErrorAlert } from "@/components/foundation/feedback/error-alert";
const Context = createContext<{ selected: SiliconEntry | undefined; items: SiliconEntry[]; setUuid: (uuid: string) => void }>({ selected: undefined, items: [], setUuid: () => {} });
export function HookScope({ children }: { children: ReactNode }) {
  const [uuid, setUuid] = useState("");
  const query = useQuery({ queryKey: ["silicons"], queryFn: listSilicons, refetchInterval: 30000 });
  const items = query.data?.items ?? [];
  const selected = items.find(item => item.silicon.uuid === uuid) ?? items[0];
  return <Context.Provider value={{ selected, items, setUuid }}><div className="hook-scope">
    <Select label="Viewing Silicon" value={selected?.silicon.uuid ?? ""} onValueChange={setUuid} placeholder={query.isLoading ? "Loading Silicons…" : "No Silicons yet"} options={items.map(item => ({ value: item.silicon.uuid, label: `${item.silicon.id ?? item.silicon.uuid} · ${item.access === "custodian" ? "Your Silicon" : item.access}` }))} />
    <Button variant="ghost" size="sm" onClick={() => void query.refetch()} loading={query.isFetching}>Refresh</Button>
  </div>{query.error && <ErrorAlert error={query.error} title="Silicons could not be loaded" />}{children}</Context.Provider>;
}
export const useHookScope = () => useContext(Context);
