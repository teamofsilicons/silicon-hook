"use client";
import { useSyncExternalStore, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiError } from "@/lib/errors";
import { api } from "@/lib/client/api";
import { useSessionView, useSignOut } from "@/lib/client/session";
import { appConfig } from "@/lib/app.config";
import { useTheme, type ThemePreference } from "@/components/foundation/theme/use-theme";
import { telemetryEnabled, setTelemetry, subscribeTelemetry } from "@/lib/hook/preferences";
import { Page, PageHeader, Section, SettingsGroup, SettingsRow, Surface } from "@/components/foundation/layout/layout";
import { ErrorAlert } from "@/components/foundation/feedback/error-alert";
import { Select } from "@/components/arc/select/select";
import { Checkbox } from "@/components/arc/checkbox/checkbox";
import { Button } from "@/components/arc/button/button";
import { Copy } from "./common";
export function SettingsPage() {
  const session = useSessionView();
  const { signOut, pending } = useSignOut();
  const [signOutError, setSignOutError] = useState<ApiError | null>(null);
  const theme = useTheme();
  const telemetry = useSyncExternalStore(subscribeTelemetry, telemetryEnabled, () => true);
  const health = useQuery({ queryKey: ["service-diagnostics"], queryFn: () => api.get<Record<string, unknown>>("/api/v3/version") });
  return <Page width="reading"><PageHeader title="Settings" description="Your account, appearance and service details." /><div className="hook-stack">{signOutError && <ErrorAlert error={signOutError} />}<Section title="Your account"><SettingsGroup><SettingsRow label={session.account?.id || "Signed in with Silicon Accounts"} description="Profile and sign-in methods are managed in Silicon Accounts."><Button variant="secondary" loading={pending} onClick={() => { void signOut().catch(error => setSignOutError(error instanceof ApiError ? error : new ApiError({status: 0, code: "sign_out_failed", message: String(error)}))); }}>Sign out</Button></SettingsRow></SettingsGroup></Section><Section title="Preferences"><SettingsGroup><SettingsRow label="Appearance" description="Follow your system or choose a theme."><Select label="Theme" value={theme.preference} onValueChange={value => theme.set(value as ThemePreference)} options={[{ value: "system", label: "System" }, { value: "light", label: "Light" }, { value: "dark", label: "Dark" }]} /></SettingsRow><SettingsRow label="Usage telemetry" description="Allow anonymous operation diagnostics for requests from this browser."><Checkbox label="Enable telemetry" checked={telemetry} onCheckedChange={value => setTelemetry(value === true)} /></SettingsRow></SettingsGroup></Section><Section title="Use Hook from your terminal" description="Install and update through Silicon Apps."><Surface className="hook-stack"><Copy value="silicon-apps install hook" /><Copy value="hook login" /><div className="hook-actions"><a href={appConfig.links.store} target="_blank" rel="noreferrer">Open in Silicon Apps ↗</a><a href={appConfig.links.docs} target="_blank" rel="noreferrer">Read the documentation ↗</a></div></Surface></Section><Section title="Service diagnostics" actions={<Button size="sm" variant="secondary" onClick={() => void health.refetch()}>Refresh</Button>}>{health.error ? <ErrorAlert error={health.error} /> : <Surface><pre>{health.isLoading ? "Loading service details…" : JSON.stringify(health.data, null, 2)}</pre></Surface>}</Section></div></Page>;
}
