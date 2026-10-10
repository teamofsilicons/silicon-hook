const key = "hook.telemetry";
export const subscribeTelemetry = (listener: () => void) => { window.addEventListener("storage", listener); window.addEventListener("hook:preferences", listener); return () => { window.removeEventListener("storage", listener); window.removeEventListener("hook:preferences", listener); }; };
export function telemetryEnabled() { try { return localStorage.getItem(key) !== "off"; } catch { return true; } }
export function setTelemetry(enabled: boolean) { try { localStorage.setItem(key, enabled ? "on" : "off"); } catch { /* The preference remains at the browser default when storage is blocked. */ } window.dispatchEvent(new Event("hook:preferences")); }
