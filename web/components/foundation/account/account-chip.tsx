/**
 * An account as Carbons and Silicons recognise it: its photo (or initials), its display name when the app knows it,
 * its c: or si: id, and whether it is a Carbon or a Silicon. Every app shows accounts this way now that sharing names
 * exact accounts (there are no groups of accounts to show instead).
 *
 *   <AccountChip account={item.owner} />                          a row: photo, name, then id · Carbon
 *   <AccountChip account={share} variant="chip" onRemove={…} />   a compact pill with a remove button
 *
 * `account` needs `id` and `kind`; `display_name` and `pfp_url` show when the service returns them (an app learns them
 * when the account signs in to it). Keys stay uuids; the id shown is the current one.
 */
import type { ReactNode } from "react";
import { X } from "lucide-react";
import { Avatar } from "@/components/silicon-ui/avatar/avatar";
import { kindNoun, type AccountKind } from "@/lib/format";
import styles from "./account-chip.module.css";

export interface ChipAccount {
  uuid?: string;
  id: string;
  kind: AccountKind;
  display_name?: string | null;
  pfp_url?: string | null;
}

export interface AccountChipProps {
  account: ChipAccount;
  variant?: "row" | "chip";
  /** "Owner", "You": a word after the kind. */
  note?: string;
  /** Adds a remove button (chips): named "Remove {id}". */
  onRemove?: () => void;
  removeLabel?: string;
  /** A state shown on the chip: resolving (pulses), or a problem (danger edge; say why next to it). */
  state?: "resolving" | "problem";
  trailing?: ReactNode;
  className?: string;
}

/** The Carbon or Silicon marker: a word, so it never depends on colour or an icon alone. */
export function KindMarker({ kind, size = "sm" }: { kind: AccountKind; size?: "sm" | "xs" }) {
  return <span className={styles.kind} data-kind={kind} data-size={size} data-sq="surface">{kindNoun(kind)}</span>;
}

export function AccountChip({ account, variant = "row", note, onRemove, removeLabel, state, trailing, className }: AccountChipProps) {
  const name = account.display_name?.trim() || null;
  const avatar = <Avatar name={name ?? account.id.replace(/^(c|si):/, "")} src={account.pfp_url ?? undefined} size="sm" className={styles.avatar} />;
  if (variant === "chip") {
    return (
      <span className={[styles.chip, className].filter(Boolean).join(" ")} data-sq="surface" data-state={state}>
        {avatar}
        <span className={styles.chipText}>
          {name ? <span className={styles.name}>{name}</span> : null}
          <span className={name ? styles.idMuted : styles.name}>{account.id}</span>
        </span>
        <KindMarker kind={account.kind} size="xs" />
        {onRemove ? (
          <button type="button" className={styles.remove} onClick={onRemove} aria-label={removeLabel ?? `Remove ${account.id}`}>
            <X size={14} strokeWidth={1.8} aria-hidden="true" />
          </button>
        ) : null}
      </span>
    );
  }
  return (
    <span className={[styles.row, className].filter(Boolean).join(" ")} data-state={state}>
      {avatar}
      <span className={styles.rowText}>
        <span className={styles.name}>{name ?? account.id}</span>
        <span className={styles.meta}>
          {name ? <span className={styles.id}>{account.id}</span> : null}
          <KindMarker kind={account.kind} />
          {note ? <span className={styles.note}>{note}</span> : null}
        </span>
      </span>
      {trailing}
    </span>
  );
}
