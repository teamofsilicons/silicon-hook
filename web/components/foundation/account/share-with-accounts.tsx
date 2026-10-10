"use client";

/**
 * Share with exact accounts: type a Carbon's c: id or a Silicon's si: id, press Enter (or a comma, or a space), and it
 * becomes a chip. The format is checked as you add it (lib/ids.ts, with the reason when it is wrong); the app's service
 * then looks the id up (`resolve`, usually GET /v1/accounts/resolve?id=…) and the chip shows the account's photo and
 * display name when the service returns them, or why it could not be found. Every app needs this now that nothing is
 * shared with a group: sharing names accounts, the service stores their uuids and shows their current ids.
 *
 *   <ShareWithAccounts label="Share with" ids={ids} onIdsChange={setIds} known={item.shares}
 *     resolve={(id, signal) => api.get(`/v1/accounts/resolve`, { query: { id }, signal })} selfId={account.id} />
 *
 * The control holds ids; save them with the page's own action (PUT …/shares). A 422 from the service names the ids it
 * refused (`errors`, from ApiError.fields), and their chips say why.
 */
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { motionTokens } from "@/components/silicon-ui/lib/motion-tokens";
import { ApiError } from "@/lib/errors";
import { parseAccountId } from "@/lib/ids";
import { AccountChip, type ChipAccount } from "./account-chip";
import styles from "./share-with-accounts.module.css";

export interface ShareWithAccountsProps {
  label: string;
  /** One line under the field: who sees what once shared. */
  description?: string;
  /** The ids shared with (c:… / si:…), in order. */
  ids: string[];
  onIdsChange: (ids: string[]) => void;
  /** Accounts the page already knows (the service's answer): shown with photo and name without a lookup. */
  known?: ChipAccount[];
  /** Looks an id up; rejects with ApiError (404 account_not_found) when there is no such account. */
  resolve?: (id: string, signal: AbortSignal) => Promise<ChipAccount>;
  /** Messages from the service per id (a 422's details.fields), shown on those chips. */
  errors?: Record<string, string>;
  /** The signed-in account's id: sharing with yourself is refused (you always see your own things). */
  selfId?: string;
  /** At most this many accounts (default 50). */
  max?: number;
  disabled?: boolean;
  placeholder?: string;
  id?: string;
}

type Lookup = { status: "resolving" } | { status: "found"; account: ChipAccount } | { status: "missing"; message: string };

export function ShareWithAccounts({ label, description, ids, onIdsChange, known = [], resolve, errors = {}, selfId, max = 50, disabled, placeholder = "c:ada or si:scout", id }: ShareWithAccountsProps) {
  const generated = useId();
  const inputId = id ?? `share-${generated}`;
  const hintId = `${inputId}-hint`;
  const problemId = `${inputId}-problem`;
  const reduced = useReducedMotion() ?? false;
  const inputRef = useRef<HTMLInputElement>(null);
  const [draft, setDraft] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [lookups, setLookups] = useState<Record<string, Lookup>>({});
  const [pulse, setPulse] = useState<string | null>(null);
  const controllers = useRef(new Map<string, AbortController>());

  const knownById = useMemo(() => new Map(known.map(account => [account.id.toLowerCase(), account])), [known]);

  // Look up every id the page does not know yet (once per id).
  useEffect(() => {
    if (!resolve) return;
    for (const value of ids) {
      if (knownById.has(value) || lookups[value] || controllers.current.has(value)) continue;
      const controller = new AbortController();
      controllers.current.set(value, controller);
      setLookups(current => ({ ...current, [value]: { status: "resolving" } }));
      resolve(value, controller.signal)
        .then(account => setLookups(current => ({ ...current, [value]: { status: "found", account } })))
        .catch(error => {
          const failure = ApiError.from(error);
          if (failure.code === "aborted") return;
          setLookups(current => ({ ...current, [value]: { status: "missing", message: failure.status === 404 ? failure.message : `Could not check ${value}: ${failure.message}` } }));
          setNotice(`${value} could not be found.`);
        })
        .finally(() => controllers.current.delete(value));
    }
  }, [ids, knownById, lookups, resolve]);

  useEffect(() => () => {
    for (const controller of controllers.current.values()) controller.abort();
  }, []);

  function add(raw: string): boolean {
    const text = raw.trim();
    if (!text) return true;
    const check = parseAccountId(text);
    if (!check.ok) {
      setProblem(check.message);
      return false;
    }
    const value = check.value.id;
    if (selfId && value === selfId.toLowerCase()) {
      setProblem(`${value} is you: you always see your own things.`);
      return false;
    }
    if (ids.includes(value)) {
      setPulse(value);
      setProblem(null);
      setNotice(`${value} is already on the list.`);
      return true;
    }
    if (ids.length >= max) {
      setProblem(`You can share with at most ${max} accounts at once.`);
      return false;
    }
    onIdsChange([...ids, value]);
    setProblem(null);
    setNotice(`Added ${value}.`);
    return true;
  }

  function remove(value: string) {
    controllers.current.get(value)?.abort();
    controllers.current.delete(value);
    setLookups(current => {
      const next = { ...current };
      delete next[value];
      return next;
    });
    onIdsChange(ids.filter(item => item !== value));
    setNotice(`Removed ${value}.`);
    inputRef.current?.focus();
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Enter" || event.key === "," || (event.key === " " && draft.trim())) {
      event.preventDefault();
      if (add(draft)) setDraft("");
    } else if (event.key === "Backspace" && !draft && ids.length) {
      event.preventDefault();
      remove(ids[ids.length - 1]!);
    }
  }

  // Several ids pasted at once ("c:ada, si:scout c:grace") are added one by one; what fails stays in the field.
  function onPaste(text: string): boolean {
    const parts = text.split(/[\s,;]+/).filter(Boolean);
    if (parts.length < 2) return false;
    const left = parts.filter(part => !add(part));
    setDraft(left.join(" "));
    return true;
  }

  const chips = ids.map(value => {
    const lookup = lookups[value];
    const account: ChipAccount = knownById.get(value) ?? (lookup?.status === "found" ? lookup.account : { id: value, kind: value.startsWith("si:") ? "silicon" : "carbon" });
    const message = errors[value] ?? (lookup?.status === "missing" ? lookup.message : undefined);
    return { value, account, message, resolving: lookup?.status === "resolving" };
  });
  const problems = chips.filter(chip => chip.message);
  const described = [description ? hintId : null, problem || problems.length ? problemId : null].filter(Boolean).join(" ") || undefined;

  return (
    <div className={styles.field}>
      <label htmlFor={inputId} className={styles.label}>{label}</label>
      <div className={styles.control} data-sq="surface" data-invalid={problem ? "" : undefined} data-disabled={disabled ? "" : undefined} onClick={event => { if (event.target === event.currentTarget) inputRef.current?.focus(); }}>
        <ul className={styles.chips} role="list" aria-label={`${label}: ${ids.length === 0 ? "nobody yet" : `${ids.length} account${ids.length === 1 ? "" : "s"}`}`}>
          <AnimatePresence initial={false} mode="popLayout">
            {chips.map(chip => (
              <motion.li
                key={chip.value}
                layout={reduced ? false : "position"}
                className={styles.item}
                initial={reduced ? { opacity: 0 } : { opacity: 0, scale: .9, filter: `blur(${motionTokens.blur.soft}px)` }}
                animate={pulse === chip.value && !reduced ? { opacity: 1, scale: [1, 1.06, 1], filter: "blur(0px)" } : { opacity: 1, scale: 1, filter: "blur(0px)" }}
                exit={reduced ? { opacity: 0, transition: { duration: 0 } } : { opacity: 0, scale: .9, filter: `blur(${motionTokens.blur.subtle}px)`, transition: { duration: motionTokens.duration.instant } }}
                transition={reduced ? { duration: motionTokens.duration.instant } : { ...motionTokens.spring.morph, opacity: { duration: motionTokens.duration.fast } }}
                onAnimationComplete={() => { if (pulse === chip.value) setPulse(null); }}
              >
                <AccountChip account={chip.account} variant="chip" state={chip.message ? "problem" : chip.resolving ? "resolving" : undefined} onRemove={disabled ? undefined : () => remove(chip.value)} />
              </motion.li>
            ))}
          </AnimatePresence>
        </ul>
        <input
          ref={inputRef}
          id={inputId}
          className={styles.input}
          value={draft}
          disabled={disabled}
          placeholder={ids.length ? "Add another" : placeholder}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          enterKeyHint="done"
          aria-invalid={problem ? true : undefined}
          aria-describedby={described}
          onChange={event => {
            setDraft(event.currentTarget.value);
            if (problem) setProblem(null);
          }}
          onKeyDown={onKeyDown}
          onPaste={event => {
            if (onPaste(event.clipboardData.getData("text"))) event.preventDefault();
          }}
          onBlur={() => {
            if (draft.trim() && add(draft)) setDraft("");
          }}
        />
      </div>
      {problem || problems.length ? (
        <div id={problemId} className={styles.problem} role="alert">
          {problem ? <p>{problem}</p> : null}
          {problems.map(chip => <p key={chip.value}><strong>{chip.value}</strong>: {chip.message}</p>)}
        </div>
      ) : null}
      {description ? <p id={hintId} className={styles.hint}>{description}</p> : null}
      <span className="sr-only" aria-live="polite">{notice}</span>
    </div>
  );
}
