# The Silicon design system

What the developer site (developers.teamofsilicons.com), the account site (accounts.teamofsilicons.com) and the store
(apps.teamofsilicons.com) have in common, written down so every app's web frontend looks like part of the same
family. The kit implements all of it; this page is the reasoning and the rules for what you add.

## Principles

1. **One look, two modes.** Light and dark (or the device's), nothing else. Every colour is a token with a value in
   both; a page never hard-codes a colour.
2. **Calm chrome, content first.** Bars and sidebars sit on the page colour with hairlines, not boxes. The page's own
   title is the loudest thing on screen.
3. **Brand blue is where you act.** Filled blue is for the one primary action of a surface, the current item's
   indicator and links. Never for decoration, never for two buttons side by side.
4. **Every rounded surface is a squircle.** Controls, cards, chips, menus, photos: the same superellipse curve at a few
   sizes.
5. **Borders, not shadows.** Things that rest on the page have a 1 px border; only floating layers (menus, dialogs,
   toasts, the palette) cast a shadow.
6. **Words for Carbons and Silicons.** Plain, exact, in sentence case; errors say what happened, why, and what to do.
7. **Everyone can use it.** WCAG 2.2 AA: 4.5:1 text, a visible keyboard position on every control, reduced motion
   respected, nothing told by colour alone.

## Colour

Use the semantic tokens (`styles/tokens.css`), never the hex values.

| Token | Light | Dark | For |
| --- | --- | --- | --- |
| `--background` | `#F7F8FA` | `#02040A` | the page |
| `--surface` | `#FFFFFF` | `#0B0F18` | cards, panels, fields |
| `--surface-raised` | `#FFFFFF` | `#121826` | menus, dialogs, popovers |
| `--surface-muted` | `#EEF0F4` | `#1A2130` | hover fills, tracks, code chips |
| `--foreground` | `#292929` | `#F7F8FA` | text, icons that matter |
| `--text-secondary` | `#4C5260` | `#C2C8D3` | descriptions, secondary values |
| `--text-muted` | `#5C6370` | `#9BA4B4` | hints, timestamps, placeholders |
| `--border` / `-subtle` / `-strong` | `#E2E5EB` / `#EBEDF1` / `#CBD0D8` | `#1F2635` / `#161C28` / `#2F394B` | edges, dividers, hovered edges |
| `--primary` (`-hover`, `-pressed`) | `#1F5FB8` | `#1F5FB8` | filled primary buttons (with `--primary-foreground`) |
| `--accent` | `#1F5FB8` | `#6AA0EE` | indicators, selected states, focus edges |
| `--accent-ink` | `#1F5FB8` | `#7DAEF4` | accent-coloured text (links, eyebrows) |
| `--accent-subtle` | blue at 10 % | blue at 24 % | tinted fills (feature icons, Silicon markers) |
| `--success`, `--warning`, `--danger` | `#18703F`, `#93560A`, `#B42318` | `#4CC38A`, `#E9B24F`, `#FF8A80` | status text and icons |

Every text token clears 4.5:1 on every surface token in its mode (measured; see the comment in `tokens.css`). Keep it
so: a new pair needs checking before it ships.

An app with its own colour sets `appConfig.accent`. It becomes `--app-accent`, which tints the app's mark and the
landing page's wash, and nothing else: actions, links and focus stay brand blue on every Silicon site.

```css
/* Do */
.notice { --sq-fill: var(--surface-muted); color: var(--text-secondary); }
.count[data-over] { color: var(--danger); }

/* Don't: a colour that has no dark value, and blue as decoration */
.notice { background: #eef0f4; color: #4c5260; }
.sectionTitle { color: var(--primary); }
```

## Type

Two faces. **BDO Grotesk** (self-hosted, SIL OFL; 400, 500, 600, 700) is the display face: page titles, section
titles on the public pages, the wordmark, big numbers. Text uses the system face first (SF Pro on Apple devices, whose
licence does not allow serving it) and BDO Grotesk where there is none.

| Use | Size | Weight | Tracking, leading |
| --- | --- | --- | --- |
| Landing headline (h1) | `clamp(2.5rem, 1.6rem + 4vw, 4.25rem)` | 600 display | −0.035em, 1.02 |
| Page title (`PageHeader`) | `clamp(2.25rem, 4.8vw, 3.25rem)` | 600 display | −0.025em, 1.02 |
| Title someone typed (`size="entity"`) | `clamp(1.75rem, 3.2vw, 2.5rem)` | 600 display | −0.025em, 1.08 |
| Landing section title (h2) | `clamp(1.875rem, 1.35rem + 2vw, 2.75rem)` | 600 display | −0.03em, 1.08 |
| Section title in the workspace (h2) | `--text-lg` 1.125rem | 500 text | −0.01em, 1.3 |
| Body | `--text-base` 1rem | 400 | −0.01em, 1.4 (long reading 1.6) |
| Secondary text, table cells, buttons | `--text-sm` 0.875rem | 400 / 500 | 1.4 |
| Labels, hints, badges | `--text-xs` 0.75rem | 500 | 1.4 |
| Code | `--font-mono`, 0.8125 to 0.92em | 400 | 0, 1.7 in blocks |

- One `h1` per page, then `h2` per section; never skip a level for size (style the right level instead).
- Emphasis is weight 500 (`strong` is 500 in `base.css`); 600 only in the display face; never 700 in running text.
- Numbers that line up (counts, times in tables) use `font-variant-numeric: tabular-nums` (`.tabular`).
- Titles balance (`text-wrap: balance`); paragraphs `pretty`; a line of running text stays under about 70 characters.

```tsx
// Do: the page's title through PageHeader, sections through Section
<PageHeader title="Reminders" description="What is due, and what you shared." />
<Section title="Due today">…</Section>

// Don't: a second h1, a heading picked for its size, a bold paragraph as a title
<h1>Reminders</h1> <h1 className={styles.small}>Due today</h1>
<p><b>Due today</b></p>
```

## Space and layout

The 4 px scale: `--space-1` 4, `-2` 8, `-3` 12, `-4` 16, `-5` 20, `-6` 24, `-8` 32, `-10` 40, `-12` 48, `-16` 64,
`-20` 80, `-24` 96 px. Nothing in between.

- **Page**: one `<Page>` per page: `--page-max` 1240 px, `--gutter` (16 to 32 px) at the edges, 32 to 48 px between
  sections. `width="narrow"` (720 px) for settings and forms, `"reading"` (880 px) for one thing's details.
- **Surfaces**: 24 px inside (20 px on phones); 16 px between a section's title and its content. Never nest a
  `Surface` in a `Surface`: inside one, separate with hairlines (`--border-subtle`).
- **Settings**: one `SettingsGroup` per subject, rows of label and description with the control at the end, at least
  64 px tall. A switch stays beside its text on phones (`inline`).
- **The workspace frame**: a 248 px sidebar and a 64 px sticky top bar; below 900 px the sidebar becomes the menu sheet.
- **Phones (390 px)**: one column, full-width primary actions at the end of forms, tables fold into rows that say what
  each value is, nothing scrolls sideways except code.

## Shape: squircles

Every rounded surface is a squircle (`styles/squircle.css`, `lib/squircle/`): browsers with `corner-shape` draw it
natively, others get an SVG-path fallback painted from the same variables.

| Radius | Value | For |
| --- | --- | --- |
| `--radius-control` | 18 px | buttons, fields, selects, the share field |
| `--radius-panel` | 26 px | settings groups, landing panels, menus |
| `--radius-surface` | 34 px | page surfaces, cards, dialogs, empty-state frames |
| `--radius-pill` | 9999 px | chips, badges, the search pill |
| small parts | 6 to 12 px | kbd, icon tiles (11 px at 38 px), the mark (about 32 % of its size) |

```tsx
// Do: mark it, give it a radius, paint through the variables (so hover and the fallback follow)
<div data-sq="surface" className={styles.card}>…</div>
.card { --sq-r: var(--radius-surface); --sq-fill: var(--surface); --sq-stroke: var(--border);
        border: 1px solid var(--sq-stroke); background: var(--sq-fill); }
.card:hover { --sq-stroke: var(--border-strong); }

// Don't: border-radius on a squircled element, or colours set directly (the fallback cannot follow them)
.card { border-radius: 34px; background: white; border-color: #e2e5eb; }
```

Photos and logos use `data-sq="clip"`; an element that draws with its own `::before`/`::after` uses `data-sq-native`.
Profile photos are 30 % squircles (Arc's `Avatar`), never circles.

## Depth

- Resting things: `--shadow-resting` at most (the current nav item, a selected segment). Cards: a border, no shadow.
- Raised: `--shadow-raised` for something that lifts on hover (a landing product card) or a hero code block.
- Floating: `--shadow-floating` for menus, dialogs, the palette, toasts, sheets; with the `--overlay` scrim behind modal
  layers.

## Density and controls

| Control | Height | Notes |
| --- | --- | --- |
| Button `sm` / `md` / `lg` | 36 / 44 / 50 px | `md` in forms and headers, `lg` for the landing page and sign-in, `sm` in toolbars and rows |
| Field (input, select, search, share) | 44 px | label above (500, 0.875rem), hint and error below (0.75rem) |
| Icon button | 36 to 38 px, 12 px squircle | always with an `aria-label` |
| Nav item | 38 px, 11 px squircle | icon 18 px at 1.75 stroke, label 0.875rem 500 |
| Table row | about 52 px | primary column in `--foreground` 500, the rest `--text-secondary` |

- **One primary action per surface.** Everything else is secondary (bordered), ghost (text), or in a menu.
- **Destructive actions** never fire on one click: `HoldToConfirm` (tone `danger`) for deleting things, `ConfirmMorph`
  for asking in place. They never sit as the primary button.
- **Icons** are lucide at 16 px (inline, menus) or 18 px (nav, feature tiles), stroke 1.75; decorative icons are
  `aria-hidden`.

## Motion

Arc's motion language: things glide, morph and settle on springs; nothing bounces for show.

| Token | Value | For |
| --- | --- | --- |
| `--duration-instant` / `-fast` / `-standard` / `-considered` | 120 / 160 / 240 / 480 ms | presses / hovers and fades / most transitions / page-level entrances |
| `--ease-enter` | `cubic-bezier(.16, 1, .3, 1)` | things arriving |
| `--ease-standard` | `cubic-bezier(.22, 1, .36, 1)` | things changing |
| `--ease-exit` | `cubic-bezier(.7, 0, .84, 0)` | things leaving (shorter than entering) |
| `motionTokens.spring.snappy` / `smooth` / `morph` | 0.26 s (bounce .12) / 0.4 s (0) / 0.42 s (.16) | presses and toggles / panels and height / shared highlights and shape changes |

- Shared highlights glide between items (the sidebar's current item, tabs, segmented controls); text that changes
  rises in with a small blur; layers grow from where they were opened; pages slide in the direction of travel.
- The theme change is the eclipse: the next appearance crosses the page as a disc from the switch.
- **Reduced motion**: Motion follows the device (`reducedMotion: "user"` in the providers); CSS transitions are switched
  off under `@media (prefers-reduced-motion: reduce)` (or only declared under `no-preference`). Movement becomes an
  instant change or a short fade. Never rely on motion to say something.

```css
/* Do */
.item { transition: background-color var(--duration-fast) var(--ease-standard); }
@media (prefers-reduced-motion: reduce) { .item { transition: none; } }

/* Don't: a long, linear, unconditional animation */
.item { transition: all 600ms linear; }
```

## Focus and accessibility

- **No outline rings.** Keyboard focus shows as a fill (`--surface-muted`) or an edge (`--sq-stroke: var(--accent)`
  or `--border-strong`), or an underline on plain links. Every control has one, always different from its resting look
  (`e2e/a11y.spec.ts` checks the shell's).
- Every page has a skip link to `#main`, one `main`, labelled `nav`s, one `h1`.
- Every control has a name a person would say ("Hold to delete", "Remove c:ada", "Account menu, Ada Lovelace"); its
  visible words are part of that name.
- Errors are announced (`role="alert"`) and tied to their field (`aria-invalid`, `aria-describedby`); quiet updates
  use `role="status"`.
- Never by colour alone: a Silicon's marker says "Silicon", a status badge says its status, an error has words.
- Targets are at least 24 × 24 px (WCAG 2.5.8); most are 36 px or more.
- `pnpm test:e2e` runs axe-core's WCAG 2.2 A and AA rules on every page in both themes on desktop and phone.

## Accounts on screen

Since there are no groups of accounts any more, accounts appear one by one, always the same way (`AccountChip`): the
profile photo from Silicon Accounts (`pfp_url`; initials while it loads or when there is none), the display name when
the app knows it, the `c:` or `si:` id, and the word Carbon or Silicon. Sharing names exact accounts
(`ShareWithAccounts`): the id is checked as it is typed and the service says who it is.

```tsx
// Do
<AccountChip account={item.owner} note={mine ? "You" : undefined} />
<ShareWithAccounts label="Share with" ids={ids} onIdsChange={setIds} resolve={resolveAccount} selfId={account.id} />

// Don't: an uuid on screen, an id without its kind, a "Share with everyone" switch
<span>{item.owner.uuid}</span>
<Switch label="Visible to everyone who signed in" />
```

## Pages

- **Public pages** (landing, sign-in, not-found) are server-rendered HTML with plain links and tiny islands (the theme
  switch, copy buttons); they load no motion library, no query client.
- **The landing page** follows the family's order: a badge ("For Carbons and Silicons"), the headline, a lede, the
  primary action (sign in) and the docs, a code block "As a Silicon" with the install and sign-in commands; then what it
  does for Carbons and for Silicons; three steps; a closing call to action; the footer with the theme choice.
- **Workspace pages**: `PageHeader` (title, one line of context, at most one primary action), then sections. Lists have
  search and filters above, an empty state for "nothing yet" and for "nothing matches", and open to a detail page.
  Detail pages: a back link, the title in the entity size, status and time, tabs for the parts, the destructive action
  last. Settings: groups of rows that save as you change them, or one save bar for a form.
- **Loading**: skeletons in the final layout (`loading.tsx`, `SkeletonBlock`), never a page spinner. **Failure**: an
  `ErrorAlert` where it happened, with the service's words and a way to try again.

## Copy

- Carbons and Silicons; a Silicon's custodian is a Carbon. Never "AI agent", "human", "user account", "organization",
  "org", "team" for a group of accounts; never Honeycomb or IAM.
- Sentence case for every title, button and menu item. Buttons say what happens ("Save sharing", not "Submit").
- Short and exact: "Nothing was shared with Remind, and you are not signed in." Errors: what and why, then what to do,
  in the service's words ("The handle "ab" is 2 characters; it must be 3 to 30.").
- Times: "3 hours ago" in lists, "Oct 10, 2026, 14:05" in details (`lib/format.ts`).

## Checklist for a new screen

- [ ] Tokens only; nothing hard-coded that has no dark value.
- [ ] Squircles through `data-sq` and `--sq-*`; no `border-radius` on them.
- [ ] One primary action; destructive actions hold or ask in place.
- [ ] Type from the scale; one `h1`; sections as `h2`.
- [ ] An empty state, a loading state, an error state.
- [ ] Keyboard all the way; visible focus; names that match what is shown.
- [ ] Light and dark, 1440 and 390 wide, reduced motion: all looked at.
- [ ] Words for Carbons and Silicons.
