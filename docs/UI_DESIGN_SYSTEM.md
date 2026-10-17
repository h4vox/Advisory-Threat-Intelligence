# AIE UI design system

This guide covers how every AIE screen is built. The structure follows the professional security-platform
pattern (Hadrian-style): a quiet canvas, a grouped sidebar, a slim global top bar, a title row with its
actions, then panels, tables and detail pages. Colour is **balanced**: neutral surfaces, with hue carried by
icons, chips, bars and the one primary button. All of it uses the theme tokens in `src/styles.css`.

The live reference is the **UI kit** page at `/ui-kit` (open it with ⌘K → "UI kit"). Copy from there.

---

## 1. Foundations

**Themes**
- **Dark** is the default. **Light** is a first-class theme (see §1.1).
- Theme (dark / light) and UI style (Default / Liquid glass) are switched from the **top bar** (right side),
  from the Profile dialog, and from Settings. They persist in `localStorage` (`aie_theme`, `aie_ui_style`).

**Tokens.** Use only these. Never add hex colours in components.

| Token | Use |
|---|---|
| `bg-bg` | App canvas |
| `bg-bg-card` | Panels, tables, cards |
| `bg-bg-elevated` | Inputs, outline buttons, menus |
| `bg-bg-subtle` | Hover, selected row, chips, icon wells |
| `text-fg` | Primary text and numbers |
| `text-muted` | Secondary text, column headers, labels |
| `text-subtle` | Hints, placeholders, timestamps |
| `border-border` | All borders: 1px, low contrast |
| `bg-primary` / `text-primary-fg` | Brand violet: the one primary action (`ActionButton variant="primary"` → `.btn-primary`), active nav marker, focus ring, selection |
| `text-accent` | Inline links ("Open matrix →"); equals primary in both themes |
| `text-sage` / `text-warn` / `text-danger` / `text-info` | Status: ok / attention / critical / informational |
| `--color-cat-*` | Category hues (below): icons, chips, bars — never large fills |

**Category colours** (one hue per entity / document family; light-theme values are darker for contrast)

| Token | Kind | Use |
|---|---|---|
| `--color-cat-actor` | Threat actor, campaign, incident | `EntityIcon kind="actor"` |
| `--color-cat-malware` | Malware / tool / software | |
| `--color-cat-technique` | ATT&CK technique / tactic | heatmap scale, tactic bars |
| `--color-cat-cve` | Vulnerability / KEV | CVE items |
| `--color-cat-ioc` | Indicator, detection, hunting | |
| `--color-cat-source` | Source / feed | |
| `--color-cat-advisory` | Advisory, report | |
| `--color-cat-emulation` | Emulation plan, atomic test, CALDERA | |
| `--color-cat-flow` | Attack flow | |

Use them through `EntityIcon` (tinted square well), `EntityChip` (tinted chip with dot) and `DocTypeBadge`
(`src/components/ui/entity.tsx`). For anything else use the same recipe:
`color: var(--color-cat-x); background: color-mix(in oklab, var(--color-cat-x) 14%, transparent)`.

**Balance rule.** Hue lives in icon wells, chips, bars and small numbers. Surfaces stay neutral. A tinted
background above ~10% mix is only for chips/badges; panels may take at most a 2–8% tint (e.g. heatmap cells).

### 1.1 Light theme

Light must look as finished as dark. Values: canvas `#f6f7f9`, cards and chrome (sidebar, top bar) pure white,
1px borders `#e3e6eb`, text `#111318` / muted `#5b616e` / subtle `#8a909c`, subtle fill `#f1f3f6`,
primary `#5b4bd6`. Cards (`rounded-xl border bg-bg-card`) automatically get a very soft shadow
(`--shadow-card: 0 1px 2px rgba(16,24,40,.04)`).
- Never hard-code `rgba(255,255,255,…)` or `bg-black/…` for surfaces: they vanish or turn muddy in light.
  Use tokens, or `color-mix(… , transparent)` with a token.
- Avoid grey-on-grey: `text-subtle` only on `bg-card`/`bg-bg`, never on `bg-bg-subtle` for important text.
- Check `/ui-kit` in light after any visual change.

### 1.2 Liquid glass

Liquid glass is a style layer, not a theme: it works in dark and light. It paints a faint tinted canvas,
frosts sidebar/top bar/cards (`.rounded-xl.border.bg-bg-card`, `.card-liquid-glass`, `.dropdown-liquid-glass`)
and keeps the primary button violet. Build with tokens and these classes; no extra work per page.

**Radius**
- `rounded-xl` (12px) for panels and tables.
- `rounded-lg` (8px) for buttons and inputs.
- `rounded-md` (6px) for chips.

**Typography** (IBM Plex Sans; IBM Plex Mono only for IDs, hashes, IOCs and code)

| Element | Style |
|---|---|
| Page title | `text-2xl md:text-[28px] font-semibold` |
| Panel title | `text-base font-medium` |
| Body / table text | `text-sm` |
| Secondary text | `text-sm text-muted` |
| Hints | `text-xs text-subtle` |
| Big numbers | `text-[32px] font-semibold tabular-nums` |

**Spacing**
- Page padding comes from `AppShell`.
- Sections use `space-y-6`; grids use `gap-4` for stat rows and `gap-6` for panels.
- Panel padding is `p-5`.

### 1.3 App chrome: sidebar + global top bar

- **Sidebar** (`w-60`): product mark only in its 56px header (no profile there), grouped nav, active item
  marked with a primary bar and primary icon, counts only when the store reports them.
- **Top bar** (56px, aligned with the sidebar header): left = breadcrumb (group / page); centre = search
  field that opens the ⌘K palette; right = UI style segmented switch, theme toggle, Activity (bell; recent
  crawl & ingest events), AI Agent, and the profile menu (avatar → Profile dialog, Settings, Keyboard
  shortcuts, Sign out).
- **Mobile**: menu button (opens the drawer), page title, search, AI agent, profile. Theme and style move
  into the profile menu.
- Shortcuts: ⌘K / Ctrl+K search, `?` shortcuts sheet, Esc closes.
- Pages keep their own `PageHeader` (title + actions) below the top bar; don't add page controls to the top bar.

## 2. Rules: do / don't

**Do**
- Use sentence case for every title, label, tab and button ("Launch crawler", not "LAUNCH CRAWLER").
- Give each page header at most one primary action; everything else is outline.
- Use colour for meaning: status hues for state, category hues for the kind of thing, primary for the action.
- Give KPI tiles and section titles a coloured icon (`StatCard kind`, `SectionCard icon iconKind`).
- Show one status chip per row at most. Put everything else in table columns.
- Use icons from `lucide-react`, stroke 1.75, `size-4` in controls and `size-[18px]` in nav.
- Show honest empty states (`EmptyState`) instead of placeholder numbers.
- Use `DataTable` for lists of things: reports, sources, jobs, IOCs. Row click opens the detail page.

**Don't**
- Don't use decorative `font-mono uppercase tracking-widest` eyebrows on every block. Use at most one per page
  header, or none.
- Don't stack badges, chips and emoji in one row, and don't use emoji as icons.
- Don't nest bordered boxes inside bordered boxes. Inside a panel, separate with spacing or `divide-y`.
- Don't use pill-shaped (`rounded-full`) cards or buttons. Pills are only for count dots.
- Don't use more than 3 visible buttons per table row. Move the rest into the detail page or a row menu.

## 3. Components

| Need | Component | File |
|---|---|---|
| App frame, sidebar, top bar, ⌘K search, profile, activity | `AppShell` | `src/components/app-shell.tsx` |
| Page title row + actions + tabs | `PageHeader` | `src/components/layout/page.tsx` |
| Header / toolbar buttons | `ActionButton` (`primary`, `outline`, `ghost`) | same |
| KPI tile (`kind` = icon hue, inferred from label) | `StatCard` | same |
| Titled panel (`icon` + `iconKind` for a small coloured glyph) | `SectionCard` | same |
| View switch with counts | `SegmentedTabs` | same |
| Search/filter row above lists | `Toolbar` | same |
| Lists | `DataTable` (sorting, selection, row click) | `src/components/ui/data-table.tsx` |
| Status (`neutral`/`success`/`warning`/`danger`/`info`/`primary`, tinted) | `StatusChip`, `StatusDot` | `src/components/ui/primitives.tsx` |
| Detail "Properties" column | `PropertyList` | same |
| No data | `EmptyState` | same |
| Score bars (`tone`, or `color` for a category token) | `Meter` | same |
| Entity / document colour language | `EntityIcon`, `EntityChip`, `DocTypeBadge`, `DOC_TYPE_META` | `src/components/ui/entity.tsx` |
| Evidence and quotes | `EvidencePanel` | `src/components/evidence/` |
| Intelligence search: query bar with autocomplete, "Interpreted as" chips, explainable result card | `SearchBar`, `InterpretedChips`, `ResultCard`, `Highlight` | `src/components/search/` |
| Collection health, yield bar, job funnel | `CollectionHealthView`, `AcceptanceBar`, `HealthChip`, `CrawlFunnelPanel` | `src/components/collector/collector-ui.tsx` |
| Report collection record (ATT&CK refs, mirrors, versions, PDFs) | `CollectionRecord` | `src/components/library/collection-record.tsx` |
| Purple path builder, phase view, step drawer, exports | `PurpleBuilder`, `PurplePathView`, `PurpleKpis`, `StepDrawer`, `PurpleExportButtons` | `src/components/purple/` |
| Threat actor card, technique mini bar, profile tabs | `ActorCard`, `TechniqueMiniBar`, `KpiStrip`, `ProfileOverview`, `TechniquesTab` … | `src/components/actors/` |

Search, collection, actors and purple paths are described in `docs/RETRIEVAL_ENGINE.md`.

## 4. Page templates

Start every new page from a template in `src/components/templates/page-templates.tsx`:

```tsx
// Dashboard: header + KPI row + panels
<AppShell>
  <DashboardTemplate
    header={{ title: "Overview", description: "…", actions: <ActionButton variant="primary">…</ActionButton> }}
    stats={<><StatCard … /><StatCard … /><StatCard … /><StatCard … /></>}
  >
    <TwoUp ratio="7:5"><SectionCard title="…">…</SectionCard><SectionCard title="…">…</SectionCard></TwoUp>
    <SectionCard title="…">…</SectionCard>
  </DashboardTemplate>
</AppShell>

// List: header + tabs + toolbar + table + pagination
<AppShell>
  <ListPageTemplate
    header={{ title: "Library", actions: …, tabs: <SegmentedTabs … /> }}
    toolbar={<Toolbar left={<SearchInput/>} right={<ActionButton>Export</ActionButton>} />}
    footer={<Pagination … />}
  >
    <DataTable data={rows} columns={columns} getRowId={(r) => r.id} onRowClick={(r) => navigate(…)} />
  </ListPageTemplate>
</AppShell>

// Detail: back + title + actions, tabs, main + properties
<AppShell>
  <DetailPageTemplate
    header={{ backTo: "/library", icon: FileText, title: report.title, actions: …, tabs: <SegmentedTabs … /> }}
    properties={<PropertyList items={[{ label: "Publisher", value: report.publisher }, …]} />}
  >
    <section><h2 className="text-xl font-semibold">Summary</h2>…</section>
  </DetailPageTemplate>
</AppShell>
```

## 5. Review checklist for a new screen
- [ ] Built from a template, so header, actions and tabs sit in the standard places.
- [ ] Only tokens; it reads well in dark, light and liquid glass.
- [ ] Sentence case; no decorative uppercase labels or emoji.
- [ ] One primary action (violet `btn-primary`); no more than 3 buttons per row.
- [ ] Balanced colour: KPI and section icons use category hues; status chips use status tones; no large coloured fills.
- [ ] Lists use `DataTable`; rows open a detail page.
- [ ] Empty, loading and error states are present and honest.
- [ ] At 390px wide: no horizontal page scroll, and actions wrap.
- [ ] Keyboard: every action is reachable with Tab, dialogs close on Esc, and icon buttons have `aria-label`.
