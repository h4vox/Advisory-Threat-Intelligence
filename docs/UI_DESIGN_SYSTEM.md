# AIE UI design system

This guide covers how every AIE screen is built. The structure follows the professional security-platform
pattern (Hadrian-style): a quiet dark canvas, a grouped sidebar, a title row with its actions, then
panels, tables and detail pages. All of it uses the theme tokens in `src/styles.css`.

The live reference is the **UI kit** page at `/ui-kit` (open it with ⌘K → "UI kit"). Copy from there.

---

## 1. Foundations

**Themes**
- **Dark** is the default.
- **Light** and **liquid glass** remain available from the workspace menu (top-left) and from Settings.

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
| `bg-accent` / `text-accent-fg` | The one primary action per header |
| `text-sage` / `text-warn` / `text-danger` | Status only: ok / attention / critical |

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

## 2. Rules: do / don't

**Do**
- Use sentence case for every title, label, tab and button ("Launch crawler", not "LAUNCH CRAWLER").
- Give each page header at most one primary action; everything else is outline.
- Use colour only for meaning: severity and status.
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
| App frame, sidebar, ⌘K search | `AppShell` | `src/components/app-shell.tsx` |
| Page title row + actions + tabs | `PageHeader` | `src/components/layout/page.tsx` |
| Header / toolbar buttons | `ActionButton` (`primary`, `outline`, `ghost`) | same |
| KPI tile | `StatCard` | same |
| Titled panel | `SectionCard` | same |
| View switch with counts | `SegmentedTabs` | same |
| Search/filter row above lists | `Toolbar` | same |
| Lists | `DataTable` (sorting, selection, row click) | `src/components/ui/data-table.tsx` |
| Status | `StatusChip`, `StatusDot` | `src/components/ui/primitives.tsx` |
| Detail "Properties" column | `PropertyList` | same |
| No data | `EmptyState` | same |
| Score bars | `Meter` | same |
| Evidence and quotes | `EvidencePanel` | `src/components/evidence/` |

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
- [ ] One primary action; no more than 3 buttons per row.
- [ ] Lists use `DataTable`; rows open a detail page.
- [ ] Empty, loading and error states are present and honest.
- [ ] At 390px wide: no horizontal page scroll, and actions wrap.
- [ ] Keyboard: every action is reachable with Tab, dialogs close on Esc, and icon buttons have `aria-label`.
