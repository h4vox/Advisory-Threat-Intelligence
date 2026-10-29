# Intel Graph — how to use it

The Intel Graph (Intelligence → Intel Graph) maps everything the library knows — threat actors,
campaigns, malware, tools, ATT&CK techniques, vulnerabilities, targeted sectors / regions /
platforms and indicators — and how they connect, based on what the reports say. Use it to answer
questions like *"what does this actor use and who does it target?"*, *"who else uses this
technique?"* or *"how is this malware connected to that CVE?"*.

## The screen

| Area | What it is for |
| --- | --- |
| **Left** | Search, lens, detail, entity types, ATT&CK tactics, evidence filters |
| **Centre** | The graph (3D or 2D) and, under it, the **trail** of entities you focused |
| **Right** | Details of what you selected, or library-wide insights when nothing is selected |
| **Top** | Overview / Focus, 3D / 2D, Direct links / 2 hops, counts, Guide |

## The two ways of looking

- **Overview** — the most-reported entities of each type and the links among them. Start here to
  get a feel for the library. *Detail* (Key / More / Wide) sets how many entities it shows.
- **Focus** — one entity in the centre with everything linked to it around it, grouped by type.
  Use it to study one actor, tool, technique, vulnerability or target in depth.
  - **Direct links** — only what is linked to the centre entity.
  - **2 hops** — also the strongest links *of* those entities (who else uses the same tools…).
    Busier; use it to look for indirect connections.

## Reading the graph

- **Dot colour** = entity type (legend: *Entity types* on the left). **Dot size** = how many
  reports mention it.
- **Thick line** = a report states the link in one sentence (*stated*). **Thin line** = both
  appear in the same report (*co-reported*). **Brighter line** = higher confidence; confidence
  grows with every report that supports the link.
- Hover for a summary, **click** to see details on the right, **double-click** to focus.
- 3D: drag to rotate, scroll to zoom, right-drag to pan. 2D: drag to pan, scroll to zoom.
  The buttons at the bottom right zoom, reset, and pause the 3D turning.

## Investigating: the trail

Every entity you focus is added to the **trail** under the graph, in order — for example
`APT29 → Government → Cobalt Strike → T1059`.

- **Click any step** to go back to it. Later steps stay in the trail (shown fainter), so you can
  go forward again with ▶ or by clicking them.
- **◀ / ▶** step back and forward through the trail.
- Focusing a **new** entity from an earlier step starts a new branch: the steps after the current
  one are replaced (like a browser's history).
- **Exit focus** returns to the overview. It asks first, because it clears the trail, and offers
  to **save the trail** before leaving.

## Saving investigations

- **Save** (on the trail bar) stores the trail together with the current filters, lens, detail,
  2D/3D and depth, under a name and an optional note.
- **Saved** lists your saved investigations: **Open** restores the whole view exactly (you land on
  the step you were on), **Delete** removes it.
- Saved investigations are stored per user on the server (MongoDB). Without MongoDB they are kept
  in this browser only, and the list says so.

## New intelligence

The graph follows the library: when the crawler or an analyst ingests reports, or a report is
re-analysed, the server rebuilds the graph in the background within seconds. An open graph page
then shows **New intelligence available** with what changed; **Update the graph** loads it
(your trail and selection stay). It never changes the view under you on its own.

## Finding things

- **Search** (top left) finds any entity by name, alias, ATT&CK ID (T1059, G0016, S0154) or CVE —
  across the whole library, including indicators and vulnerabilities not drawn on the map.
- **Lens** picks entity types by what you want to look into:
  - *Adversaries* — actors, campaigns, malware, tools, techniques
  - *Targeting* — who targets which sectors, regions and platforms
  - *Exploitation* — vulnerabilities, who exploits them and what they hit
  - *Infrastructure* — indicators and the malware / actors they belong to
  - *Everything* — all types except indicators
- **ATT&CK tactics** — show only techniques of chosen tactics (e.g. Initial Access, Lateral
  Movement).
- **Evidence**:
  - *Link confidence at least* — hide weak links.
  - *Corroborated only* — only entities and links backed by more than one report.
  - *Stated links only* — only links a report states in one sentence.
  - *Activity* — only what was reported in the chosen period.

## The details panel (right)

For a selected entity:

- **Focus on this**, **Ask the agent**, **Full context**, and a link to the actor profile, ATT&CK
  page or NVD entry.
- **Assessment** — written by the AI when available; otherwise (or if the AI fails) by the engine
  itself, clearly labelled.
- **Findings** — what the engine works out without AI: activity trend, targets, vulnerabilities,
  tooling, techniques, behaviour not in ATT&CK, how well the links are corroborated.
- **Connections** — links grouped by type, with report counts and confidence; click one to see the
  evidence for it.
- **Related through shared links** — not linked directly, but connected through shared entities
  (shown after "via").
- **Possible hidden links** — entities that share unusually much behaviour, tooling, targets or
  infrastructure but that no report links. Leads to check, not facts.

For a selected **link**: who it connects, how it is supported (stated / co-reported, reports,
confidence), the sentence that states it, and the supporting reports.

## Everywhere else in the app

- Actor, malware, technique, CVE and indicator **chips** on any page open the entity's **context
  panel** (the same engine): findings, connections, related entities, ATT&CK, reports, and
  *How is it connected to…* to trace paths between two entities.
- **Ask the agent** (or drag a chip / the *Ask the agent* handle onto the **AI Agent** button)
  starts an investigation in the chat. The agent queries the engine first; if the AI is slow or
  unavailable, you get the engine's own answer straight away and can ask again for the AI's
  write-up.

## Tips

- Start in **Overview → Key** with a **lens**, pick an entity, then **Focus**.
- Follow a thread with double-clicks; the trail keeps your path. **Save** it when it is worth
  keeping.
- Too busy? Use **Direct links**, *Corroborated only*, a higher confidence, or fewer entity types.
- Counts with `*` (e.g. indicators) mean the map holds the most-reported ones; search and Full
  context cover all of them.
