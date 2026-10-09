# VARDEN-UI-CONSISTENCY-001

Visual consistency pass on the control-plane UI. No commit, merge, push, tag, or release.

- Branch: `feature/threat-intelligence`
- Starting SHA: `a2d113d0511b8b756c70ba3bb5b6a51e28adba85`
- Working tree at start: clean

## Initial visual audit

Every major route was opened in headless Chromium against a dev control plane, at 1920, 1440, 1280, 1024, and 768. Screenshots: `data/reports/ui-consistency/before/`.

Page-header heights at 1920×900 before the fix:

| Route | Header height |
| --- | --- |
| Overview | 157px |
| Rule Impact | 616px |
| Rules Workspace | 157px |
| Coverage Gaps | 599px |
| Web Shield | 531px |
| Authority & Provenance | 489px |
| Predictive Authority | 224px |
| Threat Intelligence | 399px |

Short pages grew a mostly empty header. Web Shield and Authority also repeated the page introduction in a second panel, so the inventory and incident list sat far down the viewport. Overview placed average latency alone on a second KPI row because `.metricsRow` was fixed at four columns.

At 1024 and below, the shell stacks and the stretch was less severe. A `zoom: 0.83` rule below 1900px made laptop layouts a different size from the 1920 layout and shrank already-small supporting text.

## Root causes

1. **Grid stretch.** `.main` is a grid inside a shell that is at least as tall as the sidebar. The default `align-content` distributes leftover height across auto rows, so the header card on a short page expanded to hundreds of pixels.
2. **Duplicated stylesheet.** `frontend/src/styles/app.css` contained two copies of the base rules. The later copy won the cascade and had dropped several monitor-state rules. Impact styles lived only in the first copy.
3. **Fixed KPI columns.** Five overview metrics could not share one row.
4. **Laptop zoom.** `html { zoom: 0.83 }` fought readability and made geometry depend on viewport width.
5. **Repeated introductions.** Authority and Web Shield rendered a second title and paragraph under the global header.
6. **Narrow flex items.** Coverage filters became a vertical stack, and predictive inspector values could widen the page, because flex and grid items default to `min-width: auto`.

## Shared components changed

- `frontend/src/styles/app.css` — duplicate base removed; monitor, rule-highlight, and Sankey rules that existed only in the first copy kept; zoom removed.
- `frontend/src/styles/consistency.css` — tokens, header, KPI, sidebar, focus, reduced motion, toolbar, table, and containment overrides. Imported after `app.css`.
- `frontend/src/components/ui/Cards.tsx` — `MetricCard` supports an optional trend and renders a real button when it is interactive.
- `frontend/src/main.tsx` — one compact header on every page, category eyebrow, posture / events / P95, rules unsaved navigation warning.

Design contract: `docs/ui-design-system.md`.

## Page-specific improvements

- **Overview.** Five KPIs share one row from 1181px up. The Sankey scales to the signal panel instead of sitting in a stretched empty card. Filtering and drilldown are unchanged.
- **Rule Impact.** Summary counts are Configured, Enabled, Matched, and Detections. The false-positive column and sort are labelled as a proxy, not a verified rate. Table columns fit the heatmap pane; the table can still scroll inside the card on a narrow pane.
- **Rules Workspace.** Header describes the builder. Saved versus unsaved is visible. Leaving the page with unsaved JSON confirms, and the browser warns on refresh. Collapsed template cards keep the primary import or add action; preview and remove appear when the pack is expanded.
- **Coverage Gaps.** KPI row and filter toolbar reflow without a vertical stack of buttons. An empty result still explains that zero observed events are not proof of coverage. No coverage logic was changed.
- **Web Shield.** The duplicate essay under the header is one sentence. Tool inventory sits under the KPI row. Selected tools keep the active row treatment.
- **Authority & Provenance.** The second title and repeated paragraph are gone. Tabs stay in a compact bar. Incident and story cards show source, agent, tool, and required authority when the incident payload includes them.
- **Predictive Authority.** Header, metric type, edge contrast, and inspector wrapping match the rest of the console. Graph layout, prediction, and enforcement are unchanged. Nodes and tooltips stay in the graph panel.
- **Threat Intelligence.** Mapped, protected, unmapped, review, and exposed pills are distinct. The intelligence-to-contract workflow is unchanged.

## Before and after screenshots

- Before: `data/reports/ui-consistency/before/` (`{route}-{width}.png`) and `before-audit.json`.
- After, 1440px (from the layout test) and the five-width sweep: `data/reports/ui-consistency/after/` and `after-audit.json`.

After the fix, header height at 1920 is 98px on most routes and 118px on Rule Impact. None of the five widths produced a page-level horizontal scrollbar. Headers stay under 180px at 1024 and under 220px at 768, where the status pills wrap under the title.

## Tests

| Check | Result |
| --- | --- |
| Frontend Vitest | 7 files, 46 tests passed |
| TypeScript `tsc --noEmit` | passed |
| `npm run build` | passed (`varden/web/app/assets/app.css`, `app.js`) |
| Playwright `tests/browser/test_ui_smoke.py` and `tests/browser/test_ui_stability.py` | 12 passed |
| `tests/test_graceful_shutdown.py` | passed in the same run (18 passed together with the browser files) |

New geometry checks in `test_page_headers_stay_content_sized`: header height, no document overflow at 1440 and 768, and the five overview KPIs on one row. The predictive test still asserts nodes and tooltips stay inside the graph panel and do not cover the sidebar, and that the page itself does not scroll sideways after Load demo.

Backend policy, authority, predictive, and threat-intelligence modules were not modified.

## Remaining limitations

- The sidebar is taller than a 900px viewport, so the API-key field sits below the first screen. It scrolls with the page. An internal sidebar scrollbar was avoided because it clips the agent menu.
- Rule Impact still scrolls horizontally inside the table if the heatmap pane is narrower than about 640px.
- Predictive node copy is still dense. Type size was raised slightly; the layout algorithm was not changed.
- Empty Sankey and timeline panels are only as tall as their content. They no longer inherit a large empty card from grid stretch.
- Two local audit servers started during the pass may still be listening (PIDs 2611 and 6667). They are not the `examples/dev.env` server.
