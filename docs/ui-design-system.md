# Varden UI design system

This document is the visual contract for the control-plane UI (`frontend/`). New screens should extend these tokens and components. Do not add a second theme, a page-specific zoom hack, or a layout that stretches empty cards to fill the viewport.

The identity stays dark navy, with teal and purple accents and restrained severity colours.

## Tokens

Defined in `frontend/src/styles/app.css` and refined in `frontend/src/styles/consistency.css`. `consistency.css` is imported after `app.css` and is the place to correct shared layout. Prefer editing tokens there over inventing new one-off values.

| Token | Value | Use |
| --- | --- | --- |
| `--bg` | `#07111f` | Page background |
| `--panel` / `--panel-strong` | translucent navy | Cards and sidebar |
| `--text` | `#eef4ff` | Primary text |
| `--muted` | `#b7c6e4` | Supporting text. Do not go greyer than this for readable copy |
| `--line` | `rgba(163, 184, 255, 0.18)` | Borders |
| `--accent` | `#7b61ff` | Selection, active navigation |
| `--accent-2` | `#4ce0b5` | Eyebrows, focus, live status |
| `--danger` / `--warn` / `--ok` | `#ff6b7a` / `#ffbf5a` / `#5de1a4` | Severity. Pair with a label or icon |
| `--shadow` | `0 16px 40px rgba(0, 0, 0, 0.32)` | Panels |
| `--space-1` … `--space-6` | 4, 8, 12, 16, 20, 24px | Spacing scale |
| `--radius-sm` … `--radius-xl` | 10, 14, 18, 22px | Controls through panels |
| `--control-h` | 36px | Minimum control height |
| `--font-page` | 22px | Page title |
| `--font-section` | 18px | Section title |
| `--font-kpi` | 28px | KPI value |
| `--font-body` | 14px | Body and page descriptions |
| `--font-support` | 13px | Supporting copy |
| `--font-meta` | 12px | Labels, eyebrows, table headers. Floor for readable text |
| `--focus-ring` | teal 3px ring | Keyboard focus |

Do not set `html { zoom }`. It changes hit targets, tooltip coordinates, and screenshot geometry.

## Typography

| Role | Element | Size |
| --- | --- | --- |
| Category | `.eyebrow` | 12px, uppercase, teal |
| Page title | `.topbar h1` | 22px |
| Section title | `.sectionHeader h3`, page `h2` | 18px |
| KPI value | `.metricCard__value` | 28px |
| Body | `.topbar .muted`, paragraphs | 14px |
| Supporting | `.muted`, `.metricCard__subtitle` | 13px |
| Metadata | badges, table headers, eyebrows | 12px |

Do not use type smaller than 12px for anything an operator must read. Graph region labels may sit at 11px inside a dense visualization.

## Spacing

- Page padding and the gap between sidebar and content: 16px.
- Gap between stacked page regions: 16px.
- Gap inside a KPI row: 12px.
- Space between a panel heading and its content: 12px.
- Control gap in toolbars: 8–12px.

Page headers size to their content. A title and one sentence should land around 98–120px tall, not hundreds of pixels.

## Layout

`.shell` is a two-column grid: 272px sidebar and a fluid main column from 1181px upward. Below that, the existing breakpoint stacks the sidebar above the content.

`.main`, `.stack`, and `.pageGrid` use `align-content: start`. Grid rows must not absorb leftover viewport height. That stretch was the cause of the empty Web Shield and Authority headers.

```css
.main, .pageGrid, .stack, .card, .layout { min-width: 0; max-width: 100%; }
```

`min-width: 0` lets grid and flex items shrink below their content's minimum so toolbars wrap instead of widening the page.

The sidebar is sticky on wide screens. Do not set `overflow: hidden` on it; the agent menu is positioned inside the sidebar and must remain visible.

## Page header

Every major route uses one header:

```html
<header class="topbar topbar--compact card" data-testid="page-header">
```

Contents, in order:

1. Category eyebrow (Operations, Policy, Runtime, Investigation, Intelligence)
2. Page title (`h1`)
3. One-sentence description
4. Posture, event count, and P95 latency pills

Do not add a second introductory card that repeats the title and the description. Tabs and page actions belong in the first content panel, directly under the header.

## KPI cards

Use `MetricCard` from `frontend/src/components/ui/Cards.tsx`.

- `title`, `value`, `subtitle` are required.
- `tone` is `danger`, `warn`, `monitor`, `ok`, or `accent`.
- `trend` is optional.
- `onClick` makes the card a button. Keep the metric meaning unchanged.

`.metricsRow` and `.metricsRow--six` use `repeat(auto-fit, minmax(min(100%, 168px), 1fr))`. Five overview metrics, including average latency, stay on one row at desktop widths. Do not force a fixed column count that leaves a single card on the next row.

## Panels

- Cards use 16px–18px padding and a 22px radius.
- Section headers are a row: title block on the left, actions on the right.
- Visualization panels that need a fixed height (the activity rail) may set one. Empty marketing-style heroes may not.
- Sankey diagrams scale to the panel width via the SVG view box. They do not sit inside a stretched empty card.

## Tables

- Dense tables scroll inside their panel (`overflow-x: auto`), not the page.
- Column headers are 12px, uppercase, muted.
- Long identifiers wrap or truncate. The full value stays available on the element (`title`, or the investigation panel).
- Selected rows use a purple inset edge, not colour alone.

## Filters and controls

- Toolbars wrap as horizontal groups. Do not leave a narrow column of full-width buttons beside a row of selects on a desktop width.
- Inputs, buttons, and segmented controls share a 36px minimum height.
- Segmented controls show the active choice with the accent fill and `aria`-selected tabs where the control is a tab list.

## Responsive breakpoints

| Width | Behaviour |
| --- | --- |
| ≥ 1181px | Sidebar and content side by side |
| ≤ 1180px | Sidebar stacks above content |
| ≤ 1024px | Investigation splits (authority, predictive, impact) become one column |
| ≤ 768px | Header stacks the status pills under the title. KPI rows reflow. No page-level horizontal scroll |

Checked widths: 1920, 1440, 1280, 1024, 768.

## Accessibility

- Text on navy uses `--text` or `--muted` (`#b7c6e4` or lighter).
- Interactive elements show a teal focus ring on `:focus-visible`.
- Status uses a word (Blocked, Allowed, FP proxy) as well as colour.
- Icon-only controls need an accessible name.
- `prefers-reduced-motion: reduce` disables the brand pulse and shortens transitions.
- Unsaved policy edits set `beforeunload` and confirm in-app navigation away from the rules workspace.

## Visualization containment

- Graph nodes, edges, and tooltips stay inside their panel. The predictive graph panel is `[data-testid="graph-panel"]`.
- Tooltips are `position: absolute` inside that panel, with a z-index below the sidebar stacking context, so they cannot draw over navigation.
- A page must not grow a horizontal scrollbar because a diagram, inspector value, or filter row is wider than the viewport. Wrap text with `overflow-wrap: anywhere` and `min-width: 0` on the inspector.

## What not to do

- Do not duplicate `app.css` by appending a second copy of `:root` and the base rules.
- Do not add a page-level `min-height: 100vh` card for a short introduction.
- Do not describe a false-positive proxy as a verified false-positive rate.
- Do not change policy decisions, authority analysis, predictive algorithms, or threat-contract semantics to make a layout simpler.
