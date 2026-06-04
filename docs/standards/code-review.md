# Code Review Standards

## Purpose

Reviews catch bugs and maintain consistency. They are not style debates — formatting and naming are handled by linters. Focus on correctness, architectural fit, and the review checklist below.

## Reviewer Responsibilities

- Review within one business day of assignment.
- Approve only when you would be comfortable shipping the change yourself.
- Block only on correctness bugs, security issues, or clear architectural violations. Prefer suggestions for style or nit-level concerns.
- Use GitHub's **suggestion** feature for small, unambiguous fixes so the author can apply them with one click.

## Author Responsibilities

- Open a PR only when CI is green.
- Keep PRs focused. A calculator feature (core + UI + block) in one PR is fine; unrelated cleanup should be a separate PR.
- Respond to every comment — either apply the change or explain why not.
- Do not force-push after review has started; add fixup commits instead.

## Review Checklist

Use `CLAUDE.md` as the primary reference. The checklist below distills the non-negotiable items:

### Calculation Correctness
- [ ] Core `calculate()` output matches expected results for representative inputs (check against tests or manual spot-check).
- [ ] Edge cases handled: zero values, very large amounts, boundary rates, max term.
- [ ] `validateInputs()` collects all errors (not fail-fast) and returns `{ valid, errors }`.

### Architecture Fit
- [ ] New code follows the `core → ui → plugin` layering; no DOM references in `core/`.
- [ ] Hook uses `useDebounce` (300 ms) before calling `calculate()`.
- [ ] Shared primitives used (`CurrencyInput`, `PercentageInput`, `SelectInput`, `SliderInput`, `InputGroup`, `InlineError`, `LoadingState`) — no duplicate implementations.
- [ ] New exports added to `package.json` exports map and `rollup.config.js`.

### UI and Styling
- [ ] Shared CSS classes used before any calculator-specific overrides (`calc-table-card`, `calc-chart-card`, `calc-grid`, `calc-col-*`, etc.).
- [ ] Wide tables wrapped in `.calc-table-card-scroll` (and `--tall` when vertical scroll is also needed).
- [ ] Columns containing tables or charts have `min-width: 0`.
- [ ] Horizontal scroll verified at ≤767px viewport — no permanently clipped columns.
- [ ] Summary stats use `<p>` elements for `.calc-summary-stat-label` and `.calc-summary-stat-value`.
- [ ] Inline narrative values use `.calc-summary-statement*` classes, not stat classes.

### WordPress Block
- [ ] Block icon is a Font Awesome SVG path (not a dashicon string, not a custom SVG).
- [ ] Inspector settings use `ToolsPanel` + `ToolsPanelItem` only — no new `PanelBody`.
- [ ] `render.php` exists; `save: () => null` in `index.js`.

### Pro Calculator Licensing
- [ ] Slug registered in `matchbox_calc_inject_editor_license_data()` in **both** places: `calculators` payload and block iteration loop.
- [ ] Uses `useLicenseWarning(slug)` and `LicenseWarning` component.
- [ ] All six license states handled: `valid`, `no-license`, `expired`, `invalid`, `suspended`, `unresolved`.

### Tests
- [ ] Core engine has Jest tests covering the primary calculation path and at least one edge case.
- [ ] UI hook has a `useCalculator` test.
- [ ] No existing passing tests broken.

### Security
- [ ] No user-supplied strings injected into `dangerouslySetInnerHTML`, `eval`, or `innerHTML`.
- [ ] No secrets, API keys, or `.env` values in source.

## Merge Criteria

All checklist items relevant to the change must pass. CI must be green. At least one approval required. The PR author merges after approval (not the reviewer).
