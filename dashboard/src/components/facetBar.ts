// "Add filter" control: any field (IP, project, status, action, resource, payload keys)
// with value suggestions, as an include ("only") or exclude filter.
import { addFacet, cachedData, fieldLabel, getField, periodEvents, type FieldKey } from '../state.js';
import { esc } from '../format.js';

let _cb: () => void = () => {};
let _wired = false;
const PREFERRED: FieldKey[] = ['ip', 'data.projectName', 'data.status', 'action', 'resource', 'data.username', 'data.branch'];

/** Fields present in the data, preferred ones first, then payload keys by frequency. */
function availableFields(): FieldKey[] {
  return cachedData('facetFields', () => {
    const events = periodEvents();
    const keyCounts = new Map<string, number>();
    let ip = 0;
    let action = 0;
    let resource = 0;
    for (const e of events) {
      if (e.ip) ip++;
      if (e.action) action++;
      if (e.resource) resource++;
      for (const k of Object.keys(e.data)) keyCounts.set(k, (keyCounts.get(k) ?? 0) + 1);
    }
    const present = new Set<FieldKey>();
    if (ip) present.add('ip');
    if (action) present.add('action');
    if (resource) present.add('resource');
    for (const k of keyCounts.keys()) present.add(`data.${k}`);
    const dataByFreq = [...keyCounts.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => `data.${k}` as FieldKey);
    const ordered = [...PREFERRED.filter((f) => present.has(f)), ...dataByFreq.filter((f) => !PREFERRED.includes(f))];
    return ordered.slice(0, 40);
  });
}

/** Most common values of a field in the current period (for suggestions). */
function topValues(field: FieldKey, max = 200): { value: string; count: number }[] {
  return cachedData(`facetValues:${field}`, () => {
    const counts = new Map<string, number>();
    for (const e of periodEvents()) {
      const v = getField(e, field);
      if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, max)
      .map(([value, count]) => ({ value, count }));
  });
}

export function initFacetBar(cb: () => void): void {
  _cb = cb;
  if (_wired) return;
  _wired = true;
  const form = document.getElementById('facet-form') as HTMLFormElement | null;
  const field = document.getElementById('facet-field') as HTMLSelectElement | null;
  const value = document.getElementById('facet-value') as HTMLInputElement | null;
  if (!form || !field || !value) return;

  field.addEventListener('change', () => {
    fillSuggestions(field.value as FieldKey);
    value.value = '';
    value.focus();
  });
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const v = value.value.trim();
    if (!field.value || !v) return;
    const mode = (form.querySelector('input[name="facet-mode"]:checked') as HTMLInputElement | null)?.value;
    addFacet({ field: field.value as FieldKey, value: v, exclude: mode === 'exclude' });
    value.value = '';
    _cb();
  });
}

function fillSuggestions(f: FieldKey): void {
  const list = document.getElementById('facet-values');
  if (!list) return;
  list.innerHTML = topValues(f)
    .map((x) => `<option value="${esc(x.value)}">${x.count.toLocaleString()} events</option>`)
    .join('');
}

/** Refresh the field list (call after data loads). */
export function renderFacetBar(): void {
  const field = document.getElementById('facet-field') as HTMLSelectElement | null;
  if (!field) return;
  const fields = availableFields();
  const prev = field.value;
  field.innerHTML = fields.map((f) => `<option value="${esc(f)}">${esc(fieldLabel(f))}</option>`).join('');
  if (fields.includes(prev as FieldKey)) field.value = prev;
  document.getElementById('facet-form')!.hidden = fields.length === 0;
  if (field.value) fillSuggestions(field.value as FieldKey);
}
