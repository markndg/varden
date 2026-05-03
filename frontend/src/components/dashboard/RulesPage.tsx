import React, { useEffect, useMemo, useRef, useState } from 'react';

type RulesPageProps = {
  policy: any;
  policyText: string;
  setPolicyText: (text: string) => void;
  templates: any[];
  onApplyTemplate: (template: any) => void;
  onSave: () => void;
  loading: boolean;
  ruleFocus: string;
  ruleFocusBucket: string;
  ruleFocusToken: string;
  ruleReturnTo: string;
  ruleDraft: string;
  onBackToDecision: (path: string) => void;
  helpers: any;
};

export function RulesPage({ policy, policyText, setPolicyText, templates, onSave, loading, ruleFocus, ruleFocusBucket, ruleFocusToken, ruleReturnTo, ruleDraft, onBackToDecision, helpers }: RulesPageProps) {
  const { RULE_BUCKETS, usePersistentState, safeParsePolicy, classNames, customRuleEntries, dedupePolicyDoc, ensurePolicyDoc, pickFirstNonEmptyBucket, mergePolicyWithoutDuplicates, semanticRuleFingerprint, summarizeRule, summarizeRuleConditions, getRuleOperator, getRuleValue, coerceRuleInput, setRuleOperatorValue, setRuleSimpleValue, ADVANCED_FIELDS, CLASSIFIER_KEYS, OPERATOR_OPTIONS, bucketTone } = helpers;
  const [selectedBucket, setSelectedBucket] = useState<string>('block');
  const [selectedRuleIndex, setSelectedRuleIndex] = useState(0);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [templateMode, setTemplateMode] = useState<'replace' | 'merge'>('merge');
  const [uploadedTemplates, setUploadedTemplates] = usePersistentState('varden.uploaded-policy-templates', []);
  const [expandedTemplateKeys, setExpandedTemplateKeys] = useState<Record<string, boolean>>({});
  const [templateNotice, setTemplateNotice] = useState('');
  const [templateError, setTemplateError] = useState('');
  const [highlightedRuleKey, setHighlightedRuleKey] = useState('');
  const [highlightedFields, setHighlightedFields] = useState<string[]>([]);
  const uploadInputRef = useRef<HTMLInputElement | null>(null);
  const ruleEditorPaneRef = useRef<HTMLDivElement | null>(null);
  const ruleItemRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const appliedDraftRef = useRef<string>('');

  const workingPolicy = useMemo(() => safeParsePolicy(policyText, policy), [policyText, policy, safeParsePolicy]);
  const activeRules = workingPolicy[selectedBucket] || [];
  const activeRule = activeRules[selectedRuleIndex] || null;
  const ruleKey = (bucket: string, idx: number) => `${bucket}:${idx}`;
  const scrollSelectedRuleIntoView = (bucket = selectedBucket, index = selectedRuleIndex) => { const target = ruleItemRefs.current[ruleKey(bucket, index)]; if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' }); };
  const resetRuleEditorScroll = () => { if (ruleEditorPaneRef.current) ruleEditorPaneRef.current.scrollTop = 0; };
  const activeRuleDefinedFields = (rule: any) => { if (!rule) return []; const fields: string[] = []; if (rule.type) fields.push('type'); if (rule.tool) fields.push('tool'); if (rule.priority !== undefined) fields.push('priority'); if (rule.title || rule.name) fields.push('title'); if (rule.description || rule.reason) fields.push('description'); if (rule.enabled !== undefined) fields.push('enabled'); for (const key of Object.keys(rule || {})) if (String(key).startsWith('classifier:') || String(key).startsWith('field:')) fields.push(String(key)); for (const [key] of customRuleEntries(rule)) fields.push(String(key)); return Array.from(new Set(fields)); };
  const fieldClass = (fieldKey: string, extra?: string) => classNames(extra, highlightedFields.includes(fieldKey) && 'ruleField--matched');

  useEffect(() => { if (selectedRuleIndex > Math.max(0, activeRules.length - 1)) setSelectedRuleIndex(Math.max(0, activeRules.length - 1)); }, [selectedRuleIndex, activeRules.length, selectedBucket]);
  useEffect(() => { requestAnimationFrame(() => { scrollSelectedRuleIntoView(); resetRuleEditorScroll(); setHighlightedRuleKey(ruleKey(selectedBucket, selectedRuleIndex)); window.setTimeout(() => setHighlightedRuleKey(''), 1800); }); }, [selectedBucket, selectedRuleIndex]);
  useEffect(() => { setHighlightedFields(activeRuleDefinedFields(activeRule)); }, [activeRule]);
  useEffect(() => {
    const wantedToken = String(ruleFocusToken || '').trim();
    const wanted = String(ruleFocus || '').trim().toLowerCase();
    if (!wantedToken && !wanted) return;
    const orderedBuckets = [...(ruleFocusBucket && RULE_BUCKETS.includes(ruleFocusBucket as any) ? [ruleFocusBucket] : []), ...RULE_BUCKETS.filter((bucket: string) => bucket !== ruleFocusBucket)];
    const findRuleIndex = (bucket: string) => (workingPolicy[bucket] || []).findIndex((rule: any) => {
      if (wantedToken && semanticRuleFingerprint(rule) === wantedToken) return true;
      const summary = summarizeRule(rule).toLowerCase();
      const fields = [rule?.title, rule?.name, rule?.description, rule?.reason, summary, ...summarizeRuleConditions(rule, 4)].filter(Boolean).map((value: any) => String(value).toLowerCase());
      return wanted ? fields.some((value: string) => value === wanted || value.includes(wanted) || wanted.includes(value)) : false;
    });
    for (const bucket of orderedBuckets) {
      const idx = findRuleIndex(bucket);
      if (idx >= 0) { setSelectedBucket(bucket); setSelectedRuleIndex(idx); requestAnimationFrame(() => { scrollSelectedRuleIntoView(bucket, idx); resetRuleEditorScroll(); }); return; }
    }
  }, [ruleFocus, ruleFocusBucket, ruleFocusToken, policyText, RULE_BUCKETS, workingPolicy, semanticRuleFingerprint, summarizeRule, summarizeRuleConditions]);

  useEffect(() => {
    const raw = String(ruleDraft || '').trim();
    if (!raw || appliedDraftRef.current === raw) return;
    try {
      const parsed = ensurePolicyDoc(JSON.parse(raw));
      const nextDoc = mergePolicyWithoutDuplicates(workingPolicy, parsed);
      const bucket = pickFirstNonEmptyBucket(parsed);
      setPolicyText(JSON.stringify(dedupePolicyDoc(nextDoc), null, 2));
      requestAnimationFrame(() => selectRule(bucket, 0));
      appliedDraftRef.current = raw;
    } catch {
      appliedDraftRef.current = raw;
    }
  }, [ruleDraft, workingPolicy, ensurePolicyDoc, mergePolicyWithoutDuplicates, pickFirstNonEmptyBucket, dedupePolicyDoc, setPolicyText]);

  const updateDoc = (nextDoc: any) => setPolicyText(JSON.stringify(dedupePolicyDoc(ensurePolicyDoc(nextDoc)), null, 2));
  const selectRule = (bucket: string, index: number) => { setSelectedBucket(bucket); setSelectedRuleIndex(index); requestAnimationFrame(() => { scrollSelectedRuleIntoView(bucket, index); resetRuleEditorScroll(); }); };
  const mutateRule = (mutator: (rule: any) => any) => { const nextDoc = ensurePolicyDoc(workingPolicy); const bucketRules = [...nextDoc[selectedBucket]]; const current = bucketRules[selectedRuleIndex] || {}; bucketRules[selectedRuleIndex] = mutator({ ...current }); nextDoc[selectedBucket] = bucketRules; updateDoc(nextDoc); };
  const addRule = (bucket = selectedBucket) => { const nextDoc = ensurePolicyDoc(workingPolicy); const bucketRules = [...nextDoc[bucket]]; bucketRules.push({ title: 'New rule', enabled: true, type: bucket === 'allow' ? '' : 'http_request' }); nextDoc[bucket] = bucketRules; updateDoc(nextDoc); selectRule(bucket, bucketRules.length - 1); };
  const duplicateRule = () => { if (!activeRule) return; const nextDoc = ensurePolicyDoc(workingPolicy); const bucketRules = [...nextDoc[selectedBucket]]; bucketRules.splice(selectedRuleIndex + 1, 0, { ...activeRule, title: `${summarizeRule(activeRule)} copy` }); nextDoc[selectedBucket] = bucketRules; updateDoc(nextDoc); selectRule(selectedBucket, selectedRuleIndex + 1); };
  const deleteRule = () => { if (!activeRule) return; const nextDoc = ensurePolicyDoc(workingPolicy); const bucketRules = [...nextDoc[selectedBucket]]; bucketRules.splice(selectedRuleIndex, 1); nextDoc[selectedBucket] = bucketRules; updateDoc(nextDoc); selectRule(selectedBucket, Math.max(0, selectedRuleIndex - 1)); };
  const moveRule = (direction: -1 | 1) => { const target = selectedRuleIndex + direction; if (target < 0 || target >= activeRules.length) return; const nextDoc = ensurePolicyDoc(workingPolicy); const bucketRules = [...nextDoc[selectedBucket]]; const [rule] = bucketRules.splice(selectedRuleIndex, 1); bucketRules.splice(target, 0, rule); nextDoc[selectedBucket] = bucketRules; updateDoc(nextDoc); selectRule(selectedBucket, target); };
  const updateCustomEntry = (index: number, patch: Partial<{ key: string; operator: string; value: any; mode: string }>) => mutateRule((rule) => { const entries = customRuleEntries(rule).map(([key, expected]) => ({ key, operator: getRuleOperator({ [key]: expected }, key, 'eq'), value: getRuleValue({ [key]: expected }, key), mode: Array.isArray(getRuleValue({ [key]: expected }, key)) ? 'list' : typeof getRuleValue({ [key]: expected }, key) === 'number' ? 'number' : typeof getRuleValue({ [key]: expected }, key) === 'boolean' ? 'boolean' : 'text' })); entries[index] = { ...entries[index], ...patch }; for (const [key] of Object.entries(rule)) if (!['enabled', 'priority', 'description', 'reason', 'title', 'name', 'type', 'tool'].includes(key) && !String(key).startsWith('classifier:') && !['field:url', 'field:domain', 'field:args.args', 'field:risk_score', 'field:metadata.behavior.suspicious_sequence', 'field:metadata.behavior.previous_blocked'].includes(key)) delete (rule as any)[key]; for (const entry of entries) { if (!entry.key) continue; const value = coerceRuleInput(String(entry.value ?? ''), entry.mode as any); Object.assign(rule, setRuleOperatorValue(rule, entry.key, entry.operator || 'eq', value)); } return rule; });
  const addCustomEntry = () => mutateRule((rule) => { (rule as any)['field:route_target'] = { contains: '' }; return rule; });
  const normalizeTemplateEntry = (raw: any, fallbackName = 'Imported policy pack') => ({ name: raw?.name || raw?.title || fallbackName, description: raw?.description || raw?.summary || '', source: raw?.source || 'uploaded', template: dedupePolicyDoc(ensurePolicyDoc(raw?.template || raw || {})) });
  const templateRuleStats = (entry: any) => { const doc = ensurePolicyDoc(entry?.template || entry || {}); const activeFingerprints = new Set(RULE_BUCKETS.flatMap((bucket: string) => (workingPolicy[bucket] || []).map((rule: any) => semanticRuleFingerprint(rule)))); const templateFingerprints = RULE_BUCKETS.flatMap((bucket: string) => doc[bucket].map((rule: any) => semanticRuleFingerprint(rule))); const matched = templateFingerprints.filter((fingerprint: string) => activeFingerprints.has(fingerprint)).length; const total = templateFingerprints.length; const implemented = total > 0 && matched === total; const partial = matched > 0 && matched < total; const previews = RULE_BUCKETS.flatMap((bucket: string) => doc[bucket].map((rule: any) => ({ bucket, text: summarizeRuleConditions(rule, 4).join(' → ') || summarizeRule(rule) }))).slice(0, 5); return { doc, total, matched, implemented, partial, previews }; };
  const removeUploadedTemplate = (name: string) => { setUploadedTemplates((current: any[]) => current.filter((entry: any) => entry?.name !== name)); setTemplateNotice(`Removed ${name}`); setTemplateError(''); };
  const applyTemplateToBuilder = (template: any) => { const templateDoc = dedupePolicyDoc(ensurePolicyDoc(template?.template || template || {})); const nextDoc = templateMode === 'replace' ? templateDoc : mergePolicyWithoutDuplicates(workingPolicy, templateDoc); setPolicyText(JSON.stringify(nextDoc, null, 2)); const focusDoc = templateMode === 'replace' ? nextDoc : templateDoc; const nextBucket = pickFirstNonEmptyBucket(focusDoc); const targetRule = focusDoc[nextBucket]?.[0] || nextDoc[nextBucket]?.[0] || null; const nextIndex = targetRule ? Math.max(0, nextDoc[nextBucket].findIndex((rule: any) => semanticRuleFingerprint(rule) === semanticRuleFingerprint(targetRule))) : 0; selectRule(nextBucket, nextIndex); };
  const removeTemplateFromBuilder = (template: any) => { const templateDoc = dedupePolicyDoc(ensurePolicyDoc(template?.template || template || {})); const removeSet = new Set(RULE_BUCKETS.flatMap((bucket: string) => (templateDoc[bucket] || []).map((rule: any) => semanticRuleFingerprint(rule)))); const nextDoc = ensurePolicyDoc({ block: (workingPolicy.block || []).filter((rule: any) => !removeSet.has(semanticRuleFingerprint(rule))), warn: (workingPolicy.warn || []).filter((rule: any) => !removeSet.has(semanticRuleFingerprint(rule))), monitor: (workingPolicy.monitor || []).filter((rule: any) => !removeSet.has(semanticRuleFingerprint(rule))), allow: (workingPolicy.allow || []).filter((rule: any) => !removeSet.has(semanticRuleFingerprint(rule))) }); setPolicyText(JSON.stringify(nextDoc, null, 2)); setTemplateNotice(`Removed rules from ${template.name || 'template'} out of builder`); selectRule(pickFirstNonEmptyBucket(nextDoc), 0); };
  const handleTemplateUpload = async (files: FileList | null) => { if (!files?.length) return; const imported: any[] = []; const failures: string[] = []; for (const file of Array.from(files)) { try { const text = await file.text(); const parsed = JSON.parse(text); imported.push(normalizeTemplateEntry(parsed, file.name.replace(/\.json$/i, ''))); } catch (error: any) { failures.push(`${file.name}: ${error?.message || 'Invalid JSON'}`); } } if (imported.length) { setUploadedTemplates((current: any[]) => { const merged = [...current]; for (const entry of imported) { const idx = merged.findIndex((row: any) => row?.name === entry.name); if (idx >= 0) merged[idx] = entry; else merged.unshift(entry); } return merged; }); setTemplateNotice(`Imported ${imported.length} policy pack${imported.length === 1 ? '' : 's'}.`); } else setTemplateNotice(''); setTemplateError(failures.join(' · ')); if (uploadInputRef.current) uploadInputRef.current.value = ''; };
  const templateCards = [...uploadedTemplates.map((entry: any, idx: number) => normalizeTemplateEntry({ ...entry, source: 'uploaded' }, entry?.name || `Imported pack ${idx + 1}`)), ...(Array.isArray(templates) ? templates : []).map((entry: any, idx: number) => normalizeTemplateEntry({ ...entry, source: 'builtin' }, entry?.name || `Varden pack ${idx + 1}`))];
  const templateKey = (template: any, idx: number) => `${template.source}:${template.name || idx}`;
  const toggleTemplateExpanded = (key: string) => setExpandedTemplateKeys((current) => ({ ...current, [key]: !current[key] }));
  const parseError = (() => { try { JSON.parse(policyText); return ''; } catch (error: any) { return error?.message || 'Invalid JSON'; } })();

  return (
    <div className="pageGrid">
      <section className="layout layout--twoThirds rulesLayout">
        <div className="stack">
          <div className="card">
            <div className="sectionHeader"><div><div className="eyebrow">Rule sets</div><h3>Interactive policy builder</h3></div><div className="toggleRow"><button type="button" className="button button--ghost" onClick={() => addRule()}>New rule</button><button type="button" className="button" onClick={onSave} disabled={loading || !!parseError}>{loading ? 'Saving…' : 'Validate & save'}</button></div></div>
            <div className="bucketTabs">{RULE_BUCKETS.map((bucket: string) => (<button type="button" key={bucket} className={classNames('bucketTab', selectedBucket === bucket && 'is-active')} onClick={() => selectRule(bucket, 0)}><span>{bucket}</span><strong>{workingPolicy[bucket].length}</strong></button>))}</div>
            <div className="rulesSplit">
              <div className="ruleRail"><div className="ruleRail__header"><div><div className="subheading">{selectedBucket} rules</div><p className="muted">Grouped the way analysts expect: block, warn, monitor, and allow.</p></div></div><div className="ruleList">{activeRules.map((rule: any, idx: number) => (<button type="button" key={idx} ref={(node) => { ruleItemRefs.current[ruleKey(selectedBucket, idx)] = node; }} className={classNames('ruleCard', idx === selectedRuleIndex && 'is-active', highlightedRuleKey === ruleKey(selectedBucket, idx) && 'is-highlighted')} onClick={() => selectRule(selectedBucket, idx)}><div><div className="ruleCard__title">{summarizeRule(rule)}</div><div className="ruleCard__meta">{rule.type || 'any type'} {rule.tool ? `· ${rule.tool}` : ''}</div></div><div className="ruleCard__flags">{rule.enabled === false ? <span className="badge">disabled</span> : null}<span className={`badge badge--${bucketTone(selectedBucket)}`}>{selectedBucket}</span></div></button>))}{!activeRules.length ? <div className="emptyState"><strong>No {selectedBucket} rules yet</strong><p className="muted">Create the first rule in this group and Varden will preserve the JSON under the hood.</p><button type="button" className="button" onClick={() => addRule(selectedBucket)}>Create {selectedBucket} rule</button></div> : null}</div></div>
              <div className="ruleEditorPane" ref={ruleEditorPaneRef}>{activeRule ? <div className="ruleEditor"><div className="ruleEditor__toolbar"><div><div className="eyebrow">Selected rule</div><h4>{summarizeRule(activeRule)}</h4></div><div className="toggleRow">{ruleReturnTo ? <button type="button" className="button button--ghost" onClick={() => onBackToDecision?.(ruleReturnTo)}>← Back to decision</button> : null}<button type="button" className="button button--ghost" onClick={() => moveRule(-1)} disabled={selectedRuleIndex === 0}>Up</button><button type="button" className="button button--ghost" onClick={() => moveRule(1)} disabled={selectedRuleIndex === activeRules.length - 1}>Down</button><button type="button" className="button button--ghost" onClick={duplicateRule}>Duplicate</button><button type="button" className="button button--ghost" onClick={deleteRule}>Delete</button></div></div>
                <div className="ruleEditorGrid"><label className={fieldClass('title', 'formField')}><span>Rule name</span><input className="input" value={String(activeRule.title || activeRule.name || '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(setRuleSimpleValue(rule, 'title', e.target.value), 'name', ''))} /></label><label className={fieldClass('type', 'formField')}><span>Action type</span><input className="input" value={String(activeRule.type || '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, 'type', e.target.value))} placeholder="http_request, process_spawn, sql_query" /></label><label className={fieldClass('tool', 'formField')}><span>Tool name</span><input className="input" value={String(activeRule.tool || '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, 'tool', e.target.value))} placeholder="requests.get" /></label><label className={fieldClass('priority', 'formField')}><span>Priority</span><input className="input" type="number" value={String(activeRule.priority ?? '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, 'priority', e.target.value === '' ? '' : Number(e.target.value)))} /></label><label className={fieldClass('description', 'formField formField--wide')}><span>Description</span><textarea className="input textarea" value={String(activeRule.description || activeRule.reason || '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(setRuleSimpleValue(rule, 'description', e.target.value), 'reason', ''))} /></label></div>
                <label className={fieldClass('enabled', 'switchRow')}><input type="checkbox" checked={activeRule.enabled !== false} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, 'enabled', e.target.checked ? true : false))} /> Enabled</label>
                <div className="logicBuilder"><div className="subheading">Rule logic builder</div><div className="logicFlow"><div className="logicNode"><strong>IF</strong><span>{activeRule.type || 'any action'}{activeRule.tool ? ` · ${activeRule.tool}` : ''}</span></div><div className="logicConnector">AND</div><div className="logicNode"><strong>WHEN</strong><span>{customRuleEntries(activeRule).length + ADVANCED_FIELDS.filter((field: any) => Boolean(getRuleValue(activeRule, field.key))).length + CLASSIFIER_KEYS.filter((key: string) => Boolean(activeRule[`classifier:${key}`])).length} active conditions</span></div><div className="logicConnector">THEN</div><div className={`logicNode logicNode--${bucketTone(selectedBucket)}`}><strong>{selectedBucket.toUpperCase()}</strong><span>{activeRule.description || activeRule.reason || 'policy outcome'}</span></div></div></div>
                <div className="formSection"><div className="subheading">Common matches</div><div className="ruleEditorGrid">{ADVANCED_FIELDS.map((field: any) => field.valueType === 'boolean' ? (<label key={field.key} className={fieldClass(field.key, 'switchRow switchRow--card')}><input type="checkbox" checked={Boolean(getRuleValue(activeRule, field.key))} onChange={(e) => mutateRule((rule) => setRuleOperatorValue(rule, field.key, field.operator, e.target.checked))} /><span>{field.label}</span></label>) : (<label key={field.key} className={fieldClass(field.key, 'formField')}><span>{field.label}</span><input className="input" placeholder={field.placeholder || ''} value={String(getRuleValue(activeRule, field.key) || '')} onChange={(e) => mutateRule((rule) => setRuleOperatorValue(rule, field.key, field.operator, e.target.value))} /></label>))}<label className={fieldClass('field:risk_score', 'formField')}><span>Risk score at least</span><input className="input" type="number" value={getRuleOperator(activeRule, 'field:risk_score') === 'gte' ? String(getRuleValue(activeRule, 'field:risk_score') || '') : ''} onChange={(e) => mutateRule((rule) => setRuleOperatorValue(rule, 'field:risk_score', 'gte', e.target.value === '' ? '' : Number(e.target.value)))} /></label><label className={fieldClass('field:risk_score', 'formField')}><span>Risk score at most</span><input className="input" type="number" value={getRuleOperator(activeRule, 'field:risk_score') === 'lte' ? String(getRuleValue(activeRule, 'field:risk_score') || '') : ''} onChange={(e) => mutateRule((rule) => setRuleOperatorValue(rule, 'field:risk_score', 'lte', e.target.value === '' ? '' : Number(e.target.value)))} /></label></div></div>
                <div className="formSection"><div className="subheading">Classifier hits</div><div className="classifierGrid">{CLASSIFIER_KEYS.map((classifier: string) => (<label key={classifier} className={fieldClass(`classifier:${classifier}`, 'switchRow switchRow--card')}><input type="checkbox" checked={Boolean(activeRule[`classifier:${classifier}`])} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, `classifier:${classifier}`, e.target.checked ? true : ''))} /><span>{classifier.replace(/_/g, ' ')}</span></label>))}</div></div>
                <div className="formSection"><div className="sectionHeader sectionHeader--tight"><div><div className="subheading">Custom conditions</div><p className="muted">Keep the flexible engine, but edit conditions with fields instead of raw JSON.</p></div><button type="button" className="button button--ghost" onClick={addCustomEntry}>Add condition</button></div><div className="customList">{customRuleEntries(activeRule).map(([key, expected], idx) => { const entryRule = { [key]: expected }; const operator = getRuleOperator(entryRule, key, 'eq'); const rawValue = getRuleValue(entryRule, key); const valueMode = Array.isArray(rawValue) ? 'list' : typeof rawValue === 'number' ? 'number' : typeof rawValue === 'boolean' ? 'boolean' : 'text'; return (<div key={`${key}-${idx}`} className={fieldClass(key, 'customRow')}><input className="input" value={key} onChange={(e) => updateCustomEntry(idx, { key: e.target.value })} placeholder="field:route_target" /><select className="input input--small" value={operator} onChange={(e) => updateCustomEntry(idx, { operator: e.target.value })}>{OPERATOR_OPTIONS.map((op: string) => <option key={op} value={op}>{op}</option>)}</select><input className="input" value={Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue ?? '')} onChange={(e) => updateCustomEntry(idx, { value: e.target.value, mode: valueMode })} placeholder="value" /></div>); })}{!customRuleEntries(activeRule).length ? <div className="muted">No extra conditions on this rule.</div> : null}</div></div>
              </div> : <div className="emptyState"><strong>Select a rule</strong><p className="muted">Pick a rule from the grouped list, or create a new one in this bucket.</p></div>}</div>
            </div>
          </div>
          <div className="card"><div className="sectionHeader"><div><div className="eyebrow">Advanced</div><h3>Raw policy document</h3></div><button type="button" className="button button--ghost" onClick={() => setShowAdvanced((v) => !v)}>{showAdvanced ? 'Hide JSON' : 'Show JSON'}</button></div><p className="muted">The visual builder writes straight back to the real OSS policy file, so advanced users can still inspect or hand-edit the underlying JSON.</p>{parseError ? <div className="banner banner--error">JSON error: {parseError}</div> : null}{showAdvanced ? <textarea className="editor editor--compact" value={policyText} onChange={(e) => setPolicyText(e.target.value)} spellCheck={false} /> : null}</div>
        </div>
        <div className="stack">
          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Templates</div>
                <h3>Quick starting points</h3>
              </div>
              <div className="toggleRow">
                <button type="button" className={classNames('segmented', templateMode === 'merge' && 'is-active')} onClick={() => setTemplateMode('merge')}>Merge</button>
                <button type="button" className={classNames('segmented', templateMode === 'replace' && 'is-active')} onClick={() => setTemplateMode('replace')}>Replace</button>
              </div>
            </div>
            <div className="templatePanelTools">
              <div className="muted">Use Varden packs as one-click starting points, or upload your own JSON policy packs and keep them available here.</div>
              <div className="toggleRow">
                <input ref={uploadInputRef} type="file" accept=".json,application/json" multiple style={{ display: 'none' }} onChange={(e) => handleTemplateUpload(e.target.files)} />
                <button type="button" className="button button--ghost" onClick={() => uploadInputRef.current?.click()}>Upload rules / policies</button>
              </div>
            </div>
            {templateNotice ? <div className="banner banner--ok">{templateNotice}</div> : null}
            {templateError ? <div className="banner banner--error">{templateError}</div> : null}
            <div className="templateList">
              {templateCards.map((template: any, idx: number) => {
                const stats = templateRuleStats(template);
                const key = templateKey(template, idx);
                const expanded = !!expandedTemplateKeys[key];
                const stateLabel = stats.implemented ? 'Fully added' : stats.partial ? 'Partially added' : 'Not added';
                const summaryChip = `${stats.total} rules · ${stats.matched}/${stats.total} present · ${expanded ? 'Hide details' : 'Open pack'}`;
                return (
                  <div key={key} className={classNames('templateCard', 'templateCard--managed', expanded && 'is-expanded', stats.implemented && 'is-implemented', stats.partial && 'is-partial')}>
                    <div className="templateCard__content">
                      <div className="templateCard__mainAction">
                        <button type="button" className="templateCard__summaryButton" onClick={() => toggleTemplateExpanded(key)} aria-expanded={expanded}>
                          <div className="templateCard__header">
                            <div className="templateCard__titleBlock">
                              <strong>{template.name || `Template ${idx + 1}`}</strong>
                              {template.description ? <div className="ruleCard__meta">{template.description}</div> : null}
                              <div className="ruleCard__meta">{template.source === 'uploaded' ? 'Uploaded policy pack' : 'Built-in policy pack'}</div>
                            </div>
                            <div className="templateCard__badges">
                              <span className={classNames('badge', stats.implemented ? 'badge--ok' : stats.partial ? 'badge--warn' : 'badge--danger')}>{stateLabel}</span>
                            </div>
                          </div>
                          <div className="templateCard__summaryMeta">
                            <span>{summaryChip}</span>
                          </div>
                        </button>
                        {expanded ? (
                          <div className="templateCard__details">
                            <div className="templateCounts">{RULE_BUCKETS.map((bucket: string) => <span key={bucket}>{bucket}: {stats.doc[bucket].length}</span>)}</div>
                            <div className="templateCard__metaRow"><span>{stats.matched}/{stats.total} rules already present</span><span>{templateMode === 'replace' ? 'Replace on add' : 'Merge on add'}</span></div>
                            <div className="templatePreviewList">{stats.previews.length ? stats.previews.map((preview: any, previewIdx: number) => (<div key={`${preview.bucket}:${previewIdx}`} className="templatePreviewLine"><span className={classNames('badge', `badge--${bucketTone(preview.bucket)}`)}>{preview.bucket}</span><span>{preview.text}</span></div>)) : <div className="muted">No readable rule summary available.</div>}</div>
                          </div>
                        ) : null}
                      </div>
                      <div className="templateCard__actions" style={{ justifySelf: 'end', marginLeft: 'auto', minWidth: 172, display: 'grid', justifyItems: 'end', alignContent: 'start', gap: 10 }}>
                        <button type="button" className="button button--tiny" style={{ width: 172, minWidth: 172 }} onClick={() => applyTemplateToBuilder(template)} disabled={stats.implemented}>{stats.implemented ? 'Already added' : 'Add to builder'}</button>
                        <button type="button" className="button button--ghost button--tiny" style={{ width: 172, minWidth: 172 }} onClick={() => removeTemplateFromBuilder(template)}>Remove from builder</button>
                        {template.source === 'uploaded' ? <button type="button" className="button button--ghost button--tiny" style={{ width: 172, minWidth: 172 }} onClick={() => removeUploadedTemplate(template.name)}>Remove pack</button> : null}
                      </div>
                    </div>
                  </div>
                );
              })}
              {!templateCards.length ? <div className="emptyState emptyState--compact"><strong>No policy packs loaded.</strong><span className="muted">Upload your own JSON policy packs to start building a private template library.</span></div> : null}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
