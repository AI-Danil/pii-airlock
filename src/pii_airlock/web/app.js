const $ = (id) => document.getElementById(id);
let operationId = null;
let cloudConfigured = false;
let analyzedFields = null;
let currentOperation = null;
let selectedSourceSpan = null;
let selectedRedaction = null;
let currentReceipt = null;

async function requestJSON(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof data.detail === 'object' ? data.detail.message : data.detail;
    throw new Error(detail || `HTTP ${response.status}`);
  }
  return data;
}

async function health() {
  try {
    const data = await requestJSON('/api/v1/health');
    cloudConfigured = data.cloud_configured;
    $('complete').textContent = cloudConfigured ? 'I reviewed it — send' : 'Finish dry-run';
    $('health').textContent = `LM Studio: ${data.lm_studio.reachable ? 'reachable' : 'offline'} · Provider: ${cloudConfigured ? 'configured' : 'dry-run only'} · Default tokens: ${data.default_token_mode}`;
  } catch (error) {
    $('health').textContent = `Health check failed: ${error.message}`;
  }
}

$('file').addEventListener('change', async () => {
  const file = $('file').files[0];
  if (!file) return;
  const form = new FormData();
  form.append('file', file);
  try {
    const data = await requestJSON('/api/v1/documents/extract', { method: 'POST', body: form });
    $('source').value = data.text;
    const manifest = data.manifest;
    $('fileManifest').textContent = `${manifest.format.toUpperCase()} · ${manifest.text_characters} chars · ${manifest.parser_isolation}`;
  } catch (error) {
    setStatus('BLOCKED', error.message);
  }
});

$('analyze').addEventListener('click', async () => {
  resetOutputs();
  try {
    if (operationId) {
      await requestJSON(`/api/v1/operations/${operationId}`, { method: 'DELETE' });
      operationId = null;
    }
    const data = await requestJSON('/api/v1/operations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: $('source').value,
        task: $('task').value,
        model: $('model').value,
        token_mode: $('tokenMode').value,
      }),
    });
    operationId = data.operation_id;
    analyzedFields = { task: $('task').value, text: $('source').value };
    updateOperationView(data);
  } catch (error) {
    setStatus('BLOCKED', error.message);
  }
});

$('acknowledgeWarnings').addEventListener('change', updateCompleteButton);

$('complete').addEventListener('click', async () => {
  try {
    // Authorization is a separate call bound to the revision on screen, so an
    // edit made after this click cannot inherit the confirmation.
    await requestJSON(`/api/v1/operations/${operationId}/authorize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        review_revision: currentOperation ? currentOperation.review_revision : 0,
        acknowledge_warnings: $('acknowledgeWarnings').checked,
      }),
    });
    const data = await requestJSON(`/api/v1/operations/${operationId}/complete`, { method: 'POST' });
    $('answer').textContent = data.restored_text || 'Dry-run finished. The displayed outbound content was not sent.';
    if (data.output_trust) {
      $('answer').textContent += `\n\nTrust: ${data.output_trust.level}; actions: ${data.output_trust.downstream_actions}.`;
    }
    currentReceipt = data.review_receipt || null;
    $('downloadReceipt').hidden = !currentReceipt;
    setStatus(data.cloud_status === 'COMPLETED' ? 'COMPLETED' : 'DRY RUN COMPLETE');
    $('complete').disabled = true;
    $('destroy').disabled = true;
    operationId = null;
    currentOperation = null;
    $('reviewTools').hidden = true;
  } catch (error) {
    setStatus('BLOCKED', error.message);
  }
});

$('destroy').addEventListener('click', async () => {
  if (operationId) {
    await requestJSON(`/api/v1/operations/${operationId}`, { method: 'DELETE' });
  }
  operationId = null;
  analyzedFields = null;
  currentOperation = null;
  resetOutputs();
  setStatus('MAPPING DESTROYED');
});

function resetOutputs() {
  selectedSourceSpan = null;
  selectedRedaction = null;
  currentReceipt = null;
  $('downloadReceipt').hidden = true;
  $('entities').textContent = 'Analyzing…';
  $('redactionPreview').replaceChildren();
  $('securityWarnings').replaceChildren();
  $('reviewTools').hidden = true;
  $('payload').textContent = 'Waiting for the local checks…';
  $('answer').textContent = 'No provider call has been made.';
  $('acknowledgeWarnings').checked = false;
  $('acknowledgeRow').hidden = true;
  $('complete').disabled = true;
}

function updateCompleteButton() {
  if (!currentOperation || currentOperation.status === 'BLOCKED') {
    $('complete').disabled = true;
    return;
  }
  const needsAcknowledgement = (currentOperation.security_warnings || []).length > 0;
  $('complete').disabled = needsAcknowledgement && !$('acknowledgeWarnings').checked;
}

function renderRedactionPreview(redactions) {
  const container = $('redactionPreview');
  container.replaceChildren();
  const fields = [
    ['task', 'Task', analyzedFields.task],
    ['text', 'Document', analyzedFields.text],
  ];
  for (const [field, label, value] of fields) {
    const spans = redactions
      .filter((item) => item.field === field)
      .sort((left, right) => left.start - right.start);
    const section = document.createElement('section');
    const heading = document.createElement('h3');
    heading.textContent = `${label} · local-only highlight`;
    section.appendChild(heading);
    const preview = document.createElement('p');
    preview.dataset.field = field;
    preview.tabIndex = 0;
    let position = 0;
    for (const span of spans) {
      preview.appendChild(document.createTextNode(value.slice(position, span.start)));
      const marked = document.createElement('mark');
      marked.textContent = value.slice(span.start, span.end);
      marked.title = `${span.type} → ${span.token}`;
      marked.setAttribute('aria-label', `${span.type} redaction`);
      marked.dataset.field = field;
      marked.dataset.start = span.start;
      marked.dataset.end = span.end;
      marked.addEventListener('click', () => selectRedaction(span, marked));
      preview.appendChild(marked);
      position = span.end;
    }
    preview.appendChild(document.createTextNode(value.slice(position)));
    section.appendChild(preview);
    container.appendChild(section);
  }
}

function updateOperationView(data) {
  currentOperation = data;
  selectedSourceSpan = null;
  selectedRedaction = null;
  $('acknowledgeWarnings').checked = false;
  $('reviewHint').textContent = 'Select text to add a span, or click a highlighted span to edit it.';
  $('entities').textContent = Object.entries(data.entity_counts)
    .map(([type, count]) => `${type} × ${count}`)
    .join('\n') || 'No entities were detected.';
  renderWarnings(data.security_warnings || [], data.detector_warnings || []);
  renderRedactionPreview(data.redactions || []);
  $('payload').textContent = JSON.stringify(data.outbound_content, null, 2);
  $('tokenMode').value = data.token_mode;
  $('reviewTools').hidden = false;
  updateReviewButtons();
  $('destroy').disabled = false;
  if (data.status === 'BLOCKED') {
    setStatus('BLOCKED', data.blocked_reasons.join('\n'));
  } else if ((data.security_warnings || []).length) {
    setStatus('REVIEW REQUIRED', 'The source carries injection warnings; acknowledge them to authorize the send.');
  } else {
    setStatus('REVIEW REQUIRED', 'Inspect the outbound fields; rule checks are not proof of anonymity.');
  }
  updateCompleteButton();
}

function renderWarnings(securityWarnings, detectorWarnings) {
  const container = $('securityWarnings');
  container.replaceChildren();
  $('acknowledgeRow').hidden = !securityWarnings.length;
  const warnings = [...securityWarnings, ...detectorWarnings];
  if (!warnings.length) return;
  const heading = document.createElement('strong');
  heading.textContent = 'Manual review warning';
  const text = document.createElement('p');
  text.textContent = `${warnings.join(', ')}. The privacy gateway does not make document instructions trustworthy.`;
  container.append(heading, text);
}

function selectRedaction(span, element) {
  document.querySelectorAll('.redaction-preview mark.selected').forEach((item) => item.classList.remove('selected'));
  element.classList.add('selected');
  selectedRedaction = span;
  selectedSourceSpan = null;
  $('reviewType').value = span.type;
  $('reviewHint').textContent = `${span.field} ${span.start}:${span.end} · ${span.type}`;
  updateReviewButtons();
}

document.addEventListener('selectionchange', () => {
  if (!operationId || !analyzedFields) return;
  const selection = window.getSelection();
  if (!selection || selection.rangeCount !== 1 || selection.isCollapsed) return;
  const range = selection.getRangeAt(0);
  const parent = elementParent(range.commonAncestorContainer);
  if (!parent) return;
  const preview = parent.closest('p[data-field]');
  if (!preview || !preview.contains(range.startContainer) || !preview.contains(range.endContainer)) return;
  const before = document.createRange();
  before.selectNodeContents(preview);
  before.setEnd(range.startContainer, range.startOffset);
  const start = before.toString().length;
  const end = start + range.toString().length;
  if (end <= start) return;
  selectedSourceSpan = { field: preview.dataset.field, start, end };
  selectedRedaction = null;
  document.querySelectorAll('.redaction-preview mark.selected').forEach((item) => item.classList.remove('selected'));
  $('reviewHint').textContent = `${preview.dataset.field} ${start}:${end} · selected for a new redaction`;
  updateReviewButtons();
});

function elementParent(node) {
  return node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
}

function updateReviewButtons() {
  $('addSelection').disabled = !selectedSourceSpan;
  $('removeSelection').disabled = !selectedRedaction;
  $('retagSelection').disabled = !selectedRedaction;
}

async function applyReview(edit) {
  if (!operationId || !analyzedFields) return;
  try {
    const data = await requestJSON(`/api/v1/operations/${operationId}/redactions`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...analyzedFields, edits: edit ? [edit] : [] }),
    });
    updateOperationView(data);
  } catch (error) {
    setStatus('BLOCKED', error.message);
  }
}

$('addSelection').addEventListener('click', () => {
  if (!selectedSourceSpan) return;
  applyReview({ action: 'add', ...selectedSourceSpan, type: $('reviewType').value });
});

$('confirmSpans').addEventListener('click', () => applyReview(null));

$('removeSelection').addEventListener('click', () => {
  if (!selectedRedaction) return;
  applyReview({
    action: 'remove',
    field: selectedRedaction.field,
    start: selectedRedaction.start,
    end: selectedRedaction.end,
  });
});

$('retagSelection').addEventListener('click', () => {
  if (!selectedRedaction) return;
  applyReview({
    action: 'retag',
    field: selectedRedaction.field,
    start: selectedRedaction.start,
    end: selectedRedaction.end,
    type: $('reviewType').value,
  });
});

$('downloadReceipt').addEventListener('click', () => {
  if (!currentReceipt) return;
  const blob = new Blob([`${JSON.stringify(currentReceipt, null, 2)}\n`], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `pii-airlock-review-${currentReceipt.operation_id}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

function setStatus(label, detail = '') {
  const statusClass = label.includes('BLOCK') ? 'blocked' : label.includes('COMPLETE') ? 'complete' : 'idle';
  $('status').className = `status ${statusClass}`;
  $('status').textContent = detail ? `${label} · ${detail}` : label;
}

health();
