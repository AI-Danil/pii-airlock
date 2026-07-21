const $ = (id) => document.getElementById(id);
let operationId = null;
let cloudConfigured = false;

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
    $('health').textContent = `LM Studio: ${data.lm_studio.reachable ? 'reachable' : 'offline'} · Provider: ${cloudConfigured ? 'configured' : 'dry-run only'}`;
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
      }),
    });
    operationId = data.operation_id;
    $('entities').textContent = Object.entries(data.entity_counts)
      .map(([type, count]) => `${type} × ${count}`)
      .join('\n') || 'No entities were detected.';
    renderRedactionPreview(data.redactions || []);
    $('payload').textContent = JSON.stringify(data.outbound_content, null, 2);
    if (data.status === 'READY_FOR_REVIEW') {
      setStatus('REVIEW REQUIRED', 'No deterministic leak was found; inspect the outbound fields.');
      $('complete').disabled = false;
      $('destroy').disabled = false;
    } else {
      setStatus('BLOCKED', data.blocked_reasons.join('\n'));
      $('destroy').disabled = false;
    }
  } catch (error) {
    setStatus('BLOCKED', error.message);
  }
});

$('complete').addEventListener('click', async () => {
  try {
    const data = await requestJSON(`/api/v1/operations/${operationId}/complete`, { method: 'POST' });
    $('answer').textContent = data.restored_text || 'Dry-run finished. The displayed outbound content was not sent.';
    setStatus(data.cloud_status === 'COMPLETED' ? 'COMPLETED' : 'DRY RUN COMPLETE');
    $('complete').disabled = true;
    $('destroy').disabled = true;
    operationId = null;
  } catch (error) {
    setStatus('BLOCKED', error.message);
  }
});

$('destroy').addEventListener('click', async () => {
  if (operationId) {
    await requestJSON(`/api/v1/operations/${operationId}`, { method: 'DELETE' });
  }
  operationId = null;
  resetOutputs();
  setStatus('MAPPING DESTROYED');
});

function resetOutputs() {
  $('entities').textContent = 'Analyzing…';
  $('redactionPreview').replaceChildren();
  $('payload').textContent = 'Waiting for the local checks…';
  $('answer').textContent = 'No provider call has been made.';
  $('complete').disabled = true;
}

function renderRedactionPreview(redactions) {
  const container = $('redactionPreview');
  container.replaceChildren();
  const fields = [
    ['task', 'Task', $('task').value],
    ['text', 'Document', $('source').value],
  ];
  for (const [field, label, value] of fields) {
    const spans = redactions
      .filter((item) => item.field === field)
      .sort((left, right) => left.start - right.start);
    if (!spans.length) continue;

    const section = document.createElement('section');
    const heading = document.createElement('h3');
    heading.textContent = `${label} · local-only highlight`;
    section.appendChild(heading);
    const preview = document.createElement('p');
    let position = 0;
    for (const span of spans) {
      preview.appendChild(document.createTextNode(value.slice(position, span.start)));
      const marked = document.createElement('mark');
      marked.textContent = value.slice(span.start, span.end);
      marked.title = `${span.type} → ${span.token}`;
      marked.setAttribute('aria-label', `${span.type} redaction`);
      preview.appendChild(marked);
      position = span.end;
    }
    preview.appendChild(document.createTextNode(value.slice(position)));
    section.appendChild(preview);
    container.appendChild(section);
  }
}

function setStatus(label, detail = '') {
  const statusClass = label.includes('BLOCK') ? 'blocked' : label.includes('COMPLETE') ? 'complete' : 'idle';
  $('status').className = `status ${statusClass}`;
  $('status').textContent = detail ? `${label} · ${detail}` : label;
}

health();
