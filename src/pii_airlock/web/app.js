const $ = (id) => document.getElementById(id);
let operationId = null;

async function requestJSON(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}

async function health() {
  try {
    const data = await requestJSON('/api/v1/health');
    $('health').textContent = `LM Studio: ${data.lm_studio.reachable ? 'reachable' : 'offline'} · Cloud: ${data.cloud_configured ? 'configured' : 'dry-run'}`;
  } catch (error) { $('health').textContent = `Health check failed: ${error.message}`; }
}

$('file').addEventListener('change', async () => {
  const file = $('file').files[0];
  if (!file) return;
  const form = new FormData(); form.append('file', file);
  try {
    const data = await requestJSON('/api/v1/documents/extract', {method:'POST', body:form});
    $('source').value = data.text;
  } catch (error) { setStatus('BLOCKED', error.message); }
});

$('analyze').addEventListener('click', async () => {
  resetOutputs();
  try {
    const data = await requestJSON('/api/v1/operations', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({text:$('source').value, task:$('task').value, model:$('model').value})});
    operationId = data.operation_id;
    $('entities').textContent = Object.entries(data.entity_counts).map(([type,count]) => `${type} × ${count}`).join('\n') || 'No entities';
    $('payload').textContent = data.sanitized_fields.text;
    if (data.status === 'SAFE_TO_SEND') {
      setStatus('SAFE TO SEND'); $('complete').disabled = false; $('destroy').disabled = false;
    } else { setStatus('BLOCKED', data.blocked_reasons.join('\n')); $('destroy').disabled = false; }
  } catch (error) { setStatus('BLOCKED', error.message); }
});

$('complete').addEventListener('click', async () => {
  try {
    const data = await requestJSON(`/api/v1/operations/${operationId}/complete`, {method:'POST'});
    $('answer').textContent = data.restored_text || 'DRY RUN — sanitized payload was not sent because OPENAI_API_KEY is absent.';
    setStatus(data.cloud_status === 'COMPLETED' ? 'COMPLETED' : 'SAFE · DRY RUN');
    $('complete').disabled = true; $('destroy').disabled = true; operationId = null;
  } catch (error) { setStatus('BLOCKED', error.message); }
});

$('destroy').addEventListener('click', async () => {
  if (operationId) await requestJSON(`/api/v1/operations/${operationId}`, {method:'DELETE'});
  operationId = null; resetOutputs(); setStatus('MAPPING DESTROYED');
});

function resetOutputs(){ $('entities').textContent='Analyzing…'; $('payload').textContent='Waiting for local gate…'; $('answer').textContent='Not sent.'; $('complete').disabled=true; }
function setStatus(label, detail=''){ $('status').className=`status ${label.includes('BLOCK')?'blocked':label.includes('SAFE')||label.includes('COMPLETE')?'safe':'idle'}`; $('status').textContent=detail?`${label} · ${detail}`:label; }
health();
