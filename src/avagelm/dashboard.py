"""Loopback-only dashboard for launching and reviewing local evaluation runs."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from urllib.parse import urlparse, urlsplit

from avagelm.core.providers import make_provider
from avagelm.core.runner import run


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>AVAGELM | Local Audit</title><style>
:root{color-scheme:dark;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#0b1220;color:#eaf1ff}*{box-sizing:border-box}body{margin:0;padding:28px 18px}
main{max-width:1080px;margin:auto}header{padding:8px 2px 18px;border-bottom:1px solid #2b3d5a;margin-bottom:20px}h1{font-size:25px;color:#7ee0c3;margin:0}h2{font-size:17px;margin:0 0 12px}.muted{color:#a9bad5}
section,.card{background:#131e31;border:1px solid #2b3d5a;border-radius:8px;padding:18px;margin:16px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:10px}.card{margin:0;padding:14px}.value{font-size:1.55rem;font-weight:650;margin-top:3px}
form{display:flex;flex-wrap:wrap;gap:12px;align-items:end}label{display:grid;gap:5px;color:#a9bad5;flex:1 1 170px}input,select,button{font:inherit;color:#eaf1ff;background:#0b1220;border:1px solid #405574;border-radius:6px;padding:9px}
button{background:#146b60;border:0;font-weight:650;cursor:pointer;padding:10px 16px}button:disabled{opacity:.55;cursor:wait}.bar{height:12px;background:#243653;border-radius:6px;overflow:hidden}.bar i{display:block;height:100%;background:#ef6565;width:0}.bar.safe i{background:#42c5a1}
.outcome{display:grid;grid-template-columns:1fr 1fr;gap:18px}.outcome p{margin:8px 0}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:700px;table-layout:fixed}th:nth-child(1){width:17%}th:nth-child(2){width:18%}th:nth-child(3){width:17%}th:nth-child(4){width:13%}th:nth-child(5){width:35%}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #2b3d5a;padding:9px}th{color:#a9bad5;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:200px;overflow:auto;background:#09101c;padding:10px;border-radius:6px;margin:8px 0 0}details summary{cursor:pointer;color:#7ee0c3}.status{margin:12px 0 0}details.logs{margin-top:12px}
@media(max-width:620px){body{padding:18px 12px}.outcome{grid-template-columns:1fr}}.card:first-child .value{font-size:1.05rem;overflow-wrap:anywhere}
</style></head><body><main>
<header><h1>AVAGELM</h1><div class="muted">Local security audit</div></header>
<p class="muted">Run sample messages through a local AI model and see whether unsafe tool requests are stopped. The demo tool returns made-up sample data only.</p>
<section><h2>Start an audit</h2><form id="runForm">
<label>AI service<select id="provider"><option value="ollama">Ollama</option><option value="vllm">vLLM</option></select></label>
<label>Model name<input id="model" maxlength="128" required></label>
<label>Runs per message type<input id="trials" type="number" min="1" max="100" value="5" required></label>
<label>Service address (optional)<input id="baseUrl" maxlength="512" placeholder="Use default address"></label>
<button id="runButton" type="submit">Run audit</button></form><p id="status" class="muted status">Ready to run.</p></section>
<section><h2>Run summary</h2><div id="cards" class="cards"></div></section>
<section><h2>Tool request results</h2><div class="outcome"><div><p>Without the safety check</p><div class="bar"><i id="baselineBar"></i></div></div><div><p>With the safety check</p><div class="bar safe"><i id="defendedBar"></i></div></div></div><p id="caption" class="muted">Waiting for audit results.</p></section>
<section><h2>Message-by-message results</h2><div class="table-wrap"><table><thead><tr><th>Run / type</th><th>Test message</th><th>AI tool request</th><th>Safety result</th><th>More details</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<details class="logs"><summary>Show recent activity log</summary><pre id="logs">No activity yet.</pre></details>
</main><script>
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=v=>{const s=String(v??'');return s.length>180?s.slice(0,177)+'…':s};
function details(label,value){return `<details><summary>${esc(label)}</summary><pre>${esc(typeof value==='string'?value:JSON.stringify(value,null,2))}</pre></details>`}
function renderRows(events){const rows=document.querySelector('#rows');rows.replaceChildren();for(const e of [...events].reverse()){
 const tr=document.createElement('tr');const proposal=e.proposed_tool?`${e.proposed_tool}\n${JSON.stringify(e.proposed_arguments??{})}`:'No tool request';
 const baseline=e.baseline_unauthorized_execution?`Would run (fake data only)\n${JSON.stringify(e.baseline_result??{})}`:'Would not run';
 const allowed=e.defense_reason==='trusted_provenance_and_schema_valid';
 const guarded=e.proposed_tool?(allowed?'Allowed':'Blocked'):'No tool request';
 const response=e.model_error?`Connection error: ${e.model_error}`:(e.text||'(empty reply)');
 const more=`${details('Why?',e.defense_reason||'No tool request')}${details('Without the safety check',baseline)}${details('AI reply or error',response)}<div class="muted">${e.elapsed_seconds??'—'} seconds</div>`;
 const vals=[`${e.trial} · ${e.category}`,details('Message',e.attack??''),details('Tool request',proposal),guarded,more];
 for(let i=0;i<vals.length;i++){const td=document.createElement('td');if(i===1||i===2||i===4)td.innerHTML=vals[i];else td.textContent=vals[i];tr.append(td)}rows.append(tr)} }
async function tick(){try{const [s,events]=await Promise.all([fetch('/api/summary',{cache:'no-store'}).then(r=>r.json()),fetch('/api/events',{cache:'no-store'}).then(r=>r.json())]);
 const metrics=[['Status',(s.status??'not started').replaceAll('_',' ')],['AI calls',`${s.live_trials??0} / ${s.target_live_trials??'—'}`],['Connection errors',s.live_model_errors??0],['Safety checks',s.policy_validation_attempts??0],['Requests blocked',s.policy_validation_blocks??0],['Unprotected actions',s.baseline_unauthorized_tool_calls??0],['Actions stopped',s.defended_blocked_calls??0]];
 document.querySelector('#cards').innerHTML=metrics.map(([n,v])=>`<div class="card"><div class="muted">${esc(n)}</div><div class="value">${esc(v)}</div></div>`).join('');
 const denom=Math.max(Number(s.live_valid_trials)||0,1),b=Number(s.baseline_unauthorized_tool_calls)||0,d=Number(s.defended_unauthorized_tool_calls)||0;
 document.querySelector('#baselineBar').style.width=`${Math.min(100,100*b/denom)}%`;document.querySelector('#defendedBar').style.width=`${Math.min(100,100*d/denom)}%`;
 document.querySelector('#caption').textContent=`Provider ${s.provider||'—'} · model ${s.model||'—'} · corpus SHA-256 ${s.corpus_sha256||'pending'}`;
 // Keep an expanded result in place while the user is reading it. The summary
 // cards and status still refresh; the table catches up as soon as it is closed.
 if(!document.querySelector('#rows details[open]'))renderRows(events);document.querySelector('#logs').textContent=events.slice(-20).map(e=>JSON.stringify({time:e.time,trial:e.trial,case_id:e.case_id,category:e.category,proposed_tool:e.proposed_tool,baseline:e.baseline_unauthorized_execution,guardrail:e.defended_blocked,reason:e.defense_reason,error:e.model_error},null,2)).join('\n\n')||'No activity yet.';
 document.querySelector('#runButton').disabled=Boolean(s.dashboard_run_active);if(s.dashboard_run_active)document.querySelector('#status').textContent='Audit running. The table and logs refresh automatically.';
 else if(s.error)document.querySelector('#status').textContent=`Run failed: ${s.error}`;else if(s.status==='completed_with_errors')document.querySelector('#status').textContent='Run finished with provider errors; see each affected trial.';else if(s.status==='failed')document.querySelector('#status').textContent='Run failed; see the status message above and local artifacts.';else if(s.status==='completed')document.querySelector('#status').textContent='Run completed. Results and audit artifacts are saved locally.';
 }catch(e){document.querySelector('#status').textContent=`Dashboard could not refresh: ${e}`}}
document.querySelector('#runForm').addEventListener('submit',async ev=>{ev.preventDefault();const button=document.querySelector('#runButton');button.disabled=true;document.querySelector('#status').textContent='Checking provider and starting audit…';
 try{const response=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({provider:document.querySelector('#provider').value,model:document.querySelector('#model').value,trials:Number(document.querySelector('#trials').value),base_url:document.querySelector('#baseUrl').value.trim()||null})});const result=await response.json();if(!response.ok)throw Error(result.error||`HTTP ${response.status}`);document.querySelector('#status').textContent='Provider preflight passed. Audit starting…';}
 catch(e){document.querySelector('#status').textContent=`Could not start audit: ${e.message}`;button.disabled=false}});
document.querySelector('#provider').addEventListener('change',()=>{const m=document.querySelector('#model');if(document.querySelector('#provider').value==='ollama'){if(m.value==='gpt-3.5-turbo')m.value='llama3.2:latest'}else if(m.value==='llama3.2:latest')m.value=''});
document.querySelector('#model').value=__MODEL__;document.querySelector('#provider').value=__PROVIDER__;
tick();setInterval(tick,1500);
</script></body></html>'''


def _atomic_json(path: Path, data: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temporary.replace(path)


def _script_json(value: str) -> str:
    """Serialize text safely inside an HTML script element."""
    return (json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026"))


class RunController:
    def __init__(self, artifact_dir: Path):
        self.artifact_dir = artifact_dir
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, provider_name: str, model: str, trials: int,
              base_url: str | None, timeout: float) -> None:
        with self._lock:
            if self.active:
                raise RuntimeError("An audit is already running")
            self._thread = threading.Thread(
                target=self._run, args=(provider_name, model, trials, base_url, timeout),
                name="avagelm-audit", daemon=True,
            )
            self._thread.start()

    def _run(self, provider_name: str, model: str, trials: int,
             base_url: str | None, timeout: float) -> None:
        try:
            provider = make_provider(provider_name, model, base_url, timeout)
            status = provider.check()
            if not status["model_available"]:
                raise RuntimeError(f"Model {model!r} is not listed by {provider_name}; install it or choose an available model")
            run(self.artifact_dir, provider_name, model, trials, base_url=base_url, timeout=timeout)
        except Exception as exc:
            summary_path = self.artifact_dir / "summary.json"
            try:
                existing = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
            except (OSError, json.JSONDecodeError):
                existing = {}
            existing.update({"status": "failed", "error": f"{type(exc).__name__}: {exc}"})
            _atomic_json(summary_path, existing)


def serve(artifact_dir: Path, port: int = 8765, provider: str = "ollama",
          model: str = "llama3.2:latest", base_url: str | None = None,
          timeout: float = 300) -> None:
    artifact_dir = artifact_dir.expanduser().resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    controller = RunController(artifact_dir)

    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, value: dict | list) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                page = PAGE.replace("__MODEL__", _script_json(model)).replace("__PROVIDER__", _script_json(provider))
                body = page.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path in {"/api/summary", "/api/events"}:
                if path == "/api/summary":
                    file = artifact_dir / "summary.json"
                    try:
                        data = json.loads(file.read_text(encoding="utf-8")) if file.exists() else {"status": "not started"}
                    except (OSError, json.JSONDecodeError):
                        data = {"status": "loading"}
                    data["dashboard_run_active"] = controller.active
                    self._send_json(200, data)
                    return
                file = artifact_dir / "telemetry.jsonl"
                rows = []
                if file.exists():
                    try:
                        for line in file.read_text(encoding="utf-8").splitlines()[-100:]:
                            try:
                                item = json.loads(line)
                                if isinstance(item, dict):
                                    rows.append(item)
                            except json.JSONDecodeError:
                                continue
                    except OSError:
                        pass
                self._send_json(200, rows)
                return
            self._send_json(404, {"error": "not found"})

        def do_POST(self):
            if urlparse(self.path).path != "/api/run":
                self._send_json(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4096:
                    raise ValueError("Request body must be between 1 and 4096 bytes")
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("Expected a JSON object")
                provider_name = payload.get("provider", provider)
                if not isinstance(provider_name, str) or provider_name not in {"ollama", "vllm"}:
                    raise ValueError("provider must be ollama or vllm")
                model_name = payload.get("model", model)
                if not isinstance(model_name, str) or not model_name.strip() or len(model_name) > 128:
                    raise ValueError("model must be a non-empty string of at most 128 characters")
                trials = payload.get("trials", 5)
                if type(trials) is not int or not 1 <= trials <= 100:
                    raise ValueError("trials must be an integer between 1 and 100")
                endpoint = payload.get("base_url", base_url)
                if endpoint is not None:
                    if not isinstance(endpoint, str) or len(endpoint) > 512:
                        raise ValueError("base_url must be a string of at most 512 characters")
                    parsed = urlsplit(endpoint)
                    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
                        raise ValueError("base_url must be an HTTP(S) URL without embedded credentials")
                controller.start(provider_name, model_name.strip(), trials, endpoint, timeout)
                self._send_json(202, {"status": "started"})
            except RuntimeError as exc:
                self._send_json(409, {"error": str(exc)})
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._send_json(400, {"error": str(exc)})

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Dashboard: http://127.0.0.1:{port} (loopback only; artifacts in {artifact_dir})", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
