# SIH26145 Windows host setup — detectors dev, dashboard, local LLM
# Run from the sih26145 folder:  powershell -ExecutionPolicy Bypass -File setup_windows.ps1

$ErrorActionPreference = "Continue"
Write-Host "== [1/4] Python packages ==" -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Warning "pip failed - Python 3.14 wheels may lag for scipy/pandas."
    Write-Host "Fix: create a 3.12 venv and rerun inside it:"
    Write-Host "  py -3.12 -m venv .venv ; .\.venv\Scripts\Activate.ps1 ; python -m pip install -r requirements.txt"
}

Write-Host "== [2/4] Sanity imports ==" -ForegroundColor Cyan
python -c "import scapy, fastapi, pydantic; print('core imports OK')"

Write-Host "== [3/4] Ollama service ==" -ForegroundColor Cyan
$ollamaUp = $false
try { $null = ollama list; if ($LASTEXITCODE -eq 0) { $ollamaUp = $true } } catch {}
if (-not $ollamaUp) {
    Write-Host "starting ollama serve (background)..."
    Start-Process -WindowStyle Hidden -FilePath "ollama" -ArgumentList "serve"
    Start-Sleep -Seconds 4
}
ollama pull llama3.2:3b
if ($LASTEXITCODE -eq 0) { Write-Host "model ready (CPU-friendly ~2GB)" -ForegroundColor Green }

Write-Host "== [4/4] Smoke test: schema + template briefing ==" -ForegroundColor Cyan
python -c "from alerts.schema import Alert, ThreatClass; from triage.templates import template_briefing; from datetime import datetime, timezone; a=Alert(timestamp=datetime.now(timezone.utc), flow_id='1.2.3.4:5->6.7.8.9:443#tcp', threat_class=ThreatClass.BEACONING, confidence_score=0.87, supporting_evidence=[{'feature':'iat_cv','value':0.12,'threshold':0.35}]); print('severity:', a.severity); print(template_briefing(a)[:120])"

Write-Host ""
Write-Host "Next: set up the Ubuntu VM per BUILD_GUIDE.md section 3, then run setup_ubuntu.sh inside it." -ForegroundColor Yellow
