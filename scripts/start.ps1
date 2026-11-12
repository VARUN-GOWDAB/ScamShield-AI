# Start the ScamShield API and the Streamlit workstation on this machine.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Test-PortOpen([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect("127.0.0.1", $Port)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

foreach ($port in 8000, 8501) {
    if (Test-PortOpen $port) {
        Write-Error "Port $port is already in use. Stop the existing process, then run this script again."
        exit 1
    }
}

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    py -3 -m venv (Join-Path $Root ".venv")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $Python -c "import fastapi, streamlit, reportlab, openai"
if ($LASTEXITCODE -ne 0) {
    & $Python -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $Python -m pip install -r (Join-Path $Root "requirements.txt")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$EnvFile = Join-Path $Root ".env"
if (-not (Test-Path $EnvFile)) {
    Copy-Item (Join-Path $Root ".env.example") $EnvFile
}

Start-Process -FilePath $Python -ArgumentList @(
    "-m", "uvicorn", "backend.app.main:app",
    "--host", "127.0.0.1", "--port", "8000"
) -WorkingDirectory $Root

Start-Process -FilePath $Python -ArgumentList @(
    "-m", "streamlit", "run", "frontend/app.py",
    "--server.address", "127.0.0.1", "--server.port", "8501"
) -WorkingDirectory $Root

Write-Host "API docs: http://127.0.0.1:8000/docs"
Write-Host "Workstation: http://127.0.0.1:8501"
