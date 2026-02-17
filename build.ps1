Write-Host "Building Lochness Telemetry System..." -ForegroundColor Cyan

# 1. Build Go Relay
Write-Host "Building Go Relay..." -ForegroundColor Yellow
Push-Location .\go_relay
try {
    go build -o go_relay.exe
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Go Relay Built Successfully: .\go_relay\go_relay.exe" -ForegroundColor Green
    } else {
        Write-Host "Go Relay Build Failed!" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}


Write-Host "Build Complete!" -ForegroundColor Cyan
