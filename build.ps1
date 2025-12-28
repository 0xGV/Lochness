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

# 2. Build C++ Producer
Write-Host "Building C++ Producer..." -ForegroundColor Yellow
# Check for CL (MSVC)
if (Get-Command "cl.exe" -ErrorAction SilentlyContinue) {
    Push-Location .\cpp_producer
    try {
        # compile with MSVC
        # /EHsc for exception handling, /Fe for output alias, link libraries
        cl.exe /nologo /EHsc main.cpp ETWWorker.cpp /Fe:lochness_agent.exe /link tdh.lib advapi32.lib rpcrt4.lib user32.lib uuid.lib
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "C++ Producer Built Successfully: .\cpp_producer\lochness_agent.exe" -ForegroundColor Green
            # Clean up obj files
            Remove-Item *.obj -ErrorAction SilentlyContinue
        } else {
            Write-Host "C++ Producer Build Failed!" -ForegroundColor Red
            exit 1
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "MSVC compiler (cl.exe) not found in PATH." -ForegroundColor Red
    Write-Host "Please run this script from the 'x64 Native Tools Command Prompt for VS 20XX'." -ForegroundColor Gray
    Write-Host "Alternatively, check if MinGW (g++) is available..." -ForegroundColor Gray
    
    if (Get-Command "g++" -ErrorAction SilentlyContinue) {
        Write-Host "Found g++, attempting build..." -ForegroundColor Yellow
        Push-Location .\cpp_producer
        try {
            g++ -o lochness_agent.exe main.cpp ETWWorker.cpp -ltdh -ladvapi32 -lrpcrt4
             if ($LASTEXITCODE -eq 0) {
                Write-Host "C++ Producer Built Successfully (MinGW): .\cpp_producer\lochness_agent.exe" -ForegroundColor Green
            } else {
                Write-Host "C++ Producer Build Failed (MinGW)!" -ForegroundColor Red
            }
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "No suitable C++ compiler found (cl.exe or g++)." -ForegroundColor Red
        exit 1
    }
}

Write-Host "Build Complete!" -ForegroundColor Cyan
