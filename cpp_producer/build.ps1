$compiler = "cl.exe"
if (-not (Get-Command $compiler -ErrorAction SilentlyContinue)) {
    Write-Host "MSVC compiler (cl.exe) not found." -ForegroundColor Red
    Write-Host "Please run this script from the 'x64 Native Tools Command Prompt for VS 20XX'."
    exit 1
}

Write-Host "Building C++ Producer..."
& $compiler /EHsc /O2 /std:c++17 main.cpp ETWWorker.cpp /Fe:lochness_agent.exe /link tdh.lib advapi32.lib rpcrt4.lib wevtapi.lib

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build Successful: lochness_agent.exe" -ForegroundColor Green
} else {
    Write-Host "Build Failed" -ForegroundColor Red
}
