#include "ETWWorker.h"
#include <iostream>
#include <string>

// Wait, no external deps for Go. For C++, JSON parsing is painful without libs.
// User didn't specify no deps for C++.
// But I don't have nlohmann json installed.
// Basic simple string parsing for control commands.
// Command: {"Action":"Enable", "Provider":"GUID"}
// I'll parse it manually.

using namespace std;

void ControlLoop(ETWWorker *worker) {
  // Create permissive security descriptor for the pipe
  SECURITY_DESCRIPTOR sd;
  InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
  SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = &sd;
  sa.bInheritHandle = FALSE;

  // Create Named Pipe Server for Control
  HANDLE hPipe = CreateNamedPipeW(
      L"\\\\.\\pipe\\etw_control", PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, &sa);

  if (hPipe == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    cerr << "CRITICAL: Failed to create control pipe (Error: " << err << ")"
         << endl;
    return;
  }
  cout << ">>> Control interface ready at \\\\.\\pipe\\etw_control" << endl;

  while (true) {
    if (ConnectNamedPipe(hPipe, NULL) != FALSE) {
      char buffer[1024];
      DWORD bytesRead;
      if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        string cmd(buffer);

        // Flexible parsing for "Action" and "Provider"
        bool enable = (cmd.find("Enable") != string::npos ||
                       cmd.find("enable") != string::npos);

        // Find GUID - look for any string that looks like a GUID after
        // "provider"
        size_t pPos = cmd.find("provider");
        if (pPos != string::npos) {
          size_t valStart = cmd.find(":", pPos);
          if (valStart != string::npos) {
            size_t quoteStart = cmd.find("\"", valStart);
            if (quoteStart != string::npos) {
              size_t quoteEnd = cmd.find("\"", quoteStart + 1);
              if (quoteEnd != string::npos) {
                string guid =
                    cmd.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                wstring wguid(guid.begin(), guid.end());

                if (enable) {
                  worker->EnableProvider(wguid);
                } else {
                  worker->DisableProvider(wguid);
                }
              }
            }
          }
        }

        DWORD written;
        WriteFile(hPipe, "ACK", 3, &written, NULL);
      }
      DisconnectNamedPipe(hPipe);
    } else {
      Sleep(100);
    }
  }
}

int main() {
  ETWWorker worker;

  cout << "Lochness Agent v1.1.0 starting..." << endl;

  // Connect to Relay with infinite retry
  cout << "Waiting for Go Relay on \\\\.\\pipe\\etw_stream..." << endl;
  while (!worker.ConnectPipe(L"\\\\.\\pipe\\etw_stream")) {
    Sleep(2000);
  }

  // Start Control Thread
  thread controlThread(ControlLoop, &worker);
  controlThread.detach();

  // Start Trace
  cout << "Starting ETW Trace Session..." << endl;
  worker.Start(L"LochnessSession");

  cout << "\n[SUCCESS] Agent is active and streaming." << endl;
  cout << "Press ENTER to shut down gracefully." << endl;
  cin.get();

  worker.Stop();
  return 0;
}
