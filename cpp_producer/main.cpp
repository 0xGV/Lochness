#include "ETWWorker.h"
#include <iostream>
#include <string>



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
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024 * 1024,
      1024 * 1024, 0, &sa); // Increased buffer size for metadata

  if (hPipe == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    cerr << "CRITICAL: Failed to create control pipe (Error: " << err << ")"
         << endl;
    return;
  }
  cout << ">>> Control interface ready at \\\\.\\pipe\\etw_control" << endl;

  while (true) {
    bool connected = ConnectNamedPipe(hPipe, NULL)
                         ? true
                         : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (connected) {
      char buffer[4096]; // Increased read buffer
      DWORD bytesRead;
      if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        string cmd(buffer);
        cout << "[DEBUG] Received Control Command: " << cmd
             << endl; // Debug Log

        // Simple parsing logic (Parsing manually to avoid new deps)
        // Expected commands:
        // 1. {"Action":"Enable", "Provider":"{GUID}"}
        // 2. {"Action":"Disable", "Provider":"{GUID}"}
        // 3. {"Action":"GetMetadata", "Provider":"{GUID}"}
        // 4. {"Action":"SetFilter", "Provider":"{GUID}", "EventIds":[1,2,3]}

        string response = "ACK";
        bool enable = (cmd.find("Enable") != string::npos ||
                       cmd.find("enable") != string::npos);
        bool disable = (cmd.find("Disable") != string::npos ||
                        cmd.find("disable") != string::npos);
        bool getMeta = (cmd.find("GetMetadata") != string::npos);
        bool setFilter = (cmd.find("SetFilter") != string::npos);

        // Extract GUID
        string guid;
        size_t pPos = cmd.find("Provider");
        if (pPos == string::npos)
          pPos = cmd.find("provider");

        if (pPos != string::npos) {
          size_t valStart = cmd.find(":", pPos);
          if (valStart != string::npos) {
            size_t quoteStart = cmd.find("\"", valStart);
            if (quoteStart != string::npos) {
              size_t quoteEnd = cmd.find("\"", quoteStart + 1);
              if (quoteEnd != string::npos) {
                guid = cmd.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
              }
            }
          }
        }

        // Extract Name
        string name = "";
        size_t nPos = cmd.find("\"Name\""); // "Name": "..."
        if (nPos != string::npos) {
          size_t valStart = cmd.find(":", nPos);
          if (valStart != string::npos) {
            size_t quoteStart = cmd.find("\"", valStart);
            if (quoteStart != string::npos) {
              size_t quoteEnd = cmd.find("\"", quoteStart + 1);
              if (quoteEnd != string::npos) {
                name = cmd.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
              }
            }
          }
        }

        wstring wguid(guid.begin(), guid.end());
        wstring wname(name.begin(), name.end());

        if (!guid.empty()) {
          if (enable) {
            worker->EnableProvider(wguid);
          } else if (disable) {
            worker->DisableProvider(wguid);
          } else if (getMeta) {
            std::cout << "Getting metadata for " << guid << " (" << name << ")"
                      << std::endl;
            wstring wJson = worker->GetProviderMetadata(wguid, wname);
            // Convert wide back to string for pipe response
            int len = WideCharToMultiByte(CP_UTF8, 0, wJson.c_str(), -1, NULL,
                                          0, NULL, NULL);
            if (len > 0) {
              response.resize(len - 1); // ex. null
              WideCharToMultiByte(CP_UTF8, 0, wJson.c_str(), -1, &response[0],
                                  len, NULL, NULL);
            } else {
              response = "[]";
            }
          } else if (setFilter) {
            // Parse Event IDs array: "EventIds":[1, 2, 3]
            vector<unsigned short> ids;
            size_t idsPos = cmd.find("EventIds");
            if (idsPos != string::npos) {
              size_t arrayStart = cmd.find("[", idsPos);
              size_t arrayEnd = cmd.find("]", idsPos);
              if (arrayStart != string::npos && arrayEnd != string::npos) {
                string arrStr =
                    cmd.substr(arrayStart + 1, arrayEnd - arrayStart - 1);
                size_t start = 0, end = 0;
                while ((end = arrStr.find(",", start)) != string::npos) {
                  try {
                    ids.push_back((unsigned short)stoi(
                        arrStr.substr(start, end - start)));
                  } catch (...) {
                  }
                  start = end + 1;
                }
                try {
                  ids.push_back((unsigned short)stoi(arrStr.substr(start)));
                } catch (...) {
                }
              }
            }
            worker->SetProviderFilter(wguid, ids);
          }
        } else {
          // Deep Inspection Commands (No GUID)
          // Parse "Pid":1234
          uint32_t pid = 0;
          size_t pidPos = cmd.find("\"pid\"");
          if (pidPos == string::npos)
            pidPos = cmd.find("\"Pid\"");

          if (pidPos != string::npos) {
            size_t valStart = cmd.find(":", pidPos);
            if (valStart != string::npos) {
              // find digits
              // Skip whitespace/quotes/etc? JSON usually : 1234
              size_t digitStart = valStart + 1;
              while (digitStart < cmd.length() && !isdigit(cmd[digitStart]))
                digitStart++;

              if (digitStart < cmd.length()) {
                size_t digitEnd = digitStart;
                while (digitEnd < cmd.length() && isdigit(cmd[digitEnd]))
                  digitEnd++;
                try {
                  pid = (uint32_t)stoi(
                      cmd.substr(digitStart, digitEnd - digitStart));
                } catch (...) {
                }
              }
            }
          }

          if (pid > 0 || cmd.find("ListProcesses") != string::npos) {
            cout << "[DEBUG] Executing Inspection Command" << endl;
            wstring wJson = L"";
            if (cmd.find("GetProcessAncestry") != string::npos) {
              wJson = worker->GetProcessAncestry(pid);
            } else if (cmd.find("GetProcessResources") != string::npos) {
              wJson = worker->GetProcessResources(pid);
            } else if (cmd.find("GetNetworkConnections") != string::npos) {
              wJson = worker->GetNetworkConnections(pid);
            } else if (cmd.find("ScanProcessMemory") != string::npos) {
              wJson = worker->ScanProcessMemory(pid);
            } else if (cmd.find("GetProcessThreads") != string::npos) {
              wJson = worker->GetProcessThreads(pid);
            } else if (cmd.find("GetProcessDetails") != string::npos) {
              wJson = worker->GetProcessDetails(pid);
            } else if (cmd.find("ListProcesses") != string::npos) {
              wJson = worker->ListProcesses();
            } else if (cmd.find("GetProcessStrings") != string::npos) {
              wJson = worker->GetProcessStrings(pid);
            }

            if (!wJson.empty()) {
              int len = WideCharToMultiByte(CP_UTF8, 0, wJson.c_str(), -1, NULL,
                                            0, NULL, NULL);
              if (len > 0) {
                response.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, wJson.c_str(), -1, &response[0],
                                    len, NULL, NULL);
              }
            } else {
              // Ensure we don't return ACK if json was empty but command
              // valid-ish
              response = "{}";
            }
          }
        }

        DWORD written;
        WriteFile(hPipe, response.c_str(), (DWORD)response.length(), &written,
                  NULL);
        FlushFileBuffers(
            hPipe); // Ensure client receives data before disconnect
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
