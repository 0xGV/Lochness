#include <algorithm>
#include <iostream>
#include <string>
#include <vector>


using namespace std;

void Parse(string cmd) {
  cout << "Parsing: " << cmd << endl;

  string guid;
  size_t pPos = cmd.find("Provider");
  if (pPos == string::npos)
    pPos = cmd.find("provider");

  if (pPos != string::npos) {
    // ... (guid extraction logic)
    cout << "Found Provider" << endl;
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
            pid = (uint32_t)stoi(cmd.substr(digitStart, digitEnd - digitStart));
          } catch (...) {
          }
        }
      }
    }
    cout << "Parsed PID: " << pid << endl;
  }
}

int main() {
  Parse("{\"Action\":\"GetProcessThreads\",\"Pid\":1234}");
  Parse("{\"Pid\":5678, \"Action\":\"GetProcessThreads\"}");
  Parse("{\"Action\":\"GetProcessThreads\",\"Pid\": 9999}"); // space
  return 0;
}
