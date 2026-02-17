
// 7. Process Strings
std::wstring ETWWorker::GetProcessStrings(uint32_t pid) {
  json result;
  result["pid"] = pid;
  result["strings"] = json::array();

  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess) {
    result["error"] = "Access Denied";
    return ToWide(result.dump());
  }

  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);

  LPVOID addr = sysInfo.lpMinimumApplicationAddress;
  std::vector<std::string> foundStrings;
  const size_t MAX_STRINGS = 2000;
  const size_t MIN_LEN = 4;

  while (addr < sysInfo.lpMaximumApplicationAddress) {
    if (foundStrings.size() >= MAX_STRINGS)
      break;

    MEMORY_BASIC_INFORMATION memInfo;
    if (VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == 0)
      break;

    // Scan COMMIT and Read-Compatible regions
    if (memInfo.State == MEM_COMMIT &&
        (memInfo.Protect == PAGE_READWRITE ||
         memInfo.Protect == PAGE_READONLY ||
         memInfo.Protect == PAGE_EXECUTE_READ ||
         memInfo.Protect == PAGE_EXECUTE_READWRITE)) {

      // Cap read size per region
      SIZE_T readSize = memInfo.RegionSize;
      if (readSize > 1024 * 1024)
        readSize = 1024 * 1024; // 1MB chunks

      std::vector<BYTE> buffer(readSize);
      SIZE_T bytesRead = 0;
      if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(),
                            readSize, &bytesRead)) {
        // ASCII Scan
        std::string current;
        for (size_t i = 0; i < bytesRead; i++) {
          char c = (char)buffer[i];
          if (c >= 32 && c <= 126) {
            current += c;
          } else {
            if (current.length() >= MIN_LEN) {
              foundStrings.push_back(current);
              if (foundStrings.size() >= MAX_STRINGS)
                break;
            }
            current = "";
          }
        }
        if (current.length() >= MIN_LEN && foundStrings.size() < MAX_STRINGS)
          foundStrings.push_back(current);

        // Unicode Scan (Basic) -> skip for now to save complexity/perf or do
        // simple loop? Let's stick to ASCII for V1 to be fast.
      }
    }
    addr = (LPBYTE)memInfo.BaseAddress + memInfo.RegionSize;
  }

  result["strings"] = foundStrings;
  result["count"] = foundStrings.size();

  CloseHandle(hProcess);
  return ToWide(result.dump());
}
