#define INITGUID
#include "ETWWorker.h"
#include <evntprov.h>
#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")
#include <iostream>
#include <map>
#include <strsafe.h>

// Include nlohmann/json definition via header, but we need the alias here
using json = nlohmann::json;

#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <tlhelp32.h>

ETWWorker::ETWWorker()
    : m_sessionHandle(0), m_traceHandle(INVALID_PROCESSTRACE_HANDLE),
      m_running(false), m_hPipe(INVALID_HANDLE_VALUE), m_droppedEvents(0) {}

ETWWorker::~ETWWorker() {
  Stop();
  if (m_hPipe != INVALID_HANDLE_VALUE) {
    CloseHandle(m_hPipe);
  }
}

std::string ToUtf8(const std::wstring &wstr) {
  if (wstr.empty())
    return "";
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(),
                                        NULL, 0, NULL, NULL);
  std::string strTo(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0],
                      size_needed, NULL, NULL);
  return strTo;
}

// Helper to get process name from PID
std::string GetProcessName(uint32_t pid) {
  if (pid == 0)
    return "System Idle Process";
  if (pid == 4)
    return "System";

  std::string processName = "Unknown";
  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (hProcess) {
    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
      char szProcessName[MAX_PATH];
      if (GetModuleBaseNameA(hProcess, hMod, szProcessName,
                             sizeof(szProcessName) / sizeof(char))) {
        processName = szProcessName;
      }
    }
    // Fallback if EnumProcessModules fails (e.g. some system processes)
    if (processName == "Unknown") {
      char szProcessName[MAX_PATH];
      DWORD length = MAX_PATH;
      if (QueryFullProcessImageNameA(hProcess, 0, szProcessName, &length)) {
        std::string fullPath = szProcessName;
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
          processName = fullPath.substr(lastSlash + 1);
        } else {
          processName = fullPath;
        }
      }
    }
    CloseHandle(hProcess);
  }
  return processName;
}

// Helper to get parent PID from PID
uint32_t GetParentPid(uint32_t pid) {
  if (pid == 0 || pid == 4)
    return 0;

  uint32_t parentPid = 0;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32W pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32W);

  if (Process32FirstW(hSnapshot, &pe32)) {
    do {
      if (pe32.th32ProcessID == pid) {
        parentPid = pe32.th32ParentProcessID;
        break;
      }
    } while (Process32NextW(hSnapshot, &pe32));
  }

  CloseHandle(hSnapshot);
  return parentPid;
}

// Helper to get process owner (Domain\User)
std::string GetProcessOwner(uint32_t pid) {
  if (pid == 0)
    return "System Idle Process";
  if (pid == 4)
    return "NT AUTHORITY\\SYSTEM";

  std::string owner = "Unknown";
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!hProcess)
    return owner;

  HANDLE hToken = NULL;
  if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

    if (dwSize > 0) {
      std::vector<BYTE> buffer(dwSize);
      PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer.data();

      if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        WCHAR szName[256] = {0};
        WCHAR szDomain[256] = {0};
        DWORD dwNameSize = 256;
        DWORD dwDomainSize = 256;
        SID_NAME_USE sidType;

        if (LookupAccountSidW(NULL, pTokenUser->User.Sid, szName, &dwNameSize,
                              szDomain, &dwDomainSize, &sidType)) {
          std::wstring wOwner =
              std::wstring(szDomain) + L"\\" + std::wstring(szName);
          owner = ToUtf8(wOwner);
        }
      }
    }
    CloseHandle(hToken);
  }
  CloseHandle(hProcess);
  return owner;
}

// Helper to convert UTF-8 std::string to Wide String
std::wstring ToWide(const std::string &str) {
  if (str.empty())
    return L"";
  int size_needed =
      MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
  std::wstring wstrTo(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0],
                      size_needed);
  return wstrTo;
}

bool ETWWorker::ConnectPipe(const std::wstring &pipeName) {
  m_hPipe = CreateFileW(pipeName.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);

  if (m_hPipe != INVALID_HANDLE_VALUE) {
    std::wcout << L"Successfully connected to relay pipe: " << pipeName
               << std::endl;
    return true;
  }
  return false;
}

void ETWWorker::Start(const std::wstring &sessionName) {
  std::wcout << L"Starting ETWWorker for session: " << sessionName << std::endl;
  m_sessionName = sessionName;
  m_running = true;

  // Enable Kernel Process Provider for Image Load
  EnableProvider(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}");
  // StackWalk provider not available in standard user session, disabling for
  // now. EnableProvider(L"{DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3}");

  // Start Background Workers (4 threads)
  for (int i = 0; i < 4; i++) {
    m_workerThreads.emplace_back(&ETWWorker::WorkerLoop, this);
  }

  m_traceThread = std::thread(&ETWWorker::TraceLoop, this);
}

void ETWWorker::Stop() {
  m_running = false;
  if (m_sessionHandle) {
    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) +
                       (m_sessionName.length() + 1) * sizeof(wchar_t);
    EVENT_TRACE_PROPERTIES *pProps =
        (EVENT_TRACE_PROPERTIES *)malloc(propsSize);
    ZeroMemory(pProps, propsSize);
    pProps->Wnode.BufferSize = (ULONG)propsSize;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = ControlTraceW(m_sessionHandle, m_sessionName.c_str(), pProps,
                                 EVENT_TRACE_CONTROL_STOP);
    if (status == ERROR_SUCCESS) {
      std::wcout << L"Successfully stopped ETW session: " << m_sessionName
                 << std::endl;
    } else {
      std::wcerr << L"Failed to stop ETW session: " << m_sessionName
                 << L" (Status: " << status << L")" << std::endl;
    }
    free(pProps);
  }
  if (m_traceThread.joinable()) {
    m_traceThread.join();
  }

  // Stop Workers
  m_eventQueue.NotifyAll();
  for (auto &t : m_workerThreads) {
    if (t.joinable())
      t.join();
  }
  m_workerThreads.clear();
}

void ETWWorker::EnableProvider(const std::wstring &providerGuid) {
  GUID guid;
  if (UuidFromStringW((RPC_WSTR)providerGuid.c_str(), &guid) == RPC_S_OK) {
    ULONG status = EnableTraceEx2(m_sessionHandle, &guid,
                                  EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
    if (status == ERROR_SUCCESS) {
      std::wcout << L"Successfully enabled provider: " << providerGuid
                 << std::endl;
    } else {
      std::wcerr << L"Failed to enable provider: " << providerGuid
                 << L" (Status: " << status << L")" << std::endl;
    }
  } else {
    std::wcerr << L"Invalid Provider GUID string: " << providerGuid
               << std::endl;
  }
}

void ETWWorker::DisableProvider(const std::wstring &providerGuid) {
  GUID guid;
  if (UuidFromStringW((RPC_WSTR)providerGuid.c_str(), &guid) == RPC_S_OK) {
    ULONG status =
        EnableTraceEx2(m_sessionHandle, &guid,
                       EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, NULL);
    if (status == ERROR_SUCCESS) {
      std::wcout << L"Successfully disabled provider: " << providerGuid
                 << std::endl;
    } else {
      std::wcerr << L"Failed to disable provider: " << providerGuid
                 << L" (Status: " << status << L")" << std::endl;
    }
  } else {
    std::wcerr << L"Invalid Provider GUID string: " << providerGuid
               << std::endl;
  }
}

void ETWWorker::TraceLoop() {
  size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) +
                     (m_sessionName.length() + 1) * sizeof(wchar_t) + 1024;
  EVENT_TRACE_PROPERTIES *pProps = (EVENT_TRACE_PROPERTIES *)malloc(propsSize);
  ZeroMemory(pProps, propsSize);

  pProps->Wnode.BufferSize = (ULONG)propsSize;
  pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  pProps->Wnode.ClientContext = 1; // QPC
  pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  ControlTraceW(0, m_sessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);

  ULONG status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), pProps);
  if (status != ERROR_SUCCESS) {
    std::wcerr << L"StartTraceW failed: " << status << std::endl;
    free(pProps);
    return;
  }
  std::wcout << L"Successfully started trace session: " << m_sessionName
             << std::endl;

  free(pProps);

  EVENT_TRACE_LOGFILEW logFile;
  ZeroMemory(&logFile, sizeof(logFile));
  logFile.LoggerName = (LPWSTR)m_sessionName.c_str();
  logFile.ProcessTraceMode =
      PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  logFile.EventRecordCallback =
      (PEVENT_RECORD_CALLBACK)ETWWorker::EventCallback;
  logFile.Context = this;

  m_traceHandle = OpenTraceW(&logFile);
  if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
    std::wcerr << L"OpenTraceW failed: " << GetLastError() << std::endl;
  } else {
    std::wcout << L"Trace opened for consumption, processing events..."
               << std::endl;
    ULONG pStatus = ProcessTrace(&m_traceHandle, 1, 0, 0);
    std::wcout << L"ProcessTrace finished (Status: " << pStatus << L")"
               << std::endl;
  }

  CloseTrace(m_traceHandle);
}

void WINAPI ETWWorker::EventCallback(PEVENT_RECORD pEvent) {
  if (pEvent == NULL || pEvent->UserContext == NULL)
    return;

  ETWWorker *pWorker = static_cast<ETWWorker *>(pEvent->UserContext);
  pWorker->ProcessEvent(pEvent);
}

std::wstring ETWWorker::GetProviderMetadata(const std::wstring &providerGuid,
                                            const std::wstring &providerName) {
  EVT_HANDLE hMetadata = NULL;
  if (!providerName.empty()) {
    hMetadata =
        EvtOpenPublisherMetadata(NULL, providerName.c_str(), NULL, 0, 0);
  }

  std::wstring cleanGuid = providerGuid;
  if (!cleanGuid.empty() && cleanGuid.front() == L'{' &&
      cleanGuid.back() == L'}') {
    cleanGuid = cleanGuid.substr(1, cleanGuid.size() - 2);
  }

  if (!hMetadata) {
    hMetadata = EvtOpenPublisherMetadata(NULL, cleanGuid.c_str(), NULL, 0, 0);
  }

  if (hMetadata) {
    std::wcout << L"Successfully opened metadata for provider: "
               << (providerName.empty() ? providerGuid : providerName)
               << std::endl;
  }

  if (!hMetadata) {
    std::wcerr << L"Failed to open publisher metadata for: "
               << cleanGuid.c_str() << L" Error: " << GetLastError()
               << std::endl;

    json jArray = json::array();
    std::lock_guard<std::mutex> lock(m_stateMutex);

    GUID targetGuid;
    if (UuidFromStringW((RPC_WSTR)providerGuid.c_str(), &targetGuid) ==
        RPC_S_OK) {
      for (const auto &pair : m_schemaCache) {
        if (IsEqualGUID(pair.first.ProviderId, targetGuid)) {
          json jEvt;
          jEvt["Id"] = pair.first.Id;
          jEvt["Description"] = "Observed Event";
          jArray.push_back(jEvt);
        }
      }
    }
    return ToWide(jArray.dump());
  }

  std::map<UINT64, std::wstring> keywordMap;
  std::map<UINT32, std::wstring> opcodeMap;
  std::map<UINT32, std::wstring> taskMap;

  // Helpers to load metadata maps
  if (hMetadata) {
    auto LoadMap = [&](EVT_PUBLISHER_METADATA_PROPERTY_ID arrayId,
                       EVT_PUBLISHER_METADATA_PROPERTY_ID valId,
                       EVT_PUBLISHER_METADATA_PROPERTY_ID nameId) {
      std::map<UINT64, std::wstring> res;
      EVT_HANDLE hArray = NULL;
      DWORD bufUsed = 0;
      if (!EvtGetPublisherMetadataProperty(hMetadata, arrayId, 0, 0, NULL,
                                           &bufUsed) &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buf(bufUsed);
        if (EvtGetPublisherMetadataProperty(hMetadata, arrayId, 0, bufUsed,
                                            (PEVT_VARIANT)buf.data(),
                                            &bufUsed)) {
          PEVT_VARIANT pVal = (PEVT_VARIANT)buf.data();
          if (pVal->Type == EvtVarTypeEvtHandle)
            hArray = pVal->EvtHandleVal;
        }
      }
      if (hArray) {
        DWORD size = 0;
        if (EvtGetObjectArraySize(hArray, &size)) {
          for (DWORD i = 0; i < size; i++) {
            UINT64 val = 0;
            std::wstring name;
            DWORD pUsed = 0;
            // Value
            if (!EvtGetObjectArrayProperty(hArray, i, valId, 0, 0, NULL,
                                           &pUsed) &&
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
              std::vector<BYTE> vBuf(pUsed);
              if (EvtGetObjectArrayProperty(hArray, i, valId, 0, pUsed,
                                            (PEVT_VARIANT)vBuf.data(),
                                            &pUsed)) {
                PEVT_VARIANT p = (PEVT_VARIANT)vBuf.data();
                if (p->Type == EvtVarTypeUInt32)
                  val = p->UInt32Val;
                else if (p->Type == EvtVarTypeUInt64)
                  val = p->UInt64Val;
              }
            }
            // Name
            pUsed = 0;
            if (!EvtGetObjectArrayProperty(hArray, i, nameId, 0, 0, NULL,
                                           &pUsed) &&
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
              std::vector<BYTE> nBuf(pUsed);
              if (EvtGetObjectArrayProperty(hArray, i, nameId, 0, pUsed,
                                            (PEVT_VARIANT)nBuf.data(),
                                            &pUsed)) {
                PEVT_VARIANT p = (PEVT_VARIANT)nBuf.data();
                if (p->Type == EvtVarTypeString)
                  name = p->StringVal;
              }
            }
            if (!name.empty())
              res[val] = name;
          }
        }
        EvtClose(hArray);
      }
      return res;
    };

    std::map<UINT64, std::wstring> kRaw =
        LoadMap(EvtPublisherMetadataKeywords, EvtPublisherMetadataKeywordValue,
                EvtPublisherMetadataKeywordName);
    keywordMap = kRaw;

    std::map<UINT64, std::wstring> oRaw =
        LoadMap(EvtPublisherMetadataOpcodes, EvtPublisherMetadataOpcodeValue,
                EvtPublisherMetadataOpcodeName);
    for (auto &p : oRaw)
      opcodeMap[(UINT32)p.first] = p.second;

    std::map<UINT64, std::wstring> tRaw =
        LoadMap(EvtPublisherMetadataTasks, EvtPublisherMetadataTaskValue,
                EvtPublisherMetadataTaskName);
    for (auto &p : tRaw)
      taskMap[(UINT32)p.first] = p.second;
  }

  json jArray = json::array();
  EVT_HANDLE hEnum = EvtOpenEventMetadataEnum(hMetadata, 0);
  if (hEnum) {
    EVT_HANDLE hEvent = NULL;
    while ((hEvent = EvtNextEventMetadata(hEnum, 0)) != NULL) {

      UINT64 eventId = 0;
      DWORD bufUsed = 0;
      if (!EvtGetEventMetadataProperty(hEvent, EventMetadataEventID, 0, 0, NULL,
                                       &bufUsed) &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> valBuf(bufUsed);
        if (EvtGetEventMetadataProperty(hEvent, EventMetadataEventID, 0,
                                        bufUsed, (PEVT_VARIANT)valBuf.data(),
                                        &bufUsed)) {
          PEVT_VARIANT pVal = (PEVT_VARIANT)valBuf.data();
          if (pVal->Type == EvtVarTypeUInt32 ||
              pVal->Type == EvtVarTypeUInt64) {
            eventId = (pVal->Type == EvtVarTypeUInt32) ? pVal->UInt32Val
                                                       : pVal->UInt64Val;
          }
        }
      }

      // Helper to get UInt32 property
      auto GetUInt32Prop =
          [&](EVT_EVENT_METADATA_PROPERTY_ID propId) -> UINT32 {
        UINT32 val = 0;
        DWORD bufUsed = 0;
        if (!EvtGetEventMetadataProperty(hEvent, propId, 0, 0, NULL,
                                         &bufUsed) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
          std::vector<BYTE> buf(bufUsed);
          if (EvtGetEventMetadataProperty(hEvent, propId, 0, bufUsed,
                                          (PEVT_VARIANT)buf.data(), &bufUsed)) {
            PEVT_VARIANT pVal = (PEVT_VARIANT)buf.data();
            if (pVal->Type == EvtVarTypeUInt32)
              val = pVal->UInt32Val;
          }
        }
        return val;
      };

      auto GetUInt64Prop =
          [&](EVT_EVENT_METADATA_PROPERTY_ID propId) -> UINT64 {
        UINT64 val = 0;
        DWORD bufUsed = 0;
        if (!EvtGetEventMetadataProperty(hEvent, propId, 0, 0, NULL,
                                         &bufUsed) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
          std::vector<BYTE> buf(bufUsed);
          if (EvtGetEventMetadataProperty(hEvent, propId, 0, bufUsed,
                                          (PEVT_VARIANT)buf.data(), &bufUsed)) {
            PEVT_VARIANT pVal = (PEVT_VARIANT)buf.data();
            if (pVal->Type == EvtVarTypeUInt64)
              val = pVal->UInt64Val;
            else if (pVal->Type == EvtVarTypeUInt32)
              val = pVal->UInt32Val;
          }
        }
        return val;
      };

      UINT32 version = GetUInt32Prop(EventMetadataEventVersion);
      UINT32 levelId = GetUInt32Prop(EventMetadataEventLevel);
      UINT32 opcodeId = GetUInt32Prop(EventMetadataEventOpcode);
      UINT32 taskId = GetUInt32Prop(EventMetadataEventTask);
      UINT64 keywordMask = GetUInt64Prop(EventMetadataEventKeyword);

      // Helper lambda for format message
      auto GetFormatMessage = [&](DWORD flag) -> std::wstring {
        std::wstring result = L"";
        DWORD dwBufferSize = 0;
        DWORD dwBufferUsed = 0;
        if (!EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, flag, 0, NULL,
                              &dwBufferSize)) {
          if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<wchar_t> buf(dwBufferSize);
            if (EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, flag,
                                 dwBufferSize, buf.data(), &dwBufferUsed)) {
              result = buf.data();
            }
          }
        }
        return result;
      };

      std::wstring description = GetFormatMessage(EvtFormatMessageEvent);
      std::wstring levelStr = GetFormatMessage(EvtFormatMessageLevel);
      std::wstring opcodeStr = GetFormatMessage(EvtFormatMessageOpcode);
      std::wstring taskStr = GetFormatMessage(EvtFormatMessageTask);
      std::wstring keywordRaw = GetFormatMessage(EvtFormatMessageKeyword);
      std::wstring keyword = CleanKeyword(keywordRaw);

      // Fallback Lookups
      if (opcodeStr.empty() && opcodeMap.count(opcodeId))
        opcodeStr = opcodeMap[opcodeId];
      if (taskStr.empty() && taskMap.count(taskId))
        taskStr = taskMap[taskId];

      if (keyword.empty() && keywordMask != 0) {
        for (auto const &pair : keywordMap) {
          UINT64 mask = pair.first;
          const std::wstring &name = pair.second;
          if ((keywordMask & mask) == mask && mask != 0) {
            if (!keyword.empty())
              keyword += L" | ";
            keyword += name;
          }
        }
      }

      json jEvt;
      jEvt["Id"] = eventId;
      jEvt["Version"] = version;
      jEvt["Level"] = levelId;
      jEvt["LevelStr"] = ToUtf8(levelStr);
      jEvt["Opcode"] = opcodeId;
      jEvt["OpcodeStr"] = ToUtf8(opcodeStr);
      jEvt["Task"] = taskId;
      jEvt["TaskStr"] = ToUtf8(taskStr);
      jEvt["Keyword"] = ToUtf8(keyword);
      jEvt["Description"] = ToUtf8(description);

      jArray.push_back(jEvt);

      EvtClose(hEvent);
    }
    EvtClose(hEnum);
  }
  EvtClose(hMetadata);
  return ToWide(jArray.dump());
}

void ETWWorker::SetProviderFilter(const std::wstring &providerGuid,
                                  const std::vector<unsigned short> &eventIds) {
  GUID guid;
  if (UuidFromStringW((RPC_WSTR)providerGuid.c_str(), &guid) != RPC_S_OK) {
    std::wcerr << L"Invalid Provider GUID for filter: " << providerGuid
               << std::endl;
    return;
  }

  if (eventIds.empty()) {
    ULONG status = EnableTraceEx2(m_sessionHandle, &guid,
                                  EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
    if (status == ERROR_SUCCESS) {
      std::wcout << L"Cleared kernel filters for provider: " << providerGuid
                 << std::endl;
    } else {
      std::wcerr << L"Failed to clear filters: " << status << std::endl;
    }
    return;
  }

  size_t filterSize = offsetof(EVENT_FILTER_EVENT_ID, Events) +
                      eventIds.size() * sizeof(USHORT);

  std::vector<BYTE> buffer(filterSize);
  PEVENT_FILTER_EVENT_ID pFilter = (PEVENT_FILTER_EVENT_ID)buffer.data();

  pFilter->FilterIn = TRUE;
  pFilter->Reserved = 0;
  pFilter->Count = (USHORT)eventIds.size();
  for (size_t i = 0; i < eventIds.size(); ++i) {
    pFilter->Events[i] = eventIds[i];
  }

  EVENT_FILTER_DESCRIPTOR filterDesc;
  ZeroMemory(&filterDesc, sizeof(filterDesc));
  filterDesc.Ptr = (ULONGLONG)pFilter;
  filterDesc.Size = (ULONG)filterSize;
  filterDesc.Type = EVENT_FILTER_TYPE_EVENT_ID;

  ENABLE_TRACE_PARAMETERS params;
  ZeroMemory(&params, sizeof(params));
  params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
  params.EnableFilterDesc = &filterDesc;
  params.FilterDescCount = 1;

  ULONG status =
      EnableTraceEx2(m_sessionHandle, &guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                     TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);

  if (status == ERROR_SUCCESS) {
    std::wcout << L"Applied kernel filter (" << eventIds.size()
               << L" events) for: " << providerGuid << std::endl;
  } else {
    std::wcerr << L"Failed to apply kernel filter: " << status << std::endl;
  }
}

void ETWWorker::ProcessEvent(PEVENT_RECORD pEvent) {
  if (m_hPipe == INVALID_HANDLE_VALUE) {
    if (!ConnectPipe(L"\\\\.\\pipe\\etw_stream")) {
      return;
    }
  }

  if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid))
    return;

  std::lock_guard<std::mutex> lock(m_stateMutex);

  // 1. Define Cache Key
  EventKey key;
  key.ProviderId = pEvent->EventHeader.ProviderId;
  key.Id = pEvent->EventHeader.EventDescriptor.Id;
  key.Version = pEvent->EventHeader.EventDescriptor.Version;

  // 2. Check Cache
  auto it = m_schemaCache.find(key);
  if (it == m_schemaCache.end()) {
    // Cache Miss
    ULONG bufferSize = 0;
    ULONG status = TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);

    if (status == ERROR_INSUFFICIENT_BUFFER) {
      TRACE_EVENT_INFO *pInfo = (TRACE_EVENT_INFO *)malloc(bufferSize);
      if (pInfo) {
        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);
        if (status == ERROR_SUCCESS) {
          CachedEventSchema schema;

          // Extract Strings
          if (pInfo->KeywordsNameOffset)
            schema.KeywordStr = CleanKeyword(std::wstring(
                (LPWSTR)((PBYTE)pInfo + pInfo->KeywordsNameOffset)));

          if (pInfo->OpcodeNameOffset)
            schema.OpcodeStr =
                std::wstring((LPWSTR)((PBYTE)pInfo + pInfo->OpcodeNameOffset));

          if (pInfo->TaskNameOffset)
            schema.TaskStr =
                std::wstring((LPWSTR)((PBYTE)pInfo + pInfo->TaskNameOffset));

          std::vector<PropertyMetadata> props;

          for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            PropertyMetadata meta;
            EVENT_PROPERTY_INFO &propInfo = pInfo->EventPropertyInfoArray[i];

            if (propInfo.NameOffset != 0) {
              meta.Name =
                  std::wstring((LPWSTR)((PBYTE)pInfo + propInfo.NameOffset));
            } else {
              meta.Name = L"Field" + std::to_wstring(i);
            }

            meta.InType = propInfo.nonStructType.InType;
            meta.OutType = propInfo.nonStructType.OutType;

            if ((propInfo.Flags & PropertyParamLength) ||
                (propInfo.Flags & PropertyParamCount)) {
              meta.IsVariable = true;
              meta.Length = 0;
            } else {
              meta.Length = propInfo.length;
              meta.IsVariable = (meta.Length == 0);

              if (meta.InType == TDH_INTYPE_UNICODESTRING ||
                  meta.InType == TDH_INTYPE_ANSISTRING ||
                  meta.InType == TDH_INTYPE_SID) {
                meta.IsVariable = true;
              }
            }
            props.push_back(meta);
          }
          schema.Properties = props;
          m_schemaCache[key] = schema;
          it = m_schemaCache.find(key);
        }
        free(pInfo);
      }
    }
  }

  if (it == m_schemaCache.end()) {
    return;
  }

  // 3. Hot Path Parsing (JSON serialization used nlohmann::json)
  json jObj;

  PBYTE pData = (PBYTE)pEvent->UserData;
  PBYTE pEnd = pData + pEvent->UserDataLength;

  const auto &schema = it->second;
  const auto &props = schema.Properties;

  // Inject Metadata
  if (!schema.KeywordStr.empty())
    jObj["Keyword"] = ToUtf8(schema.KeywordStr);
  if (!schema.OpcodeStr.empty())
    jObj["OpcodeStr"] = ToUtf8(schema.OpcodeStr);
  if (!schema.TaskStr.empty())
    jObj["TaskStr"] = ToUtf8(schema.TaskStr);

  for (size_t i = 0; i < props.size(); ++i) {
    if (pData >= pEnd)
      break;

    const auto &prop = props[i];
    std::string keyName = ToUtf8(prop.Name);

    // Value Extraction
    switch (prop.InType) {
    case TDH_INTYPE_INT32:
    case TDH_INTYPE_UINT32:
    case TDH_INTYPE_HEXINT32: {
      if (pData + 4 <= pEnd) {
        uint32_t val;
        memcpy(&val, pData, 4);
        jObj[keyName] = val; // let json handle type
        pData += 4;
      } else {
        jObj[keyName] = 0;
      }
      break;
    }
    case TDH_INTYPE_INT16:
    case TDH_INTYPE_UINT16: {
      if (pData + 2 <= pEnd) {
        uint16_t val;
        memcpy(&val, pData, 2);
        jObj[keyName] = val;
        pData += 2;
      } else {
        jObj[keyName] = 0;
      }
      break;
    }
    case TDH_INTYPE_INT64:
    case TDH_INTYPE_UINT64:
    case TDH_INTYPE_FILETIME: {
      if (pData + 8 <= pEnd) {
        uint64_t val;
        memcpy(&val, pData, 8);
        jObj[keyName] = val;
        pData += 8;
      } else {
        jObj[keyName] = 0;
      }
      break;
    }
    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_SIZET: {
      size_t ptrSize =
          (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
      if (pData + ptrSize <= pEnd) {
        uint64_t val = 0;
        memcpy(&val, pData, ptrSize);
        jObj[keyName] = val;
        pData += ptrSize;
      } else {
        jObj[keyName] = 0;
      }
      break;
    }
    case TDH_INTYPE_BOOLEAN: {
      if (pData + 4 <= pEnd) {
        uint32_t val;
        memcpy(&val, pData, 4);
        jObj[keyName] = (val != 0);
        pData += 4;
      } else {
        jObj[keyName] = false;
      }
      break;
    }
    case TDH_INTYPE_GUID: {
      if (pData + sizeof(GUID) <= pEnd) {
        GUID g;
        memcpy(&g, pData, sizeof(GUID));
        RPC_WSTR str = NULL;
        if (UuidToStringW(&g, &str) == RPC_S_OK) {
          jObj[keyName] = ToUtf8((wchar_t *)str);
          RpcStringFreeW(&str);
        } else {
          jObj[keyName] = "00000000-0000-0000-0000-000000000000";
        }
        pData += sizeof(GUID);
      } else {
        jObj[keyName] = "00000000-0000-0000-0000-000000000000";
      }
      break;
    }
    case TDH_INTYPE_UNICODESTRING: {
      size_t maxLen = (pEnd - pData) / 2;
      size_t len = 0;
      while (len < maxLen && ((wchar_t *)pData)[len] != 0) {
        len++;
      }
      std::wstring s((wchar_t *)pData, len);
      jObj[keyName] = ToUtf8(s);
      pData += (len + 1) * 2;
      break;
    }
    case TDH_INTYPE_ANSISTRING: {
      size_t maxLen = (pEnd - pData);
      size_t len = 0;
      while (len < maxLen && ((char *)pData)[len] != 0)
        len++;
      std::string mbs((char *)pData, len);
      jObj[keyName] = mbs; // Assuming standard ASCII/UTF8 or let json escape it
      pData += (len + 1);
      break;
    }
    default:
      jObj[keyName] = "<UnsupportedType>";
      if (!prop.IsVariable) {
        pData += prop.Length;
      } else {
        pData = pEnd; // Abort
      }
      break;
    }
  }

  // 4. Push to Async Queue instead of Immediate Send
  // 4. Push to Async Queue instead of Immediate Send
  EnrichedEventFrame frame;
  frame.Header.Timestamp = pEvent->EventHeader.TimeStamp.QuadPart;
  frame.Header.ProviderId = pEvent->EventHeader.ProviderId;
  frame.Header.EventId = pEvent->EventHeader.EventDescriptor.Id;
  frame.Header.PayloadSize = 0;     // Calculated after enrichment/serialization
  frame.JsonBody = std::move(jObj); // Transfer JSON object
  frame.ProcessId = pEvent->EventHeader.ProcessId;

  m_eventQueue.Push(frame);
}

// -----------------------------------------------------------------------
// Async Worker Logic
// -----------------------------------------------------------------------

void ETWWorker::WorkerLoop() {
  while (m_running) {
    EnrichedEventFrame frame;
    // Wait for event or stop signal
    m_eventQueue.WaitAndPop(frame, m_running);

    if (!m_running && m_eventQueue.Empty()) {
      break;
    }

    // Double check if we got a frame (WaitAndPop might return empty on stop)
    if (frame.JsonBody.is_null())
      continue;

    // ----------------------------------------------------------------
    // Enrichment Phase
    // ----------------------------------------------------------------

    // 0. Stack Trace Support
    HandleImageLoad(frame.JsonBody, frame.ProcessId);

    // StackWalk Event (Id 32)
    if (frame.Header.EventId == 32) {
      if (frame.JsonBody.contains("Stack") &&
          frame.JsonBody["Stack"].is_array()) {
        std::vector<uint64_t> stack;
        for (auto &val : frame.JsonBody["Stack"]) {
          if (val.is_number())
            stack.push_back(val.get<uint64_t>());
        }
        frame.JsonBody["Frames"] = ResolveStack(frame.ProcessId, stack);
      }
    }

    // 1. Process Name Resolution
    // Check if "Process Name" is already present, if not resolve it
    if (!frame.JsonBody.contains("process name")) {
      uint32_t targetPid = frame.ProcessId;

      // Check for overrides in payload
      if (frame.JsonBody.contains("PID")) {
        try {
          targetPid = frame.JsonBody["PID"].get<uint32_t>();
        } catch (...) {
        }
      } else if (frame.JsonBody.contains("processid")) {
        try {
          targetPid = frame.JsonBody["processid"].get<uint32_t>();
        } catch (...) {
        }
      } else if (frame.JsonBody.contains("ProcessId")) {
        try {
          targetPid = frame.JsonBody["ProcessId"].get<uint32_t>();
        } catch (...) {
        }
      }

      std::string procName = GetProcessName(targetPid);
      frame.JsonBody["process name"] = procName;

      // 2. Parent PID Resolution
      uint32_t parentPid = GetParentPid(targetPid);
      frame.JsonBody["parent pid"] = parentPid;

      // 3. Parent Process Name Resolution
      if (parentPid > 0) {
        std::string parentProcName = GetProcessName(parentPid);
        frame.JsonBody["parent process name"] = parentProcName;
      }

      // 4. User/Owner Resolution
      std::string owner = GetProcessOwner(targetPid);
      frame.JsonBody["user"] = owner;
    }

    // Look for File Paths to Enrich
    // Common keys: "FileName", "ImageName", "Path", "ImagePath"
    std::string pathToCheck;
    if (frame.JsonBody.contains("FileName")) {
      pathToCheck = frame.JsonBody["FileName"];
    } else if (frame.JsonBody.contains("ImageName")) {
      pathToCheck = frame.JsonBody["ImageName"];
    } else if (frame.JsonBody.contains("Path")) {
      pathToCheck = frame.JsonBody["Path"];
    }

    // If we found a path, compute hashes
    if (!pathToCheck.empty()) {
      std::wstring widePath = ToWide(pathToCheck);

      // Very basic validation (skip pipes, etc)
      if (widePath.find(L"\\Device\\HarddiskVolume") == 0 ||
          widePath.find(L"C:") != std::string::npos) {
        std::string md5, sha1, sha256;
        if (ComputeFileHashes(widePath, md5, sha1, sha256)) {
          json hashes;
          hashes["md5"] = md5;
          hashes["sha1"] = sha1;
          hashes["sha256"] = sha256;
          frame.JsonBody["hashes"] = hashes;
        }
      }
    }

    // ----------------------------------------------------------------
    // Serialization & Send Phase
    // ----------------------------------------------------------------
    std::string jsonPayload = frame.JsonBody.dump();
    if (!jsonPayload.empty()) {
      std::vector<char> sendBuf;
      sendBuf.resize(sizeof(PacketHeader) + jsonPayload.size());

      PacketHeader *h = (PacketHeader *)sendBuf.data();
      h->Timestamp = frame.Header.Timestamp;
      h->ProviderId = frame.Header.ProviderId;
      h->EventId = frame.Header.EventId;
      h->PayloadSize = (unsigned __int32)jsonPayload.size();

      memcpy(sendBuf.data() + sizeof(PacketHeader), jsonPayload.data(),
             jsonPayload.size());

      // Lock pipe for writing
      {
        std::lock_guard<std::mutex> lock(m_pipeMutex);
        if (m_hPipe != INVALID_HANDLE_VALUE) {
          DWORD bytesWritten;
          WriteFile(m_hPipe, sendBuf.data(), (DWORD)sendBuf.size(),
                    &bytesWritten, NULL);
        }
      }
    }
  }
}

// Helper to clean keyword string
std::wstring ETWWorker::CleanKeyword(std::wstring k) {
  if (k.empty())
    return k;
  if (k.size() >= 2 && k.front() == L'{' && k.back() == L'}')
    k = k.substr(1, k.size() - 2);
  if (k.size() >= 2 && k.substr(0, 2) == L", ")
    k = k.substr(2);

  std::wstring res;
  std::wstring del = L", ";
  std::wstring rep = L" | ";
  size_t pos = 0, prev = 0;
  while ((pos = k.find(del, prev)) != std::wstring::npos) {
    res += k.substr(prev, pos - prev) + rep;
    prev = pos + del.length();
  }
  res += k.substr(prev);
  return res;
}

// Helper to calculate hashes logic
bool ETWWorker::ComputeFileHashes(const std::wstring &path, std::string &md5,
                                  std::string &sha1, std::string &sha256) {

  // 1. Check Cache
  {
    std::lock_guard<std::mutex> lock(m_fileCacheMutex);
    auto it = m_fileHashCache.find(path);
    if (it != m_fileHashCache.end()) {
      // Verify timestamp haven't changed (basic consistency)
      // For now, simple return cached values
      md5 = it->second.Md5;
      sha1 = it->second.Sha1;
      sha256 = it->second.Sha256;
      return true;
    }
  }

  // 2. Open File
  HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return false;

  // 3. Prep Crypto
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHashMd5 = 0;
  HCRYPTHASH hHashSha1 = 0;
  HCRYPTHASH hHashSha256 =
      0; // Only supporting MD5/SHA1 with basic Provider, need Enhanced provider
         // for SHA256? Actually default PROV_RSA_AES supports SHA256 usually in
         // modern Windows. Or use CNG (BCrypt). Let's stick to simple HCRYPT
         // for now, checking support.

  if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES,
                           CRYPT_VERIFYCONTEXT)) {
    CloseHandle(hFile);
    return false;
  }

  CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHashMd5);
  CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHashSha1);
  CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHashSha256);

  // 4. Read Loop
  const int BUF_SIZE = 4096;
  BYTE buffer[BUF_SIZE];
  DWORD bytesRead = 0;
  bool success = false;

  while (ReadFile(hFile, buffer, BUF_SIZE, &bytesRead, NULL)) {
    if (bytesRead == 0)
      break;
    if (hHashMd5)
      CryptHashData(hHashMd5, buffer, bytesRead, 0);
    if (hHashSha1)
      CryptHashData(hHashSha1, buffer, bytesRead, 0);
    if (hHashSha256)
      CryptHashData(hHashSha256, buffer, bytesRead, 0);
  }

  auto GetHashStr = [](HCRYPTHASH h) -> std::string {
    if (!h)
      return "";
    DWORD cbHash = 0;
    DWORD dwCount = sizeof(cbHash);
    // Get size first? commonly known.
    if (CryptGetHashParam(h, HP_HASHVAL, NULL, &cbHash, 0)) {
      std::vector<BYTE> rgbHash(cbHash);
      if (CryptGetHashParam(h, HP_HASHVAL, rgbHash.data(), &cbHash, 0)) {
        const char hex[] = "0123456789abcdef";
        std::string str;
        for (DWORD i = 0; i < cbHash; i++) {
          str += hex[rgbHash[i] >> 4];
          str += hex[rgbHash[i] & 0xF];
        }
        return str;
      }
    }
    return "";
  };

  md5 = GetHashStr(hHashMd5);
  sha1 = GetHashStr(hHashSha1);
  sha256 = GetHashStr(hHashSha256);

  success = (!md5.empty());

  // Cleanup
  if (hHashMd5)
    CryptDestroyHash(hHashMd5);
  if (hHashSha1)
    CryptDestroyHash(hHashSha1);
  if (hHashSha256)
    CryptDestroyHash(hHashSha256);
  CryptReleaseContext(hProv, 0);
  CloseHandle(hFile);

  // 5. Update Cache
  if (success) {
    std::lock_guard<std::mutex> lock(m_fileCacheMutex);
    m_fileHashCache[path] = {md5, sha1, sha256, 0}; // TODO: Use real timestamp
  }

  return success;
}

// Helper to handle Image Load events for stack walking
void ETWWorker::HandleImageLoad(const json &evtBody, uint32_t pid) {
  try {
    uint64_t base = 0;
    uint64_t size = 0;
    std::string pathUtf8 = "";

    auto getVal = [&](const char *key, uint64_t &out) {
      if (evtBody.contains(key)) {
        if (evtBody[key].is_number())
          out = evtBody[key].get<uint64_t>();
        else if (evtBody[key].is_string()) {
          std::string s = evtBody[key].get<std::string>();
          if (s.find("0x") == 0)
            out = std::stoull(s, nullptr, 16);
          else
            out = std::stoull(s);
        }
      }
    };

    getVal("ImageBase", base);
    getVal("ImageSize", size);

    if (base == 0)
      getVal("BaseAddress", base);
    if (size == 0)
      getVal("ModuleSize", size);

    if (evtBody.contains("FileName"))
      pathUtf8 = evtBody["FileName"].get<std::string>();
    else if (evtBody.contains("ImageName"))
      pathUtf8 = evtBody["ImageName"].get<std::string>();

    if (base != 0 && !pathUtf8.empty()) {
      std::lock_guard<std::mutex> lock(m_moduleMutex);
      m_processModules[pid].push_back({base, size, ToWide(pathUtf8)});
    }
  } catch (...) {
  }
}

// Helper to resolve stack addresses to Module + Offset
json ETWWorker::ResolveStack(uint32_t pid, const std::vector<uint64_t> &stack) {
  std::lock_guard<std::mutex> lock(m_moduleMutex);
  json frames = json::array();

  bool hasModules = (m_processModules.count(pid) > 0);
  const auto &modules = m_processModules[pid];

  for (uint64_t addr : stack) {
    std::string symbol = "";
    if (hasModules) {
      for (const auto &mod : modules) {
        if (addr >= mod.ImageBase && addr < mod.ImageBase + mod.ImageSize) {
          uint64_t offset = addr - mod.ImageBase;
          std::string modName = ToUtf8(mod.ImagePath);
          size_t lastSlash = modName.find_last_of("\\/");
          if (lastSlash != std::string::npos)
            modName = modName.substr(lastSlash + 1);

          char buf[64];
          sprintf_s(buf, " + 0x%llX", offset);
          symbol = modName + buf;
          break;
        }
      }
    }
    if (symbol.empty()) {
      char buf[32];
      sprintf_s(buf, "0x%llX", addr);
      symbol = buf;
    }
    frames.push_back(symbol);
  }
  return frames;
}
