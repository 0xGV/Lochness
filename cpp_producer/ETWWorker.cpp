#define INITGUID
#include "ETWWorker.h"
#include <evntprov.h>
#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")
#include <iostream>
#include <map>
#include <strsafe.h>

ETWWorker::ETWWorker()
    : m_sessionHandle(0), m_traceHandle(INVALID_PROCESSTRACE_HANDLE),
      m_running(false), m_hPipe(INVALID_HANDLE_VALUE), m_droppedEvents(0) {}

ETWWorker::~ETWWorker() {
  Stop();
  if (m_hPipe != INVALID_HANDLE_VALUE) {
    CloseHandle(m_hPipe);
  }
}

bool ETWWorker::ConnectPipe(const std::wstring &pipeName) {
  m_hPipe = CreateFileW(pipeName.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);

  if (m_hPipe != INVALID_HANDLE_VALUE) {
    // We'll use blocking mode for reliability but small buffers to ensure
    // lossy behavior if we choose. For now, standard blocking is safer
    // for the stream synchronization.
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
  m_traceThread = std::thread(&ETWWorker::TraceLoop, this);
}

void ETWWorker::Stop() {
  m_running = false;
  if (m_sessionHandle) {
    // Allocate properties for Stop
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
  // 1. Start Trace Session
  // We need to allocate memory for EVENT_TRACE_PROPERTIES + session name
  size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) +
                     (m_sessionName.length() + 1) * sizeof(wchar_t) + 1024;
  EVENT_TRACE_PROPERTIES *pProps = (EVENT_TRACE_PROPERTIES *)malloc(propsSize);
  ZeroMemory(pProps, propsSize);

  pProps->Wnode.BufferSize = (ULONG)propsSize;
  pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  pProps->Wnode.ClientContext = 1; // QPC
  pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  pProps->LoggerNameOffset =
      sizeof(EVENT_TRACE_PROPERTIES); // Name follows struct

  // Stop if exists
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

  // 2. Open Trace for Consumption
  EVENT_TRACE_LOGFILEW logFile;
  ZeroMemory(&logFile, sizeof(logFile));
  logFile.LoggerName = (LPWSTR)m_sessionName.c_str();
  logFile.ProcessTraceMode =
      PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  logFile.EventRecordCallback =
      (PEVENT_RECORD_CALLBACK)ETWWorker::EventCallback;
  logFile.Context =
      this; // Pass 'this' to callback ... wait, EventCallback is static.

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

std::wstring JsonEscape(const std::wstring &s) {
  std::wstring res;
  for (wchar_t c : s) {
    switch (c) {
    case L'\"':
      res += L"\\\"";
      break;
    case L'\\':
      res += L"\\\\";
      break;
    case L'\b':
      res += L"\\b";
      break;
    case L'\f':
      res += L"\\f";
      break;
    case L'\n':
      res += L"\\n";
      break;
    case L'\r':
      res += L"\\r";
      break;
    case L'\t':
      res += L"\\t";
      break;
    default:
      if (c < 32 || c > 126) {
        // Simple hex escape for non-printable/unicode or just pass-through if
        // UTF8 later handled
        // For simplicity, just pass through or skip if control
        if (c >= 32)
          res += c;
      } else {
        res += c;
      }
    }
  }
  return res;
}

std::wstring ETWWorker::GetProviderMetadata(const std::wstring &providerGuid,
                                            const std::wstring &providerName) {
  // Use Winevt API as requested for better reliability
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
    // Fallback: If we have observed events, return them
    std::wcerr << L"Failed to open publisher metadata for: "
               << cleanGuid.c_str() << L" Error: " << GetLastError()
               << std::endl;

    std::wstring json = L"[";
    std::lock_guard<std::mutex> lock(m_stateMutex);

    bool first = true;
    GUID targetGuid;
    // We need to parse GUID first to compare
    if (UuidFromStringW((RPC_WSTR)providerGuid.c_str(), &targetGuid) ==
        RPC_S_OK) {
      for (const auto &pair : m_schemaCache) {
        if (IsEqualGUID(pair.first.ProviderId, targetGuid)) {
          if (!first)
            json += L",";
          json += L"{\"Id\":" + std::to_wstring(pair.first.Id) +
                  L",\"Description\":\"Observed Event\"}";
          first = false;
        }
      }
    }
    json += L"]";
    return json;
  }

  std::map<UINT64, std::wstring> keywordMap;
  std::map<UINT32, std::wstring> opcodeMap;
  std::map<UINT32, std::wstring> taskMap;

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
        // Note: hArray is owned by hPublisher? No, usually separate. But
        // EvtGetPublisherMetadataProperty returns variant with handle. Docs
        // say: "You must call the EvtClose function to close the handle when
        // you are done."
        EvtClose(hArray);
      }
      return res;
    };

    // Need cast? IDs are generic enum.
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

  std::wstring json = L"[";
  EVT_HANDLE hEnum = EvtOpenEventMetadataEnum(hMetadata, 0);
  if (hEnum) {
    EVT_HANDLE hEvent = NULL;
    bool first = true;
    while ((hEvent = EvtNextEventMetadata(hEnum, 0)) != NULL) {
      DWORD dwBufferSize = 0;
      DWORD dwBufferUsed = 0;

      // Get ID
      UINT64 eventId = 0;
      DWORD dwValUsed = 0;
      if (!EvtGetEventMetadataProperty(hEvent, EventMetadataEventID, 0, 0, NULL,
                                       &dwValUsed) &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> valBuf(dwValUsed);
        if (EvtGetEventMetadataProperty(hEvent, EventMetadataEventID, 0,
                                        dwValUsed, (PEVT_VARIANT)valBuf.data(),
                                        &dwValUsed)) {
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
      std::wstring keyword = GetFormatMessage(EvtFormatMessageKeyword);

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

      if (!first)
        json += L",";

      json +=
          L"{\"Id\":" + std::to_wstring(eventId) + L",\"Version\":" +
          std::to_wstring(version) + L",\"Level\":" + std::to_wstring(levelId) +
          L",\"LevelStr\":\"" + JsonEscape(levelStr) + L"\"" + L",\"Opcode\":" +
          std::to_wstring(opcodeId) + L",\"OpcodeStr\":\"" +
          JsonEscape(opcodeStr) + L"\"" + L",\"Task\":" +
          std::to_wstring(taskId) + L",\"TaskStr\":\"" + JsonEscape(taskStr) +
          L"\"" + L",\"Keyword\":\"" + JsonEscape(keyword) + L"\"" +
          L",\"Description\":\"" + JsonEscape(description) + L"\"}";
      first = false;

      EvtClose(hEvent);
    }
    EvtClose(hEnum);
  }
  EvtClose(hMetadata);
  json += L"]";
  return json;
}

void ETWWorker::SetProviderFilter(const std::wstring &providerGuid,
                                  const std::vector<unsigned short> &eventIds) {
  GUID guid;
  if (UuidFromStringW((RPC_WSTR)providerGuid.c_str(), &guid) != RPC_S_OK) {
    std::wcerr << L"Invalid Provider GUID for filter: " << providerGuid
               << std::endl;
    return;
  }

  // If IDs are empty, we want to clear the filter.
  // Passing NULL filter to EnableTraceEx2 clears it?
  // Or do we need to Enable without params.
  // We will re-enable the provider with (or without) filter parameters.

  if (eventIds.empty()) {
    // Enable without filters (clears them)
    // Note: This assumes Level=VERBOSE (0) logic from EnableProvider.
    // Ideally we track current level/keywords, but for now re-enabling with
    // default is okay.
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

  // Construct EVENT_FILTER_EVENT_ID
  size_t filterSize =
      sizeof(EVENT_FILTER_EVENT_ID) +
      (eventIds.size() > 0 ? (eventIds.size() - 1) : 0) * sizeof(USHORT);
  // Actually, align usage:
  // Offset of 'Events' is where array starts.
  // But definition is USHORT Events[ANYSIZE_ARRAY].
  // Safe calculation:
  filterSize = offsetof(EVENT_FILTER_EVENT_ID, Events) +
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
  params.EnableProperty = 0;
  params.ControlFlags = 0;
  params.SourceId = guid; // Not strictly used for normal enable?
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
    // Re-attempt connection to relay
    if (!ConnectPipe(L"\\\\.\\pipe\\etw_stream")) {
      return;
    }
  }

  // Filter headers?
  if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid))
    return; // Skip meta events if unwanted

  // --- FILTERING CHECK ---
  // Kernel now handles filtering! We just process what we receive.
  // We hold lock for Cache Access
  std::lock_guard<std::mutex> lock(m_stateMutex);

  // 1. Define Cache Key
  EventKey key;
  key.ProviderId = pEvent->EventHeader.ProviderId;
  key.Id = pEvent->EventHeader.EventDescriptor.Id;
  key.Version = pEvent->EventHeader.EventDescriptor.Version;

  // 2. Check Cache
  auto it = m_schemaCache.find(key);
  if (it == m_schemaCache.end()) {
    // Cache Miss - "First-Look" Logic
    ULONG bufferSize = 0;
    ULONG status = TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);

    if (status == ERROR_INSUFFICIENT_BUFFER) {
      TRACE_EVENT_INFO *pInfo = (TRACE_EVENT_INFO *)malloc(bufferSize);
      if (pInfo) {
        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);
        if (status == ERROR_SUCCESS) {
          std::vector<PropertyMetadata> props;

          for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            PropertyMetadata meta;
            EVENT_PROPERTY_INFO &propInfo = pInfo->EventPropertyInfoArray[i];

            // Handle Name
            if (propInfo.NameOffset != 0) {
              meta.Name =
                  std::wstring((LPWSTR)((PBYTE)pInfo + propInfo.NameOffset));
            } else {
              meta.Name = L"Field" + std::to_wstring(i);
            }

            meta.InType = propInfo.nonStructType.InType;
            meta.OutType = propInfo.nonStructType.OutType;

            // Check for length
            if ((propInfo.Flags & PropertyParamLength) ||
                (propInfo.Flags & PropertyParamCount)) {
              meta.IsVariable = true;
              meta.Length = 0;
            } else {
              meta.Length = propInfo.length;
              meta.IsVariable = (meta.Length == 0);

              // Force strings to be variable if length not explicitly static
              if (meta.InType == TDH_INTYPE_UNICODESTRING ||
                  meta.InType == TDH_INTYPE_ANSISTRING ||
                  meta.InType == TDH_INTYPE_SID) {
                meta.IsVariable = true;
              }
            }
            props.push_back(meta);
          }
          m_schemaCache[key] = props;
          it = m_schemaCache.find(key); // Refresh iterator after insert
        }
        free(pInfo);
      }
    }
  }

  // If still not found (TDH failed), we can't parse payload
  if (it == m_schemaCache.end()) {
    return;
  }

  // 3. Hot Path Parsing (JSON serialization)
  std::wstring json = L"{";

  PBYTE pData = (PBYTE)pEvent->UserData;
  PBYTE pEnd = pData + pEvent->UserDataLength;

  const auto &props = it->second;
  for (size_t i = 0; i < props.size(); ++i) {
    if (pData >= pEnd)
      break;

    const auto &prop = props[i];
    if (i > 0)
      json += L",";

    json += L"\"" + JsonEscape(prop.Name) + L"\":";

    // Value Extraction
    switch (prop.InType) {
    case TDH_INTYPE_INT32:
    case TDH_INTYPE_UINT32:
    case TDH_INTYPE_HEXINT32: {
      if (pData + 4 <= pEnd) {
        uint32_t val;
        memcpy(&val, pData, 4);
        json += std::to_wstring(val);
        pData += 4;
      } else {
        json += L"0";
      }
      break;
    }
    case TDH_INTYPE_INT16:
    case TDH_INTYPE_UINT16: {
      if (pData + 2 <= pEnd) {
        uint16_t val;
        memcpy(&val, pData, 2);
        json += std::to_wstring(val);
        pData += 2;
      } else {
        json += L"0";
      }
      break;
    }
    case TDH_INTYPE_INT64:
    case TDH_INTYPE_UINT64:
    case TDH_INTYPE_FILETIME: {
      if (pData + 8 <= pEnd) {
        uint64_t val;
        memcpy(&val, pData, 8);
        json += std::to_wstring(val);
        pData += 8;
      } else {
        json += L"0";
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
        json += std::to_wstring(val);
        pData += ptrSize;
      } else {
        json += L"0";
      }
      break;
    }
    case TDH_INTYPE_BOOLEAN: {
      if (pData + 4 <= pEnd) {
        uint32_t val;
        memcpy(&val, pData, 4);
        json += val ? L"true" : L"false";
        pData += 4;
      } else {
        json += L"false";
      }
      break;
    }
    case TDH_INTYPE_GUID: {
      if (pData + sizeof(GUID) <= pEnd) {
        GUID g;
        memcpy(&g, pData, sizeof(GUID));
        RPC_WSTR str = NULL;
        if (UuidToStringW(&g, &str) == RPC_S_OK) {
          json += L"\"" + std::wstring((wchar_t *)str) + L"\"";
          RpcStringFreeW(&str);
        } else {
          json += L"\"00000000-0000-0000-0000-000000000000\"";
        }
        pData += sizeof(GUID);
      } else {
        json += L"\"00000000-0000-0000-0000-000000000000\"";
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
      json += L"\"" + JsonEscape(s) + L"\"";
      pData += (len + 1) * 2;
      break;
    }
    case TDH_INTYPE_ANSISTRING: {
      size_t maxLen = (pEnd - pData);
      size_t len = 0;
      while (len < maxLen && ((char *)pData)[len] != 0)
        len++;
      std::string mbs((char *)pData, len);
      std::wstring wstr(mbs.begin(), mbs.end());
      json += L"\"" + JsonEscape(wstr) + L"\"";
      pData += (len + 1);
      break;
    }
    default:
      json += L"\"<UnsupportedType>\"";
      if (!prop.IsVariable) {
        pData += prop.Length;
      } else {
        pData = pEnd; // Abort
      }
      break;
    }
  }
  json += L"}";

  // 4. Send Packet (Header + JSON)
  int payloadLen = WideCharToMultiByte(CP_UTF8, 0, json.c_str(),
                                       (int)json.length(), NULL, 0, NULL, NULL);
  if (payloadLen > 0) {
    std::vector<char> sendBuf;
    sendBuf.resize(sizeof(PacketHeader) + payloadLen);

    PacketHeader *h = (PacketHeader *)sendBuf.data();
    h->Timestamp = pEvent->EventHeader.TimeStamp.QuadPart;
    h->ProviderId = pEvent->EventHeader.ProviderId;
    h->EventId = pEvent->EventHeader.EventDescriptor.Id;
    h->PayloadSize = (unsigned __int32)payloadLen;

    WideCharToMultiByte(CP_UTF8, 0, json.c_str(), (int)json.length(),
                        (char *)(sendBuf.data() + sizeof(PacketHeader)),
                        payloadLen, NULL, NULL);

    DWORD written;
    if (!WriteFile(m_hPipe, sendBuf.data(), (DWORD)sendBuf.size(), &written,
                   NULL) ||
        written != sendBuf.size()) {
      m_droppedEvents++;
      // If the pipe is broken, reset the handle
      if (GetLastError() == ERROR_BROKEN_PIPE ||
          GetLastError() == ERROR_NO_DATA) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
      }
    }
  }
}
