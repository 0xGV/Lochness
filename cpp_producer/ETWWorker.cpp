#define INITGUID
#include "ETWWorker.h"
#include <iostream>
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
          it = m_schemaCache.find(key); // Refresh iterator
        }
        free(pInfo);
      }
    }

    if (it == m_schemaCache.end()) {
      return;
    }
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
