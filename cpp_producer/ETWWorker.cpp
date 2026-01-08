#define INITGUID
#include "ETWWorker.h"
#include <evntprov.h>
#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")
#include <iostream>
#include <map>
#include <strsafe.h>

// Include nlohmann/json
#include "nlohmann/json.hpp"
using json = nlohmann::json;

ETWWorker::ETWWorker()
    : m_sessionHandle(0), m_traceHandle(INVALID_PROCESSTRACE_HANDLE),
      m_running(false), m_hPipe(INVALID_HANDLE_VALUE), m_droppedEvents(0) {}

ETWWorker::~ETWWorker() {
  Stop();
  if (m_hPipe != INVALID_HANDLE_VALUE) {
    CloseHandle(m_hPipe);
  }
}

// Helper to convert Wide String to UTF-8 std::string for JSON
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
          m_schemaCache[key] = props;
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

  const auto &props = it->second;
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

  // 4. Send Packet (Header + JSON)
  // Dump to minified string
  std::string jsonPayload = jObj.dump();

  if (!jsonPayload.empty()) {
    std::vector<char> sendBuf;
    sendBuf.resize(sizeof(PacketHeader) + jsonPayload.size());

    PacketHeader *h = (PacketHeader *)sendBuf.data();
    h->Timestamp = pEvent->EventHeader.TimeStamp.QuadPart;
    h->ProviderId = pEvent->EventHeader.ProviderId;
    h->EventId = pEvent->EventHeader.EventDescriptor.Id;
    h->PayloadSize = (unsigned __int32)jsonPayload.size();

    // Copy payload after header
    memcpy(sendBuf.data() + sizeof(PacketHeader), jsonPayload.data(),
           jsonPayload.size());

    DWORD bytesWritten;
    WriteFile(m_hPipe, sendBuf.data(), (DWORD)sendBuf.size(), &bytesWritten,
              NULL);
  }
}
