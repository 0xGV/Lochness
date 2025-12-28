#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// windows.h MUST be first
#include <evntcons.h>
#include <evntrace.h>
#include <rpc.h>
#include <rpcdce.h>
#include <tdh.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

// Packet Header Structure (Packed)
#pragma pack(push, 1)
struct PacketHeader {
  unsigned __int64 Timestamp;
  GUID ProviderId;
  unsigned short EventId;
  unsigned __int32 PayloadSize;
};
#pragma pack(pop)

// Schema Cache Structures
struct EventKey {
  GUID ProviderId;
  unsigned short Id;
  unsigned char Version;

  bool operator==(const EventKey &other) const {
    return IsEqualGUID(ProviderId, other.ProviderId) && Id == other.Id &&
           Version == other.Version;
  }
};

struct EventKeyHash {
  size_t operator()(const EventKey &k) const {
    size_t h1 = 0;
    const unsigned __int64 *p = (const unsigned __int64 *)&k.ProviderId;
    h1 ^= std::hash<unsigned __int64>{}(p[0]);
    h1 ^= std::hash<unsigned __int64>{}(p[1]);
    h1 ^= std::hash<unsigned short>{}(k.Id);
    h1 ^= std::hash<unsigned char>{}(k.Version);
    return h1;
  }
};

struct PropertyMetadata {
  std::wstring Name;
  USHORT InType;
  USHORT OutType;
  ULONG Length; // 0 if variable
  bool IsVariable;
};

class ETWWorker {
public:
  ETWWorker();
  ~ETWWorker();

  void Start(const std::wstring &sessionName);
  void Stop();
  void EnableProvider(const std::wstring &providerGuid);
  void DisableProvider(const std::wstring &providerGuid);

  // Connect to the data pipe (Go Server)
  bool ConnectPipe(const std::wstring &pipeName);

private:
  static void WINAPI EventCallback(PEVENT_RECORD pEvent);
  void ProcessEvent(PEVENT_RECORD pEvent);

  void TraceLoop();

  TRACEHANDLE m_sessionHandle;
  TRACEHANDLE m_traceHandle;
  std::wstring m_sessionName;
  std::atomic<bool> m_running;
  std::thread m_traceThread;

  // Pipe Handle
  HANDLE m_hPipe;
  std::atomic<unsigned long> m_droppedEvents;

  // Schema Cache
  std::unordered_map<EventKey, std::vector<PropertyMetadata>, EventKeyHash>
      m_schemaCache;
  std::unordered_map<EventKey, std::wstring, EventKeyHash>
      m_eventNameCache; // Optional: cache event names
};
