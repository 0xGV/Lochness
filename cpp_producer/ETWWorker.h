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
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Include nlohmann/json globally for the header struct
#include "nlohmann/json.hpp"

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

// Enriched Event Frame (Internal Queue Item)
struct EnrichedEventFrame {
  PacketHeader Header;
  nlohmann::json JsonBody;
};

// Files Hash Cache Entry
struct FileHashCacheEntry {
  std::string Md5;
  std::string Sha1;
  std::string Sha256;
  unsigned __int64 LastWriteTime;
};

// Thread Safe Queue
template <typename T> class ThreadSafeQueue {
public:
  void Push(const T &item) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.push(item);
    m_cond.notify_one();
  }

  bool Pop(T &item) {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_queue.empty()) {
      return false;
    }
    item = std::move(m_queue.front());
    m_queue.pop();
    return true;
  }

  // Blocking Pop with timeout or stop signal could be added,
  // but for now we'll use a simple condition wait in the worker loop if needed,
  // or just use this non-blocking/blocking hybrid pattern.
  // Actually, let's add a blocking wait helper for the worker Loop.
  void WaitAndPop(T &item, std::atomic<bool> &running) {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_cond.wait(lock, [&] { return !m_queue.empty() || !running; });
    if (!m_queue.empty()) {
      item = std::move(m_queue.front());
      m_queue.pop();
    }
  }

  bool Empty() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.empty();
  }

  void NotifyAll() {
    // Wake up all waiters (used for stopping)
    m_cond.notify_all();
  }

private:
  std::queue<T> m_queue;
  std::mutex m_mutex;
  std::condition_variable m_cond;
};

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

struct CachedEventSchema {
  std::vector<PropertyMetadata> Properties;
  std::wstring KeywordStr;
  std::wstring OpcodeStr;
  std::wstring TaskStr;
};

class ETWWorker {
public:
  ETWWorker();
  ~ETWWorker();

  void Start(const std::wstring &sessionName);
  void Stop();
  void EnableProvider(const std::wstring &providerGuid);
  void DisableProvider(const std::wstring &providerGuid);

  std::wstring GetProviderMetadata(const std::wstring &providerGuid,
                                   const std::wstring &providerName = L"");
  void SetProviderFilter(const std::wstring &providerGuid,
                         const std::vector<unsigned short> &eventIds);

  // Connect to the data pipe (Go Server)
  bool ConnectPipe(const std::wstring &pipeName);

private:
  static void WINAPI EventCallback(PEVENT_RECORD pEvent);
  void ProcessEvent(PEVENT_RECORD pEvent);

  void TraceLoop();
  void WorkerLoop(); // Background Enrichment Worker

  // Hashing Helper
  bool ComputeFileHashes(const std::wstring &path, std::string &md5,
                         std::string &sha1, std::string &sha256);

  std::wstring CleanKeyword(std::wstring keyword);

  TRACEHANDLE m_sessionHandle;
  TRACEHANDLE m_traceHandle;
  std::wstring m_sessionName;
  std::atomic<bool> m_running;
  std::thread m_traceThread;

  // Pipe Handle
  // m_hPipe is now protected by m_pipeMutex since workers share it
  HANDLE m_hPipe;
  std::mutex m_pipeMutex;
  std::atomic<unsigned long> m_droppedEvents;

  // Async Worker Components
  std::vector<std::thread> m_workerThreads;
  ThreadSafeQueue<EnrichedEventFrame> m_eventQueue;

  // File Hash Cache
  std::unordered_map<std::wstring, FileHashCacheEntry> m_fileHashCache;
  std::mutex m_fileCacheMutex;

  // Schema Cache
  std::unordered_map<EventKey, CachedEventSchema, EventKeyHash> m_schemaCache;
  std::unordered_map<EventKey, std::wstring, EventKeyHash>
      m_eventNameCache; // Optional: cache event names

  // Cache Protection
  mutable std::mutex m_stateMutex;
};
