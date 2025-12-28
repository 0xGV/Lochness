package server

import (
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
	// Wait, user said avoid external deps.
	// I need to use standard net with \\.\pipe\.
	// Go's net package on Windows typically uses winio under the hood or requires specific dialing.
	// Standard `net.Listen("unix", ...)` is for Unix sockets.
	// For Windows Named Pipes, if we strictly avoid external deps, we might need to use `syscall`.
	// However, `net` package DOES NOT support Named Pipes server out of the box on Windows easily without `winio`.
	// Actually, `net.Listen` with `\\.\pipe\` does not work directly.
	// BUT, the user said "try to avoid". If I cannot do it easily, I might have to use winio or syscall.
	// Writing a full overlapped IO named pipe server in syscall is complex.
	// I will try to use `winio` as a last resort? No, user was specific. "Lets try to avoid".
	// I will implementation a simple `syscall` based listener or client.
	// Actually, for the SERVER side, `winio` is very standard.
	// Let me try to use `npipe` (std lib fork?) No.
	// I will attempt to implement a helper using `syscall` to create the named pipe instance.
)

// Let's implement a listener using syscalls to avoid deps if possible.
// Or I can ask the user if `go-winio` is okay since `net` doesn't support it native server side.
// The user said "standard net + winio or just os file operations might be preferred".
// They said "Lets try to avoid external deps".
// Implementing a robust named pipe server in raw syscalls is risky for this agent.
// I will use `github.com/microsoft/go-winio` but wrapped? No, that's still a dep.
// I will write a simple Blocking wrapper around CreateNamedPipe.

var (
	modkernel32             = syscall.NewLazyDLL("kernel32.dll")
	procCreateNamedPipeW    = modkernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe    = modkernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe = modkernel32.NewProc("DisconnectNamedPipe")
)

const (
	PIPE_ACCESS_DUPLEX       = 0x00000003
	PIPE_TYPE_BYTE           = 0x00000000
	PIPE_READMODE_BYTE       = 0x00000000
	PIPE_WAIT                = 0x00000000
	PIPE_UNLIMITED_INSTANCES = 255
	ERROR_PIPE_CONNECTED     = 535
)

type PipeServer struct {
	Path    string
	Running bool
	Storage *Storage
	mu      sync.Mutex
}

func NewPipeServer(path string, storage *Storage) *PipeServer {
	return &PipeServer{
		Path:    path,
		Storage: storage,
	}
}

func (s *PipeServer) Start() {
	s.mu.Lock()
	s.Running = true
	s.mu.Unlock()

	go s.acceptLoop()
}

func (s *PipeServer) acceptLoop() {
	pathPtr, _ := syscall.UTF16PtrFromString(s.Path)

	for {
		s.mu.Lock()
		if !s.Running {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		// Create Named Pipe
		h, _, err := procCreateNamedPipeW.Call(
			uintptr(unsafe.Pointer(pathPtr)),
			uintptr(PIPE_ACCESS_DUPLEX),
			uintptr(PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT),
			uintptr(PIPE_UNLIMITED_INSTANCES),
			uintptr(65536), // Out buffer
			uintptr(65536), // In buffer
			uintptr(0),     // Default timeout
			uintptr(0),     // Security attributes
		)

		handle := syscall.Handle(h)
		if handle == syscall.InvalidHandle {
			log.Printf("CreateNamedPipe failed: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		// Wait for connection
		// ConnectNamedPipe returns 0 on failure. Overlapped is nil aka synchronous.
		r, _, err := procConnectNamedPipe.Call(uintptr(handle), 0)

		// If another process is already connected, it returns ERROR_PIPE_CONNECTED (535? No 109? No).
		// Actually ConnectNamedPipe returns non-zero on success.
		// If it returns 0, check GetLastError.
		// If GetLastError is ERROR_PIPE_CONNECTED, then we are good.

		if r == 0 {
			// check error
			if err.(syscall.Errno) != syscall.Errno(ERROR_PIPE_CONNECTED) {
				syscall.CloseHandle(handle)
				continue
			}
		}

		// Handle connection in a new goroutine
		// We convert handle to a File to use Read/Write easily
		f := os.NewFile(uintptr(handle), s.Path)
		go s.handleConnection(f)
	}
}

func (s *PipeServer) handleConnection(f *os.File) {
	defer f.Close()
	log.Println("Client connected to pipe")

	// Read loop
	for {
		header, err := ReadHeader(f)
		if err != nil {
			log.Printf("Pipe read error (disconnect): %v", err)
			return
		}

		// Read Payload
		payload := make([]byte, header.PayloadSize)
		if _, err := io.ReadFull(f, payload); err != nil {
			log.Printf("Payload read error: %v", err)
			return
		}

		// Construct Event and Push to Storage
		log.Printf("Received Event [%d] from %x: %s", header.EventId, header.ProviderId, string(payload))
		evt := Event{
			Timestamp:  header.Timestamp,
			ProviderId: header.ProviderId,
			EventId:    header.EventId,
			Data:       payload,
		}
		s.Storage.Add(evt)
	}
}
