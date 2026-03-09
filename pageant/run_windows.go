//go:build windows
// +build windows

package pageant

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"encoding/binary"
	"encoding/hex"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/ndbeals/winssh-pageant/internal/security"
	"github.com/ndbeals/winssh-pageant/internal/win"
	"github.com/ndbeals/winssh-pageant/openssh"
)

var defaultHandlerFunc = func(p *Pageant, result []byte) ([]byte, error) {
	return openssh.QueryAgent(p.SSHAgentPipe, result)
}

func (p *Pageant) Run() {

	err := win.FixConsoleIfNeeded()
	if err != nil {
		log.Printf("FixConsoleOutput: %v\n", err)
	}

	// Check if any application claiming to be a Pageant Window is already running
	if doesPageantWindowExist() {
		log.Println("This application is already running, exiting.")
		return
	}

	// Start a proxy/redirector for the pageant named pipes
	if p.pageantPipe {
		go p.pipeProxy()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pageantWindow := p.createPageantWindow()
	if pageantWindow == 0 {
		log.Println(fmt.Errorf("CreateWindowEx failed: %v", win.GetLastError()))
		return
	}

	hglobal := win.GlobalAlloc(0, unsafe.Sizeof(win.MSG{}))
	defer win.GlobalFree(hglobal)
	//nolint:gosec
	msg := (*win.MSG)(unsafe.Pointer(hglobal))

	// main message loop
	for win.GetMessage(msg, pageantWindow, 0, 0) > 0 {
		win.TranslateMessage(msg)
		win.DispatchMessage(msg)
	}
}

const (
	// windows consts
	//revive:disable:var-naming,exported
	CRYPTPROTECTMEMORY_BLOCK_SIZE    = 16
	CRYPTPROTECTMEMORY_CROSS_PROCESS = 1
	FILE_MAP_ALL_ACCESS              = 0xf001f
	FILE_MAP_WRITE                   = 0x2

	// Pageant consts
	agentPipeName   = `\\.\pipe\pageant.%s.%s`
	agentCopyDataID = 0x804e50ba
	wndClassName    = "Pageant"
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectMemory = crypt32.NewProc("CryptProtectMemory")

	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procOpenFileMappingA = modkernel32.NewProc("OpenFileMappingA")
	wndClassNamePtr, _   = syscall.UTF16PtrFromString(wndClassName)
)

// copyDataStruct is used to pass data in the WM_COPYDATA message.
// We directly pass a pointer to our copyDataStruct type, be careful that it matches the Windows type exactly
type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

func openFileMap(dwDesiredAccess, bInheritHandle uint32, mapNamePtr uintptr) (windows.Handle, error) {
	mapPtr, _, err := procOpenFileMappingA.Call(uintptr(dwDesiredAccess), uintptr(bInheritHandle), mapNamePtr)

	//Properly compare syscall.Errno to number, instead of naive (i18n-unaware) string comparison
	errno, ok := err.(syscall.Errno)
	if ok && errno == windows.ERROR_SUCCESS {
		err = nil
	}
	return windows.Handle(mapPtr), err
}

func doesPageantWindowExist() bool {
	return win.FindWindow(wndClassNamePtr, nil) != 0
}

func (p *Pageant) registerPageantWindow(hInstance win.HINSTANCE) (atom win.ATOM) {
	var wc win.WNDCLASSEX
	wc.Style = 0

	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = syscall.NewCallback(p.wndProc)
	wc.CbClsExtra = 0
	wc.CbWndExtra = 0
	wc.HInstance = hInstance
	wc.HIcon = win.LoadIcon(0, win.MAKEINTRESOURCE(win.IDI_APPLICATION))
	wc.HCursor = win.LoadCursor(0, win.MAKEINTRESOURCE(win.IDC_IBEAM))
	wc.HbrBackground = win.GetSysColorBrush(win.BLACK_BRUSH)
	wc.LpszMenuName = nil
	wc.LpszClassName = wndClassNamePtr
	wc.HIconSm = win.LoadIcon(0, win.MAKEINTRESOURCE(win.IDI_APPLICATION))

	return win.RegisterClassEx(&wc)
}

func (p *Pageant) createPageantWindow() win.HWND {
	inst := win.GetModuleHandle(nil)
	atom := p.registerPageantWindow(inst)
	if atom == 0 {
		log.Println(fmt.Errorf("RegisterClass failed: %d", win.GetLastError()))
		return 0
	}

	// CreateWindowEx
	pageantWindow := win.CreateWindowEx(
		win.WS_EX_APPWINDOW,
		wndClassNamePtr,
		wndClassNamePtr,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		inst,
		nil,
	)

	return pageantWindow
}

func (p *Pageant) wndProc(hWnd win.HWND, message uint32, wParam uintptr, lParam uintptr) uintptr {
	switch message {
	case win.WM_COPYDATA:
		{
			copyData := (*copyDataStruct)(unsafe.Pointer(lParam))
			if copyData.dwData != agentCopyDataID {
				return 0
			}

			// 1. Validate the size of the incoming string data (map name).
			// Pageant map names are typically ~24 characters. Max path is 260.
			if copyData.cbData == 0 || copyData.cbData > 260 {
				log.Println("WM_COPYDATA cbData size out of bounds")
				return 0
			}

			if copyData.lpData == 0 {
				log.Println("WM_COPYDATA lpData is null")
				return 0
			}

			// 2. Create a bounded slice using the exact size provided by the OS
			mapNameSlice := unsafe.Slice((*byte)(unsafe.Pointer(copyData.lpData)), copyData.cbData)

			// 3. Convert to a Go string, safely stripping any trailing null bytes or garbage
			mapNameStr := strings.TrimRight(string(mapNameSlice), "\x00")

			// 4. Safely create a guaranteed null-terminated byte pointer for OpenFileMappingA
			mapNamePtr, err := windows.BytePtrFromString(mapNameStr)
			if err != nil {
				log.Println("Invalid map name format:", err)
				return 0
			}

			// 5. Pass our safely bounded and explicitly null-terminated pointer instead of lpData
			fileMap, err := openFileMap(FILE_MAP_ALL_ACCESS, 0, uintptr(unsafe.Pointer(mapNamePtr)))
			if err != nil {
				log.Println("openFileMap failed:", err)
				return 0
			}
			defer windows.CloseHandle(fileMap)

			// check security
			ourself, err := security.GetUserSID()
			if err != nil {
				log.Println(err)
				return 0
			}
			ourself2, err := security.GetDefaultSID()
			if err != nil {
				log.Println(err)
				return 0
			}
			mapOwner, err := security.GetHandleSID(fileMap)
			if err != nil {
				log.Println(err)
				return 0
			}
			if !windows.EqualSid(mapOwner, ourself) && !windows.EqualSid(mapOwner, ourself2) {
				return 0
			}

			// Passed security checks, copy data
			sharedMemory, err := windows.MapViewOfFile(fileMap, FILE_MAP_WRITE, 0, 0, 0)
			if err != nil {
				log.Println(err)
				return 0
			}
			defer windows.UnmapViewOfFile(sharedMemory)

			// 1. Query the actual size of the mapped memory region to prevent Out-Of-Bounds (OOB) access
			var mbi windows.MemoryBasicInformation
			err = windows.VirtualQuery(sharedMemory, &mbi, unsafe.Sizeof(mbi))
			if err != nil {
				log.Println("VirtualQuery failed:", err)
				return 0
			}

			// 2. Ensure the region is large enough to at least hold the 4-byte size header
			if mbi.RegionSize < 4 {
				log.Println("Mapped file is too small for a size header")
				return 0
			}

			// 3. Create a safe slice strictly bounded by the OS-reported region size
			mappedSlice := unsafe.Slice((*byte)(unsafe.Pointer(sharedMemory)), mbi.RegionSize)

			// 4. Safely read the size requested by the client
			msgSize := binary.BigEndian.Uint32(mappedSlice[:4])
			totalSize := uint64(msgSize) + 4 // +4 to account for the size uint itself

			// 5. Strict bounds checking
			if totalSize > openssh.AgentMaxMessageLength {
				log.Println("Declared message size exceeds application maximum")
				return 0
			}
			if uintptr(totalSize) > mbi.RegionSize {
				log.Println("Declared message size exceeds actual mapped memory")
				return 0
			}

			// 6. Query the windows OpenSSH agent via the windows named pipe
			result, err := p.PageantRequestHandler(p, mappedSlice[:totalSize])
			if err != nil {
				log.Printf("Error in PageantRequestHandler: %+v\n", err)
				return 0
			}

			// 7. Ensure we do not write out-of-bounds when copying the result back
			if uintptr(len(result)) > mbi.RegionSize {
				log.Println("Result payload exceeds mapped memory size")
				return 0
			}

			// Safely copy the result into the mapped memory slice
			copy(mappedSlice, result)

			// Zero-out the result buffer
			clear(result)

			return 1
		}
	case win.WM_DESTROY, win.WM_CLOSE, win.WM_QUIT, win.WM_QUERYENDSESSION:
		{ // Handle system shutdowns and process sigterms etc
			win.PostQuitMessage(0)
			return 0
		}
	}

	return win.DefWindowProc(hWnd, message, wParam, lParam)
}

func capiObfuscateString(realname string) string {
	cryptlen := len(realname) + 1
	cryptlen += CRYPTPROTECTMEMORY_BLOCK_SIZE - 1
	cryptlen /= CRYPTPROTECTMEMORY_BLOCK_SIZE
	cryptlen *= CRYPTPROTECTMEMORY_BLOCK_SIZE

	cryptdata := make([]byte, cryptlen)
	copy(cryptdata, realname)

	pDataIn := uintptr(unsafe.Pointer(&cryptdata[0]))
	cbDataIn := uintptr(cryptlen)
	dwFlags := uintptr(CRYPTPROTECTMEMORY_CROSS_PROCESS)

	//revive:disable:unhandled-error  - pageant ignores errors
	procCryptProtectMemory.Call(pDataIn, cbDataIn, dwFlags)

	hash := sha256.Sum256(cryptdata)
	return hex.EncodeToString(hash[:])
}

func (p *Pageant) pipeProxy() {
	currentUser, err := user.Current()
	if err != nil {
		log.Println(err)
	}

	parts := strings.Split(currentUser.Username, `\`)
	namePart := parts[len(parts)-1] // Gets the last item safely
	pipeName := fmt.Sprintf(agentPipeName, namePart, capiObfuscateString(wndClassName))
	config := &winio.PipeConfig{
		SecurityDescriptor: "D:(A;;GA;;;OW)", // Generic All to Owner only
	}
	listener, err := winio.ListenPipe(pipeName, config)
	if err != nil {
		log.Println(err)
	} else {
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Println(err)
				return
			}
			go p.pipeListen(conn)
		}
	}
}

func (p *Pageant) pipeListen(pageantConn net.Conn) {
	defer pageantConn.Close()
	reader := bufio.NewReader(pageantConn)

	for {
		lenBuf := make([]byte, 4)
		_, err := io.ReadFull(reader, lenBuf)
		if err != nil {
			return
		}

		bufferLen := binary.BigEndian.Uint32(lenBuf)
		if bufferLen > openssh.AgentMaxMessageLength {
			return // Reject and close connection
		}
		readBuf := make([]byte, bufferLen)
		_, err = io.ReadFull(reader, readBuf)
		if err != nil {
			return
		}

		result, err := p.PageantRequestHandler(p, append(lenBuf, readBuf...))
		if err != nil {
			log.Printf("Pipe: Error in PageantRequestHandler: %+v\n", err)
			return
		}

		_, err = pageantConn.Write(result)
		if err != nil {
			return
		}
	}
}
