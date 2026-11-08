//go:build windows

package appserver

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	readerUser32      = windows.NewLazySystemDLL("user32.dll")
	readerStation     = readerUser32.NewProc("GetProcessWindowStation")
	readerObjectInfo  = readerUser32.NewProc("GetUserObjectInformationW")
	readerAssociation = windows.NewLazySystemDLL("shlwapi.dll").NewProc("AssocQueryStringW")
)

func nativeReaderEnvironment() ReaderEnvironmentInfo {
	station, _, _ := readerStation.Call()
	if station == 0 {
		return ReaderEnvironmentInfo{"unknown", "unknown", "The process desktop session could not be determined"}
	}
	// USEROBJECTFLAGS uses two BOOLs and a DWORD. WSF_VISIBLE distinguishes an
	// interactive window station from service stations, without inferring from TTY.
	flags := struct{ Inherit, Reserved, Flags uint32 }{}
	var needed uint32
	ok, _, _ := readerObjectInfo.Call(station, 1, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 {
		return ReaderEnvironmentInfo{"unknown", "unknown", "The process desktop session could not be determined"}
	}
	if flags.Flags&1 == 0 {
		return ReaderEnvironmentInfo{"headless", "unknown", "This process has no visible interactive desktop"}
	}
	protocol, _ := windows.UTF16PtrFromString("http")
	verb, _ := windows.UTF16PtrFromString("open")
	var size uint32
	// ASSOCF_IS_PROTOCOL, ASSOCSTR_EXECUTABLE; query only, never ShellExecute.
	result, _, _ := readerAssociation.Call(0x1000, 2, uintptr(unsafe.Pointer(protocol)), uintptr(unsafe.Pointer(verb)), 0, uintptr(unsafe.Pointer(&size)))
	if result != 1 || size < 2 || size > 32768 {
		return ReaderEnvironmentInfo{"desktop", "unknown", "The default HTTP browser association could not be determined"}
	}
	value := make([]uint16, size)
	result, _, _ = readerAssociation.Call(0x1000, 2, uintptr(unsafe.Pointer(protocol)), uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(&value[0])), uintptr(unsafe.Pointer(&size)))
	if result != 0 {
		return ReaderEnvironmentInfo{"desktop", "unknown", "The default HTTP browser association could not be determined"}
	}
	if info, err := os.Stat(windows.UTF16ToString(value)); err != nil || info.IsDir() {
		return ReaderEnvironmentInfo{"desktop", "unavailable", "The default HTTP browser executable is unavailable"}
	}
	return ReaderEnvironmentInfo{"desktop", "available", "Interactive desktop and HTTP browser handler detected; opening is not yet verified"}
}
