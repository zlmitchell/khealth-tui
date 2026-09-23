package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// consoleScreenBufferInfoEx is CONSOLE_SCREEN_BUFFER_INFOEX.
type consoleScreenBufferInfoEx struct {
	Size              uint32
	BufferSize        windows.Coord
	CursorPosition    windows.Coord
	Attributes        uint16
	Window            windows.SmallRect
	MaximumWindowSize windows.Coord
	PopupAttributes   uint16
	FullscreenSupport int32
	ColorTable        [16]uint32
}

var procGetCSBIEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleScreenBufferInfoEx")

// platformInfo prints the two answers Windows gives without asking the
// terminal: the console's color table (accurate in conhost, ConPTY's own
// defaults under Windows Terminal / VS Code) and the app light/dark setting.
func platformInfo() {
	var info consoleScreenBufferInfoEx
	info.Size = uint32(unsafe.Sizeof(info))
	h, _ := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if r, _, err := procGetCSBIEx.Call(uintptr(h), uintptr(unsafe.Pointer(&info))); r == 0 {
		fmt.Println("console color table: unavailable:", err)
	} else {
		fgi, bgi := info.Attributes&0xf, info.Attributes>>4&0xf
		fg, bg := info.ColorTable[fgi], info.ColorTable[bgi]
		fmt.Printf("console color table: text slot %d %s, background slot %d %s -> %s\n", fgi, hexRGB(fg), bgi, hexRGB(bg), verdict(rgbLum(bg) < 0.5))
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		fmt.Println("Windows app theme: unavailable:", err)
		return
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		fmt.Println("Windows app theme: unavailable:", err)
		return
	}
	fmt.Println("Windows app theme (AppsUseLightTheme):", verdict(v == 0))
}

func rgbLum(c uint32) float64 {
	return (0.2126*float64(c&0xff) + 0.7152*float64(c>>8&0xff) + 0.0722*float64(c>>16&0xff)) / 255
}

// enableVTOutput turns on escape-sequence processing for stdout, as
// bubbletea does; the queries are written as plain text otherwise.
func enableVTOutput() func() {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return func() {}
	}
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return func() {}
	}
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	return func() { _ = windows.SetConsoleMode(h, mode) }
}
