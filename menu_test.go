package main

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// The main menu renders its title, entries, and footer hints when drawn headlessly.
func TestConsoleRendersMainMenu(t *testing.T) {
	c, err := newConsole(t.TempDir())
	if err != nil {
		t.Fatalf("newConsole: %v", err)
	}
	sim := tcell.NewSimulationScreen("")
	if err := sim.Init(); err != nil {
		t.Fatalf("sim init: %v", err)
	}
	sim.SetSize(120, 40)
	c.app.SetScreen(sim)

	// Snapshot the flattened cell grid on each draw; the mutex guards the
	// handoff from the draw goroutine to the test goroutine.
	var mu sync.Mutex
	var content string
	c.app.SetAfterDrawFunc(func(screen tcell.Screen) {
		s, ok := screen.(tcell.SimulationScreen)
		if !ok {
			return
		}
		cells, w, h := s.GetContents()
		var sb strings.Builder
		for i := 0; i < w*h; i++ {
			for _, r := range cells[i].Runes {
				sb.WriteRune(r)
			}
		}
		mu.Lock()
		content = sb.String()
		mu.Unlock()
	})

	// Run the app, force one draw, give it time to paint, then stop.
	runErr := make(chan error, 1)
	go func() { runErr <- c.app.Run() }()
	c.app.QueueUpdateDraw(func() {})
	time.Sleep(300 * time.Millisecond)
	c.app.Stop()
	if err := <-runErr; err != nil {
		t.Fatalf("app.Run: %v", err)
	}

	mu.Lock()
	got := content
	mu.Unlock()
	if strings.TrimSpace(got) == "" {
		t.Fatal("console drew nothing")
	}
	for _, want := range []string{"creator-server", "Main menu", "Register a config", "Mint a share link", "F3"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered screen is missing %q", want)
		}
	}
}

// renderConsoleScreen optionally navigates the console, draws it onto a headless
// simulation screen, and returns the flattened text of the painted cells.
func renderConsoleScreen(t *testing.T, c *console, navigate func()) string {
	t.Helper()

	if navigate != nil {
		navigate()
	}
	sim := tcell.NewSimulationScreen("")
	if err := sim.Init(); err != nil {
		t.Fatalf("sim init: %v", err)
	}
	sim.SetSize(120, 40)
	c.app.SetScreen(sim)

	// Snapshot the flattened cell grid on each draw; the mutex guards the
	// handoff from the draw goroutine to the test goroutine.
	var mu sync.Mutex
	var content string
	c.app.SetAfterDrawFunc(func(screen tcell.Screen) {
		s, ok := screen.(tcell.SimulationScreen)
		if !ok {
			return
		}
		cells, w, h := s.GetContents()
		var sb strings.Builder
		for i := 0; i < w*h; i++ {
			for _, r := range cells[i].Runes {
				sb.WriteRune(r)
			}
		}
		mu.Lock()
		content = sb.String()
		mu.Unlock()
	})

	// Run the app, force one draw, give it time to paint, then stop.
	runErr := make(chan error, 1)
	go func() { runErr <- c.app.Run() }()
	c.app.QueueUpdateDraw(func() {})
	time.Sleep(300 * time.Millisecond)
	c.app.Stop()
	if err := <-runErr; err != nil {
		t.Fatalf("app.Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return content
}

// The server screen reflects injected status, domain, and key/action labels.
func TestConsoleRendersServerScreen(t *testing.T) {
	c, err := newConsole(t.TempDir())
	if err != nil {
		t.Fatalf("newConsole: %v", err)
	}
	c.svc = &fakeController{status: ServiceStatus{Active: true, ActiveState: "active", SubState: "running"}}
	c.health = fakeHealth{ok: true}
	c.port = fakePort{open: map[string]bool{"127.0.0.1:80": true, "127.0.0.1:443": true}}
	c.cert = fakeCert{exp: time.Now().Add(60 * 24 * time.Hour), known: true}
	c.canManage = true
	c.settings.Deployment = &deployment{SetupComplete: true, Domain: "issuer.alpha.example", TLSMode: "builtin"}

	got := renderConsoleScreen(t, c, c.showServer)
	for _, want := range []string{
		"Server", "active", "issuer.alpha.example", "public key", "pubkey",
		"Restart", "View logs",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("server screen missing %q\n---\n%s", want, got)
		}
	}
}

// serviceVerbCommand invokes the binary directly when root and wraps it in sudo
// otherwise, appending any extra arguments after the verb.
func TestServiceVerbCommand(t *testing.T) {

	// uid 0: run the binary directly.
	name, args := serviceVerbCommand(0, "/usr/local/bin/creator-server", "restart", nil)
	if name != "/usr/local/bin/creator-server" ||
		!reflect.DeepEqual(args, []string{"service", "restart"}) {
		t.Errorf("root: got %s %v", name, args)
	}

	// non-root uid: prefix with sudo.
	name, args = serviceVerbCommand(1000, "/usr/local/bin/creator-server", "start", nil)
	if name != "sudo" ||
		!reflect.DeepEqual(args, []string{"/usr/local/bin/creator-server", "service", "start"}) {
		t.Errorf("non-root: got %s %v", name, args)
	}

	// extra args follow the verb.
	_, args = serviceVerbCommand(0, "bin", "install", []string{"-tls", "builtin", "-domain", "h"})
	if !reflect.DeepEqual(args, []string{"service", "install", "-tls", "builtin", "-domain", "h"}) {
		t.Errorf("extra args: got %v", args)
	}
}
