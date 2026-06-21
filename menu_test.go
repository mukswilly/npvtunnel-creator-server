package main

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// TestConsoleRendersMainMenu runs the console against a tcell simulation
// screen and asserts the main menu actually drew — runtime render
// verification, not just construction. The frame is captured inside the
// draw callback (reading after Stop() would see a finalized/cleared screen).
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

	runErr := make(chan error, 1)
	go func() { runErr <- c.app.Run() }()
	c.app.QueueUpdateDraw(func() {}) // force a draw under the simulation screen
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

// renderConsoleScreen drives a console against a tcell simulation screen,
// optionally navigating to a screen first, and returns the rendered text. Used
// by the per-screen render tests so they don't each re-implement the harness.
func renderConsoleScreen(t *testing.T, c *console, navigate func()) string {
	t.Helper()
	// Switch to the target screen synchronously — page switches are just model
	// mutations, so doing it before Run avoids racing the initial draw.
	if navigate != nil {
		navigate()
	}
	sim := tcell.NewSimulationScreen("")
	if err := sim.Init(); err != nil {
		t.Fatalf("sim init: %v", err)
	}
	sim.SetSize(120, 40)
	c.app.SetScreen(sim)

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

	runErr := make(chan error, 1)
	go func() { runErr <- c.app.Run() }()
	c.app.QueueUpdateDraw(func() {}) // force a draw of the current front page
	time.Sleep(300 * time.Millisecond)
	c.app.Stop()
	if err := <-runErr; err != nil {
		t.Fatalf("app.Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return content
}

// TestConsoleRendersServerScreen drives the new Server lifecycle screen with
// injected fakes (no systemd, no network) and asserts it renders live state.
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
		"Server", "active", "issuer.alpha.example", "Identity", "pubkey",
		"Restart", "View logs", // privileged action buttons (canManage=true, running)
	} {
		if !strings.Contains(got, want) {
			t.Errorf("server screen missing %q\n---\n%s", want, got)
		}
	}
}

func TestServiceVerbCommand(t *testing.T) {
	// Root: invoke the binary directly.
	name, args := serviceVerbCommand(0, "/usr/local/bin/creator-server", "restart", nil)
	if name != "/usr/local/bin/creator-server" ||
		!reflect.DeepEqual(args, []string{"service", "restart"}) {
		t.Errorf("root: got %s %v", name, args)
	}
	// Non-root: go through sudo with the binary as the first arg.
	name, args = serviceVerbCommand(1000, "/usr/local/bin/creator-server", "start", nil)
	if name != "sudo" ||
		!reflect.DeepEqual(args, []string{"/usr/local/bin/creator-server", "service", "start"}) {
		t.Errorf("non-root: got %s %v", name, args)
	}
	// Extra args (e.g. install flags) are appended after the verb.
	_, args = serviceVerbCommand(0, "bin", "install", []string{"-tls", "builtin", "-domain", "h"})
	if !reflect.DeepEqual(args, []string{"service", "install", "-tls", "builtin", "-domain", "h"}) {
		t.Errorf("extra args: got %v", args)
	}
}
