package main

import (
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
