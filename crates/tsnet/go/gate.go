package main

import "sync"

// gate lets a node's calls into Concord through until the node stops, then waits out those in
// flight: Concord frees what they reach once cts_stop returns. Every C.cts_call_* goes through
// one.
type gate struct {
	mu   sync.Mutex
	idle sync.Cond
	busy int
	shut bool
}

func newGate() *gate {
	g := &gate{}
	g.idle.L = &g.mu
	return g
}

func (g *gate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.shut {
		return false
	}
	g.busy++
	return true
}

func (g *gate) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.busy--
	if g.busy == 0 {
		g.idle.Broadcast()
	}
}

func (g *gate) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shut = true
	for g.busy > 0 {
		g.idle.Wait()
	}
}
