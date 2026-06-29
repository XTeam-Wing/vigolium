package runner

import (
	"context"
	"testing"
	"time"
)

// These tests guard the spidering phase's "per-target budget + overall ceiling"
// policy. Each target gets its own full max-duration, but the whole phase is
// bounded at max-duration × min(targets, spideringPhaseBudgetCap) so a large
// merged target list (CLI targets + many in-scope DB hosts) can't make the
// phase run for len(targets) × max-duration. Before this, runSpideringPhase
// created a fresh context.WithTimeout(ctx, maxDuration) per target with no
// overall bound.

// TestSpideringPhaseCeiling_Arithmetic pins the ceiling formula across the
// boundary cases: below cap (scales with targets), at/above cap (clamped), and
// the unlimited/empty sentinels (0 = "no ceiling").
func TestSpideringPhaseCeiling_Arithmetic(t *testing.T) {
	const md = 6 * time.Minute
	tests := []struct {
		name        string
		maxDuration time.Duration
		numTargets  int
		want        time.Duration
	}{
		{"single target", md, 1, md},
		{"few targets below cap", md, 3, 3 * md},
		{"exactly at cap", md, spideringPhaseBudgetCap, spideringPhaseBudgetCap * md},
		{"above cap is clamped", md, spideringPhaseBudgetCap + 50, spideringPhaseBudgetCap * md},
		{"unlimited max-duration => no ceiling", 0, 10, 0},
		{"negative max-duration => no ceiling", -1 * time.Second, 10, 0},
		{"zero targets => no ceiling", md, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := spideringPhaseCeiling(tt.maxDuration, tt.numTargets); got != tt.want {
				t.Fatalf("spideringPhaseCeiling(%s, %d) = %s, want %s",
					tt.maxDuration, tt.numTargets, got, tt.want)
			}
		})
	}
}

// TestSpideringPhaseCeiling_SkipsTargetsBeyondBudget models the phase loop: with
// more targets than the cap, the per-target budgets draw down the shared ceiling
// and the targets that don't fit are skipped rather than launched against an
// already-expired context. Durations are small; tolerances are generous so the
// test stays deterministic on slow CI.
func TestSpideringPhaseCeiling_SkipsTargetsBeyondBudget(t *testing.T) {
	const maxDuration = 40 * time.Millisecond
	const numTargets = spideringPhaseBudgetCap + 5 // deliberately over the cap

	ceiling := spideringPhaseCeiling(maxDuration, numTargets)
	if want := spideringPhaseBudgetCap * maxDuration; ceiling != want {
		t.Fatalf("ceiling = %s, want %s (clamped to the cap)", ceiling, want)
	}

	phaseCtx, phaseCancel := context.WithTimeout(context.Background(), ceiling)
	defer phaseCancel()

	start := time.Now()
	ran, skipped := 0, 0
	for i := 0; i < numTargets; i++ {
		if phaseCtx.Err() != nil {
			skipped = numTargets - i
			break
		}
		ran++
		// Mirror the real loop: per-target budget derives from phaseCtx, so it's
		// min(maxDuration, remaining ceiling). A "busy" target uses its whole slice.
		targetCtx, cancel := context.WithTimeout(phaseCtx, maxDuration)
		_ = runUntilCtxDone(targetCtx)
		cancel()
	}
	elapsed := time.Since(start)

	if skipped == 0 {
		t.Fatal("no targets were skipped — the overall ceiling did not bound the phase (the original bug)")
	}
	// Can't run more full budgets than the cap allows; allow a 1-target slack for
	// boundary timing.
	if ran > spideringPhaseBudgetCap {
		t.Fatalf("ran %d targets, exceeding the cap of %d — the ceiling was not enforced", ran, spideringPhaseBudgetCap)
	}
	if ran < spideringPhaseBudgetCap-1 {
		t.Fatalf("ran only %d targets; expected ~%d before the ceiling was reached", ran, spideringPhaseBudgetCap)
	}
	if skipped < numTargets-spideringPhaseBudgetCap {
		t.Fatalf("skipped %d targets, want at least %d", skipped, numTargets-spideringPhaseBudgetCap)
	}
	// The phase must not run meaningfully past the ceiling.
	if elapsed > ceiling+300*time.Millisecond {
		t.Fatalf("phase ran %s, exceeding the ceiling of %s", elapsed, ceiling)
	}
}

// TestSpideringPhaseCeiling_SmallListRunsAll confirms the common case is
// unaffected: when targets <= cap, every target runs (the ceiling is exactly
// targets × max-duration, so nothing is skipped).
func TestSpideringPhaseCeiling_SmallListRunsAll(t *testing.T) {
	const maxDuration = 30 * time.Millisecond
	const numTargets = 3 // well under the cap

	ceiling := spideringPhaseCeiling(maxDuration, numTargets)
	phaseCtx, phaseCancel := context.WithTimeout(context.Background(), ceiling)
	defer phaseCancel()

	ran, skipped := 0, 0
	for i := 0; i < numTargets; i++ {
		if phaseCtx.Err() != nil {
			skipped = numTargets - i
			break
		}
		ran++
		// Model a fast target so the small list never exhausts its generous budget.
		time.Sleep(time.Millisecond)
	}

	if skipped != 0 {
		t.Fatalf("skipped %d targets on a small list; none should be skipped", skipped)
	}
	if ran != numTargets {
		t.Fatalf("ran %d/%d targets; all should run when under the cap", ran, numTargets)
	}
}
