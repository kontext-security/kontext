//go:build race

package stepsafety

// raceSlowdown scales the budgets of tests that load the embedded model. The
// race detector instruments the standard library gzip decoder that unpacks
// the weights, which stretches a 7 s load past two minutes.
const raceSlowdown = 3
