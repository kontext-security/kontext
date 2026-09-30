package stepsafety

// Inference reuses bounded scratch storage across layers and calls. In
// particular the six attention heads must not allocate 512x512 matrices on
// each of twelve layers. A pool also keeps independent callers race-free.
type nativeWorkspace struct {
	x, q, k, v, a, attention, intermediate []float32
	positions                              []int
	heads                                  [nativeHeads]nativeHeadWorkspace
}
type nativeHeadWorkspace struct {
	q, k, v, vt, packedK, packedV, result []float32
	scores, c2p, p2c                      []float32
}

func nativeBuffer(buffer []float32, n int) []float32 {
	if cap(buffer) < n {
		return make([]float32, n)
	}
	return buffer[:n]
}
func newNativeWorkspace() *nativeWorkspace {
	h := func() []float32 { return make([]float32, maxSequenceLength*nativeHidden) }
	w := &nativeWorkspace{x: h(), q: h(), k: h(), v: h(), a: h(), attention: h(), intermediate: make([]float32, maxSequenceLength*nativeIntermediate), positions: make([]int, maxSequenceLength*maxSequenceLength)}
	for i := range w.heads {
		s := func() []float32 { return make([]float32, maxSequenceLength*nativeHeadSize) }
		matrix := func() []float32 { return make([]float32, maxSequenceLength*maxSequenceLength) }
		w.heads[i] = nativeHeadWorkspace{q: s(), k: s(), v: s(), vt: s(), packedK: s(), packedV: s(), result: s(), scores: matrix(), c2p: matrix(), p2c: matrix()}
	}
	return w
}
