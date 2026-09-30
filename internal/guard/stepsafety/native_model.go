package stepsafety

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
)

const (
	nativeHidden       = 384
	nativeHeads        = 6
	nativeHeadSize     = 64
	nativeIntermediate = 1536
	nativeLayers       = 12
	nativePositions    = 512
)

// This is the pinned DeBERTa-v3-xsmall evaluation graph, not a general-purpose
// transformer interpreter. Dropout is disabled; there are no token-type,
// absolute-position, convolution, or decoder layers in this checkpoint.
type nativeModel struct {
	embeddings         []float32
	embeddingNorm      nativeNorm
	layers             [nativeLayers]nativeLayer
	pooler, classifier nativeLinear
	work               sync.Pool
}
type nativeNorm struct{ weight, bias []float32 }
type nativeLinear struct {
	weight, bias []float32
	packed       []float32
	in, out      int
}
type nativeLayer struct {
	query, key, value, attention, intermediate, output nativeLinear
	attentionNorm, outputNorm                          nativeNorm
	relative                                           [nativeHeads]struct{ query, key nativeLinear }
}

func buildNativeModel(ctx context.Context, tensors map[string]nativeTensor) (*nativeModel, error) {
	m := &nativeModel{}
	var firstErr error
	weight := func(name string, shape ...int) []float32 {
		data, err := nativeWeight(tensors, name, shape...)
		if firstErr == nil {
			firstErr = err
		}
		return data
	}
	norm := func(name string) nativeNorm {
		return nativeNorm{weight(name+".weight", nativeHidden), weight(name+".bias", nativeHidden)}
	}
	linear := func(name string, in, out int) nativeLinear {
		return prepareNativeLinear(nativeLinear{weight: weight(name+".weight", out, in), bias: weight(name+".bias", out), in: in, out: out})
	}
	m.embeddings = weight("deberta.embeddings.word_embeddings.weight", 128005, nativeHidden)
	m.embeddingNorm = norm("deberta.embeddings.LayerNorm")
	rel := weight("deberta.encoder.rel_embeddings.weight", nativePositions, nativeHidden)
	relNorm := norm("deberta.encoder.LayerNorm")
	for i := range m.layers {
		p := fmt.Sprintf("deberta.encoder.layer.%d.", i)
		l := &m.layers[i]
		l.query = linear(p+"attention.self.query_proj", nativeHidden, nativeHidden)
		l.key = linear(p+"attention.self.key_proj", nativeHidden, nativeHidden)
		l.value = linear(p+"attention.self.value_proj", nativeHidden, nativeHidden)
		l.attention = linear(p+"attention.output.dense", nativeHidden, nativeHidden)
		l.attentionNorm = norm(p + "attention.output.LayerNorm")
		l.intermediate = linear(p+"intermediate.dense", nativeHidden, nativeIntermediate)
		l.output = linear(p+"output.dense", nativeIntermediate, nativeHidden)
		l.outputNorm = norm(p + "output.LayerNorm")
	}
	m.pooler = linear("pooler.dense", nativeHidden, nativeHidden)
	m.classifier = linear("classifier", nativeHidden, 2)
	if firstErr != nil {
		return nil, firstErr
	}
	// Relative embeddings and their projections depend only on weights. Cache
	// them once; every inference uses the same exact float32 parameters.
	rel = append([]float32(nil), rel...)
	relNorm.apply(rel, nil)
	for i := range m.layers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l := &m.layers[i]
		relQ, relK := l.query.apply(rel, nativePositions), l.key.apply(rel, nativePositions)
		for h := 0; h < nativeHeads; h++ {
			l.relative[h].query = prepareNativeLinear(nativeLinear{weight: nativeHead(relQ, nativePositions, h), in: nativeHeadSize, out: nativePositions})
			l.relative[h].key = prepareNativeLinear(nativeLinear{weight: nativeHead(relK, nativePositions, h), in: nativeHeadSize, out: nativePositions})
		}
	}
	return m, nil
}

func (l nativeLinear) apply(x []float32, rows int) []float32 {
	return l.applyInto(x, rows, nil)
}
func (l nativeLinear) applyInto(x []float32, rows int, scratch []float32) []float32 {
	out := nativeLinearProductInto(l, x, rows, scratch)
	for i := 0; i < rows; i++ {
		row := out[i*l.out : (i+1)*l.out]
		for j := range row {
			row[j] += l.bias[j]
		}
	}
	return out
}

func (norm nativeNorm) apply(x, residual []float32) {
	for start := 0; start < len(x); start += nativeHidden {
		row := x[start : start+nativeHidden]
		var mean float64
		for j := range row {
			if residual != nil {
				row[j] += residual[start+j]
			}
			mean += float64(row[j])
		}
		mean /= nativeHidden
		var variance float64
		for _, v := range row {
			d := float64(v) - mean
			variance += d * d
		}
		inv := float32(1 / math.Sqrt(variance/nativeHidden+1e-7))
		mu := float32(mean)
		for j := range row {
			row[j] = (row[j]-mu)*inv*norm.weight[j] + norm.bias[j]
		}
	}
}

func nativeGELU(x []float32) {
	for i, v := range x {
		x[i] = v * 0.5 * (1 + float32(math.Erf(float64(v)/math.Sqrt2)))
	}
}

// Trimming trailing masked padding is exact for this encoder: valid queries
// never attend to padding, and all other operations are per-token. Preserve
// every real token, its original position, and the checkpoint's relative buckets.
func nativeSequenceLength(packed packedInput) (int, error) {
	if len(packed.IDs) != maxSequenceLength || len(packed.Mask) != maxSequenceLength {
		return 0, errors.New("invalid native input shape")
	}
	n := 0
	for i, mask := range packed.Mask {
		if packed.IDs[i] < 0 || packed.IDs[i] >= 128005 {
			return 0, errors.New("invalid native token")
		}
		if mask == 1 && i == n {
			n++
		} else if mask != 0 {
			return 0, errors.New("non-contiguous native attention mask")
		}
	}
	if n == 0 {
		return 0, errors.New("empty native input")
	}
	return n, nil
}

func nativeRelativePosition(distance int) int {
	abs := distance
	if abs < 0 {
		abs = -abs
	}
	if abs <= 128 {
		return distance
	}
	// Mirror make_log_bucket_position(bucket_size=256,max_position=512).
	bucket := int(math.Ceil(math.Log(float64(abs)/128)/math.Log(511.0/128)*127)) + 128
	if distance < 0 {
		return -bucket
	}
	return bucket
}

func (m *nativeModel) infer(ctx context.Context, packed packedInput) (InferenceResult, error) {
	n, err := nativeSequenceLength(packed)
	if err != nil {
		return InferenceResult{}, err
	}
	w, ok := m.work.Get().(*nativeWorkspace)
	if !ok {
		w = newNativeWorkspace()
	}
	defer m.work.Put(w)
	x := w.x[:n*nativeHidden]
	for i, id := range packed.IDs[:n] {
		copy(x[i*nativeHidden:], m.embeddings[int(id)*nativeHidden:(int(id)+1)*nativeHidden])
	}
	m.embeddingNorm.apply(x, nil)
	positions := w.positions[:n*n]
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			positions[i*n+j] = min(max(nativeRelativePosition(i-j)+256, 0), 511)
		}
	}
	for _, l := range m.layers {
		if err := ctx.Err(); err != nil {
			return InferenceResult{}, err
		}
		q, k, v := l.query.applyInto(x, n, w.q), l.key.applyInto(x, n, w.k), l.value.applyInto(x, n, w.v)
		attention := w.attention[:n*nativeHidden]
		var wg sync.WaitGroup
		for head := 0; head < nativeHeads; head++ {
			wg.Add(1)
			go func(head int) {
				defer wg.Done()
				nativeAttention(ctx, q, k, v, l.relative[head].query, l.relative[head].key, positions, attention, n, head, &w.heads[head])
			}(head)
		}
		wg.Wait()
		if err := ctx.Err(); err != nil {
			return InferenceResult{}, err
		}
		a := l.attention.applyInto(attention, n, w.a)
		l.attentionNorm.apply(a, x)
		intermediate := l.intermediate.applyInto(a, n, w.intermediate)
		nativeGELU(intermediate)
		x = l.output.applyInto(intermediate, n, w.x)
		l.outputNorm.apply(x, a)
	}
	if err := ctx.Err(); err != nil {
		return InferenceResult{}, err
	}
	pooled := m.pooler.apply(x[:nativeHidden], 1)
	nativeGELU(pooled)
	logits := m.classifier.apply(pooled, 1)
	return InferenceResult{Logits: [2]float64{float64(logits[0]), float64(logits[1])}, HistoryOmitted: packed.HistoryOmitted}, nil
}

func nativeHead(x []float32, n, head int) []float32 {
	return nativeHeadInto(x, n, head, nil)
}
func nativeHeadInto(x []float32, n, head int, scratch []float32) []float32 {
	out := nativeBuffer(scratch, n*nativeHeadSize)
	for i := 0; i < n; i++ {
		copy(out[i*nativeHeadSize:], x[i*nativeHidden+head*nativeHeadSize:i*nativeHidden+(head+1)*nativeHeadSize])
	}
	return out
}

func nativeAttention(ctx context.Context, q, k, v []float32, relQ, relK nativeLinear, positions []int, output []float32, n, head int, w *nativeHeadWorkspace) {
	scale := float32(math.Sqrt(nativeHeadSize * 3))
	qh, kh, vh := nativeHeadInto(q, n, head, w.q), nativeHeadInto(k, n, head, w.k), nativeHeadInto(v, n, head, w.v)
	scores := nativeLinearProductInto(prepareNativeLinearInto(nativeLinear{weight: kh, in: nativeHeadSize, out: n}, w.packedK), qh, n, w.scores)
	c2p := nativeLinearProductInto(relK, qh, n, w.c2p)
	p2c := nativeLinearProductInto(relQ, kh, n, w.p2c)
	offset := head * nativeHeadSize
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			return
		}
		row := scores[i*n : (i+1)*n]
		largest := float32(-math.MaxFloat32)
		for j := range row {
			pos := positions[i*n+j]
			// p2c gathers (-relative_pos), then transposes the query/key axes;
			// for equal-length self attention this selects the same i-j bucket.
			row[j] = row[j]/scale + (c2p[i*nativePositions+pos]/scale + p2c[j*nativePositions+pos]/scale)
			if row[j] > largest {
				largest = row[j]
			}
		}
		var sum float32
		for j := range row {
			row[j] = float32(math.Exp(float64(row[j] - largest)))
			sum += row[j]
		}
		for j := range row {
			row[j] /= sum
		}
	}
	vt := w.vt[:n*nativeHeadSize]
	for i := 0; i < n; i++ {
		for j := 0; j < nativeHeadSize; j++ {
			vt[j*n+i] = vh[i*nativeHeadSize+j]
		}
	}
	result := nativeLinearProductInto(prepareNativeLinearInto(nativeLinear{weight: vt, in: n, out: nativeHeadSize}, w.packedV), scores, n, w.result)
	for i := 0; i < n; i++ {
		copy(output[i*nativeHidden+offset:], result[i*nativeHeadSize:(i+1)*nativeHeadSize])
	}
}
