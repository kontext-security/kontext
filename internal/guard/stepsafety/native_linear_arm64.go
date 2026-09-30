//go:build arm64 && !purego

package stepsafety

import (
	"runtime"
	"sync"

	"gonum.org/v1/gonum/blas"
	"gonum.org/v1/gonum/blas/gonum"
)

// Pack each group of eight output columns together. The NEON kernel consumes
// four rows and eight columns without a C ABI, dynamic library, or cgo.
func prepareNativeLinear(l nativeLinear) nativeLinear {
	return prepareNativeLinearInto(l, nil)
}

func prepareNativeLinearInto(l nativeLinear, scratch []float32) nativeLinear {
	if l.out < 8 || len(l.weight) != l.in*l.out {
		return l
	}
	l.packed = nativeBuffer(scratch, (l.out+7)/8*8*l.in)
	for j := 0; j < l.out; j += 8 {
		for k := 0; k < l.in; k++ {
			for c := 0; c < 8; c++ {
				if j+c < l.out {
					l.packed[j*l.in+k*8+c] = l.weight[(j+c)*l.in+k]
				}
			}
		}
	}
	l.weight = nil
	return l
}

func nativeLinearProduct(l nativeLinear, x []float32, rows int) []float32 {
	return nativeLinearProductInto(l, x, rows, nil)
}

func nativeLinearProductInto(l nativeLinear, x []float32, rows int, scratch []float32) []float32 {
	if len(l.packed) == 0 {
		out := nativeBuffer(scratch, rows*l.out)
		gonum.Implementation{}.Sgemm(blas.NoTrans, blas.Trans, rows, l.out, l.in, 1, x, l.in, l.weight, l.in, 0, out, l.out)
		return out
	}
	padded := (rows + 3) / 4 * 4
	if rows != padded {
		if cap(x) >= padded*l.in {
			x = x[:padded*l.in]
		} else {
			temp := make([]float32, padded*l.in)
			copy(temp, x)
			x = temp
		}
	}
	stride := (l.out + 7) / 8 * 8
	out := nativeBuffer(scratch, padded*stride)
	workers := min(4, runtime.GOMAXPROCS(0), padded/4)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := worker * 4; i < padded; i += workers * 4 {
				for j := 0; j < l.out; j += 8 {
					nativeMatmul4x8(&x[i*l.in], &l.packed[j*l.in], &out[i*stride+j], l.in, stride)
				}
			}
		}(worker)
	}
	wg.Wait()
	if stride != l.out {
		for i := 0; i < rows; i++ {
			copy(out[i*l.out:(i+1)*l.out], out[i*stride:i*stride+l.out])
		}
	}
	return out[:rows*l.out]
}

//go:noescape
func nativeMatmul4x8(a, packedB, c *float32, k, strideC int)
