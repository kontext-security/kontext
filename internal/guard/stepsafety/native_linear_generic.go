//go:build !arm64 || purego

package stepsafety

import (
	"gonum.org/v1/gonum/blas"
	"gonum.org/v1/gonum/blas/gonum"
)

func prepareNativeLinear(l nativeLinear) nativeLinear                  { return l }
func prepareNativeLinearInto(l nativeLinear, _ []float32) nativeLinear { return l }

func nativeLinearProduct(l nativeLinear, x []float32, rows int) []float32 {
	return nativeLinearProductInto(l, x, rows, nil)
}
func nativeLinearProductInto(l nativeLinear, x []float32, rows int, scratch []float32) []float32 {
	out := nativeBuffer(scratch, rows*l.out)
	gonum.Implementation{}.Sgemm(blas.NoTrans, blas.Trans, rows, l.out, l.in, 1, x, l.in, l.weight, l.in, 0, out, l.out)
	return out
}
