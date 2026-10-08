package stepsafety

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
)

// The native backend consumes the original float32 checkpoint, without
// quantization, conversion through ONNX, or any change to its learned weights.
const nativeWeightsSHA256 = "429b09164c6705790c4414eb31c0bc18d2fa8a374bea467b2e1b49ead6aeb5f1"
const nativeWeightsBytes = 283201512

type nativeTensor struct {
	Shape []int
	Data  []float32
}

// readNativeWeights supports only the pinned checkpoint's F32 safetensors
// subset. Validate offsets and lengths before allocating, and verify the entire
// byte stream against the training pin before exposing any tensor to inference.
func readNativeWeights(ctx context.Context, source io.Reader) (map[string]nativeTensor, error) {
	digest := sha256.New()
	r := io.TeeReader(io.LimitReader(source, nativeWeightsBytes+1), digest)
	var headerSize uint64
	if err := binary.Read(r, binary.LittleEndian, &headerSize); err != nil {
		return nil, err
	}
	if headerSize == 0 || headerSize > 128*1024 {
		return nil, errors.New("invalid native model header size")
	}
	header := make([]byte, int(headerSize))
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(header, &raw); err != nil {
		return nil, err
	}
	delete(raw, "__metadata__")
	if len(raw) != 202 {
		return nil, errors.New("unexpected native model tensor count")
	}
	type spec struct {
		Name    string
		DType   string   `json:"dtype"`
		Shape   []int    `json:"shape"`
		Offsets [2]int64 `json:"data_offsets"`
	}
	entries := make([]spec, 0, len(raw))
	for name, data := range raw {
		entry := spec{Name: name}
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, err
		}
		size := int64(1)
		if entry.DType != "F32" || len(entry.Shape) < 1 || len(entry.Shape) > 2 {
			return nil, errors.New("unsupported native model tensor")
		}
		for _, dim := range entry.Shape {
			if dim <= 0 || dim > 128005 {
				return nil, errors.New("invalid native model dimension")
			}
			size *= int64(dim)
		}
		if entry.Offsets[0] < 0 || size*4 != entry.Offsets[1]-entry.Offsets[0] || entry.Offsets[1] > nativeWeightsBytes-int64(headerSize)-8 {
			return nil, errors.New("invalid native model offsets")
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b spec) int {
		if a.Offsets[0] < b.Offsets[0] {
			return -1
		}
		if a.Offsets[0] > b.Offsets[0] {
			return 1
		}
		return 0
	})
	result := make(map[string]nativeTensor, len(entries))
	buffer := make([]byte, 64*1024)
	var offset int64
	for _, entry := range entries {
		if entry.Offsets[0] != offset {
			return nil, errors.New("native model has overlapping or missing data")
		}
		values := make([]float32, (entry.Offsets[1]-offset)/4)
		for start := 0; start < len(values); {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			n := min(len(buffer)/4, len(values)-start)
			if _, err := io.ReadFull(r, buffer[:n*4]); err != nil {
				return nil, err
			}
			for i := 0; i < n; i++ {
				value := math.Float32frombits(binary.LittleEndian.Uint32(buffer[i*4:]))
				if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
					return nil, errors.New("non-finite native weight")
				}
				values[start+i] = value
			}
			start += n
		}
		result[entry.Name] = nativeTensor{Shape: entry.Shape, Data: values}
		offset = entry.Offsets[1]
	}
	if n, err := r.Read(buffer[:1]); n != 0 || err != io.EOF || offset+int64(headerSize)+8 != nativeWeightsBytes {
		return nil, errors.New("invalid native model length")
	}
	if hex.EncodeToString(digest.Sum(nil)) != nativeWeightsSHA256 {
		return nil, errors.New("native model checksum mismatch")
	}
	return result, nil
}

func nativeWeight(tensors map[string]nativeTensor, name string, shape ...int) ([]float32, error) {
	tensor, ok := tensors[name]
	if !ok || !slices.Equal(tensor.Shape, shape) {
		return nil, fmt.Errorf("unexpected native tensor %s", name)
	}
	return tensor.Data, nil
}
