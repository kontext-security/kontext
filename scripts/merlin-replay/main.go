package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kontext-security/kontext/internal/guard/stepsafety"
)

type replayRow struct {
	ID    string           `json:"id"`
	Input stepsafety.Input `json:"input"`
}

func decodeRow(data []byte) (replayRow, error) {
	var row replayRow
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&row); err != nil {
		return row, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values on one input line")
		}
		return row, err
	}
	return row, nil
}

// Merlin only evaluates these inputs; it never executes the supplied tool calls.
func main() {
	ctx := context.Background()
	evaluator := stepsafety.New(ctx, stepsafety.Config{Enabled: true, Timeout: 30 * time.Second, StartupTimeout: 30 * time.Second, MaxConcurrency: 1})
	health := evaluator.Health(ctx)
	if health.Status != "ready" {
		fmt.Fprintln(os.Stderr, "Merlin initialization failed:", health.ErrorCode)
		os.Exit(1)
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 65536), 4*1024*1024)
	output := json.NewEncoder(os.Stdout)
	for scan.Scan() {
		row, err := decodeRow(scan.Bytes())
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid input JSON:", err)
			os.Exit(1)
		}
		if row.Input.ToolName == "" {
			fmt.Fprintln(os.Stderr, "input.tool_name is required")
			os.Exit(1)
		}
		result := struct {
			ID         string                `json:"id"`
			Evaluation stepsafety.Evaluation `json:"evaluation"`
		}{row.ID, evaluator.Evaluate(ctx, row.Input)}
		if err := output.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := scan.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
