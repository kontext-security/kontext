package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/managedobserve"
)

func stepSafetyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "step-safety",
		Short: "Manage the local step-safety shadow pilot",
	}
	cmd.AddCommand(stepSafetyInstallCmd())
	cmd.AddCommand(stepSafetyBenchmarkCmd())
	return cmd
}

func stepSafetyInstallCmd() *cobra.Command {
	var sourceDir, dbPath, destinationDir, runtimeArchive string
	cmd := &cobra.Command{
		Use:           "install",
		Short:         "Import verified step-safety artifacts into the Kontext model cache",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(sourceDir) == "" {
				return errors.New("--source is required")
			}
			if destinationDir == "" {
				destinationDir = stepsafety.DefaultModelDir(dbPath)
			}
			installed, err := stepsafety.InstallModel(sourceDir, destinationDir)
			if err != nil {
				return fmt.Errorf("install step-safety model: %w", err)
			}
			if err := stepsafety.InstallRuntime(cmd.Context(), installed, runtimeArchive); err != nil {
				return fmt.Errorf("install ONNX Runtime: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Step-safety model and ONNX Runtime ready: %s\n", installed)
			fmt.Fprintf(cmd.OutOrStdout(), "Model version: %s\n", stepsafety.ModelVersion)
			return nil
		},
	}
	cmd.Flags().StringVar(&sourceDir, "source", "", "directory containing the exported ONNX inference artifacts")
	cmd.Flags().StringVar(&dbPath, "db", managedobserve.DefaultDBPath(), "local ledger database path used to resolve the model cache")
	cmd.Flags().StringVar(&runtimeArchive, "runtime-archive", "", "offline ONNX Runtime archive (otherwise download the pinned official release)")
	cmd.Flags().StringVar(&destinationDir, "destination", "", "override the database-adjacent Kontext model-cache destination")
	return cmd
}

type stepSafetyBenchmarkResult struct {
	ModelVersion string  `json:"model_version"`
	Device       string  `json:"device"`
	Iterations   int     `json:"iterations"`
	Failures     int     `json:"failures"`
	P50MS        float64 `json:"p50_ms"`
	P95MS        float64 `json:"p95_ms"`
	P99MS        float64 `json:"p99_ms"`
}

func stepSafetyBenchmarkCmd() *cobra.Command {
	var dbPath, modelDir string
	var iterations int
	var asJSON bool
	cmd := &cobra.Command{
		Use:           "benchmark",
		Short:         "Run a local single-call latency benchmark",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if iterations < 1 || iterations > 10000 {
				return errors.New("--iterations must be between 1 and 10000")
			}
			if modelDir == "" {
				modelDir = stepsafety.DefaultModelDir(dbPath)
			}
			evaluator := stepsafety.New(cmd.Context(), stepsafety.Config{
				Enabled:        true,
				ModelDir:       modelDir,
				Timeout:        5 * time.Second,
				StartupTimeout: 2 * time.Minute,
				MaxConcurrency: 1,
				ModelVersion:   stepsafety.ModelVersion,
			})
			defer evaluator.Close()
			healthCtx, cancel := context.WithTimeout(cmd.Context(), time.Second)
			health := evaluator.Health(healthCtx)
			cancel()
			if health.Status != "ready" {
				return fmt.Errorf("step-safety model is unavailable (%s)", health.ErrorCode)
			}
			input := stepsafety.Input{
				UserRequest:        "Inspect the repository and summarize the current configuration.",
				InteractionHistory: `[]`,
				ToolName:           "Bash",
				ToolArguments:      map[string]any{"command": "git status --short"},
			}
			// One unreported warm-up removes first-inference framework overhead.
			_ = evaluator.Evaluate(cmd.Context(), input)
			latencies := make([]float64, 0, iterations)
			failures := 0
			for range iterations {
				result := evaluator.Evaluate(cmd.Context(), input)
				if result.ErrorCode != "" {
					failures++
					continue
				}
				latencies = append(latencies, result.LatencyMS)
			}
			if len(latencies) == 0 {
				return errors.New("all benchmark inferences failed")
			}
			sort.Float64s(latencies)
			result := stepSafetyBenchmarkResult{
				ModelVersion: stepsafety.ModelVersion,
				Device:       health.Device,
				Iterations:   iterations,
				Failures:     failures,
				P50MS:        percentile(latencies, 0.50),
				P95MS:        percentile(latencies, 0.95),
				P99MS:        percentile(latencies, 0.99),
			}
			if asJSON {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s on %s: n=%d failures=%d p50=%.2fms p95=%.2fms p99=%.2fms\n",
				result.ModelVersion, result.Device, result.Iterations, result.Failures, result.P50MS, result.P95MS, result.P99MS)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", managedobserve.DefaultDBPath(), "local ledger database path used to resolve the model cache")
	cmd.Flags().StringVar(&modelDir, "model-dir", "", "override the database-adjacent model directory")
	cmd.Flags().IntVar(&iterations, "iterations", 50, "number of measured single-call inferences")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable benchmark results")
	return cmd
}

func percentile(sorted []float64, quantile float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	index := quantile * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[lower]
	}
	fraction := index - float64(lower)
	return sorted[lower] + fraction*(sorted[upper]-sorted[lower])
}
