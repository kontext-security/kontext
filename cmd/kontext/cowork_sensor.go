package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/kontext-security/kontext/internal/coworksensor"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/spf13/cobra"
)

func coworkSensorCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cowork-sensor", Short: "Run the internal observe-only Cowork sensor", Hidden: true}
	var configPath string
	run := &cobra.Command{
		Use: "run", Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := coworksensor.Load(configPath)
			if err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, sensorStopSignal())
			defer cancel()
			return coworksensor.Run(ctx, cfg, version, cmd.ErrOrStderr())
		},
	}
	run.Flags().StringVar(&configPath, "config", "/etc/kontext-cowork/config.json", "private sensor configuration")
	var socket string
	check := &cobra.Command{
		Use: "check", Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Second)
			defer cancel()
			client := localruntime.NewClient(socket)
			if _, err := client.Capabilities(ctx); err != nil {
				return fmt.Errorf("sensor not ready: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Cowork sensor socket is ready (observe-only)")
			return nil
		},
	}
	check.Flags().StringVar(&socket, "socket", "/run/kontext-cowork/sensor.sock", "sensor socket")
	cmd.AddCommand(run, check)
	return cmd
}
