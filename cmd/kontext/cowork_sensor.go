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
	var session string
	var duration time.Duration
	var maxEvents int
	collect := &cobra.Command{Use: "collect", Args: cobra.NoArgs, SilenceUsage: true, Short: "Attach to this VM session's future transcript tool results", RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, sensorStopSignal())
		defer cancel()
		return coworksensor.Collect(ctx, session, duration, maxEvents, cmd.OutOrStdout())
	}}
	collect.Flags().StringVar(&session, "session-id", "", "this task's transcript session UUID")
	collect.Flags().DurationVar(&duration, "duration", 3*time.Minute, "bounded observation duration (maximum 10m)")
	collect.Flags().IntVar(&maxEvents, "max-events", 1, "stop after this many completed VM Bash calls (1..100)")
	var observationSocket string
	status := &cobra.Command{Use: "status", Args: cobra.NoArgs, SilenceUsage: true, Short: "Query the running VM daemon identity and observation counters", RunE: func(cmd *cobra.Command, _ []string) error {
		return coworksensor.Status(cmd.Context(), observationSocket, cmd.OutOrStdout())
	}}
	status.Flags().StringVar(&observationSocket, "socket", "/run/kontext-cowork/observations.sock", "VM observation socket")
	cmd.AddCommand(run, check, collect, status)
	return cmd
}
