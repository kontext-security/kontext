package managedstream

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func reconcileToolUsage(ctx context.Context, opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	store, err := sqlite.OpenStore(opts.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	store.SetHistoricalTurnRecovery(opts.AllowHistoricalTurnRecovery)
	cachePath := opts.EndpointConfigCachePath
	if cachePath == "" {
		cachePath = endpointconfig.DefaultCachePathForDB(opts.DBPath)
	}
	cache := endpointconfig.NewCacheForDB(cachePath, opts.DBPath)
	if err := cache.Load(); err == nil {
		snapshot := cache.Current()
		store.SetPayloadCaptureConfiguration(payloadcapture.RuntimeConfiguration{
			ConfiguredMode: snapshot.Configured.PayloadCaptureMode, EffectiveMode: snapshot.Config.PayloadCaptureMode,
			ConfigIdentity: snapshot.ConfigIdentity, Confirmed: snapshot.Confirmed,
			WorkTypeClassification: snapshot.Config.WorkTypeClassificationEnabled(),
		})
	}
	if opts.CaptureConfiguration != nil {
		store.SetPayloadCaptureConfiguration(opts.CaptureConfiguration())
	}
	return store.ReconcileToolUsage(ctx)
}

func flushToolUsage(ctx context.Context, opts Options) error {
	store, err := sqlite.OpenStore(opts.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	limit := 50
	for {
		records, err := store.PendingToolUsage(ctx, limit)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return nil
		}
		var sessionIDs []string
		for _, record := range records {
			sessionIDs = append(sessionIDs, record.SessionID)
		}
		sessions, err := store.AgentSessions(ctx, sessionIDs)
		if err != nil {
			return err
		}
		payload := newPayload(opts, sessions, nil, nil, nil, nil, time.Now().UTC())
		payload.ToolUsage = records
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if len(body) > MaxPayloadBytes {
			if limit == 1 {
				return fmt.Errorf("tool usage record exceeds upload limit")
			}
			limit = (limit + 1) / 2
			continue
		}
		if _, err := post(ctx, opts, body); err != nil {
			return err
		}
		if opts.OnFlushSuccess != nil {
			opts.OnFlushSuccess()
		}
		if err := store.AcknowledgeToolUsage(ctx, records); err != nil {
			return err
		}
	}
}
