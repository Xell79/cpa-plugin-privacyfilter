package main

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var _ pluginapi.RequestLifecyclePlugin = (*privacyFilterPlugin)(nil)

// HandleRequestComplete releases request-scoped state. The initial
// implementation is intentionally a no-op; request cache cleanup is added with
// the changed-after lifecycle integration.
func (p *privacyFilterPlugin) HandleRequestComplete(context.Context, pluginapi.RequestCompletion) error {
	return nil
}
