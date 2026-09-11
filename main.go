package main

import (
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var pluginVersion = "0.3.0-dev"

func buildPlugin(configYAML []byte, pluginDir string) (pluginapi.Plugin, error) {
	cfg, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}
	if pluginDir == "" {
		pluginDir = inferPluginDir()
	}

	p := &privacyFilterPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
	}

	engine, _, errEngine := newEngine(pluginDir, cfg)
	if errEngine != nil {
		return pluginapi.Plugin{}, errEngine
	}
	renderer, errRenderer := cfg.renderer()
	if errRenderer != nil {
		return pluginapi.Plugin{}, errRenderer
	}
	p.engine = engine
	p.renderer = renderer
	p.blockRuleIDs = cfg.blockRuleSet()

	return pluginapi.Plugin{
		SchemaVersion: implementedSchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "ahoo (fork of rheodev)",
			GitHubRepository: "https://github.com/ahoo/cpa-plugin-privacyfilter",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "gitleaks_toml",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Path to gitleaks.toml rules file. Empty uses built-in rules.",
				},
				{
					Name:        "skip_models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Model names to skip redaction for.",
				},
				{
					Name:        "skip_formats",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Source format names to skip redaction for.",
				},
			},
		},
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor:     p,
			RequestLifecyclePlugin: p,
		},
	}, nil
}
