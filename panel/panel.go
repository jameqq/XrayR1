package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"dario.cat/mergo"
	"github.com/r3labs/diff/v2"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/bunpanel"
	"github.com/XrayR-project/XrayR/api/gov2panel"
	"github.com/XrayR-project/XrayR/api/newV2board"
	"github.com/XrayR-project/XrayR/api/pmpanel"
	"github.com/XrayR-project/XrayR/api/proxypanel"
	"github.com/XrayR-project/XrayR/api/sspanel"
	"github.com/XrayR-project/XrayR/api/v2raysocks"
	"github.com/XrayR-project/XrayR/app/mydispatcher"
	_ "github.com/XrayR-project/XrayR/cmd/distro/all"
	"github.com/XrayR-project/XrayR/service"
	"github.com/XrayR-project/XrayR/service/controller"
)

// Panel Structure
type Panel struct {
	access      sync.Mutex
	panelConfig *Config
	Server      *core.Instance
	Service     []service.Service
	Running     bool
}

func New(panelConfig *Config) *Panel {
	p := &Panel{panelConfig: panelConfig}
	return p
}

func structToMap(v interface{}) (map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func sliceStructsToMaps[T any](items []T) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		data, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, nil
}

func normalizeMetricsConfig(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	normalized := make(map[string]any, 2)
	for key, value := range src {
		switch strings.ToLower(key) {
		case "tag":
			normalized["tag"] = value
		case "listen":
			normalized["listen"] = value
		}
	}
	return normalized
}

func buildCoreConfigMap(panelConfig *Config) (map[string]any, error) {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if panelConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, panelConfig.LogConfig, logConfig); err != nil {
			log.Panicf("Read Log config failed: %s", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if panelConfig.DnsConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.DnsConfigPath); err != nil {
			log.Panicf("Failed to read DNS config file at: %s", panelConfig.DnsConfigPath)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Panicf("Failed to unmarshal DNS config: %s", panelConfig.DnsConfigPath)
			}
		}
	}

	// init controller's DNS config
	// for _, config := range p.panelConfig.NodesConfig {
	// 	config.ControllerConfig.DNSConfig = coreDnsConfig
	// }

	if _, err := coreDnsConfig.Build(); err != nil {
		return nil, fmt.Errorf("failed to understand DNS config: %w", err)
	}

	// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if panelConfig.RouteConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.RouteConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read routing config file %s: %w", panelConfig.RouteConfigPath, err)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal routing config %s: %w", panelConfig.RouteConfigPath, err)
			}
		}
	}
	if _, err := coreRouterConfig.Build(); err != nil {
		return nil, fmt.Errorf("failed to understand routing config: %w", err)
	}
	// Custom Inbound config
	var coreCustomInboundConfig []conf.InboundDetourConfig
	if panelConfig.InboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.InboundConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read custom inbound config file %s: %w", panelConfig.InboundConfigPath, err)
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom inbound config %s: %w", panelConfig.InboundConfigPath, err)
			}
		}
	}
	// Validate inbound configs
	for _, config := range coreCustomInboundConfig {
		if _, err := config.Build(); err != nil {
			return nil, fmt.Errorf("failed to understand inbound config: %w", err)
		}
	}
	var coreCustomOutboundConfig []conf.OutboundDetourConfig
	if panelConfig.OutboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.OutboundConfigPath); err != nil {
			return nil, fmt.Errorf("failed to read custom outbound config file %s: %w", panelConfig.OutboundConfigPath, err)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom outbound config %s: %w", panelConfig.OutboundConfigPath, err)
			}
		}
	}
	for _, config := range coreCustomOutboundConfig {
		if _, err := config.Build(); err != nil {
			return nil, fmt.Errorf("failed to understand outbound config: %w", err)
		}
	}
	// Policy config
	levelPolicyConfig := parseConnectionConfig(panelConfig.ConnectionConfig)
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	if _, err := corePolicyConfig.Build(); err != nil {
		return nil, fmt.Errorf("failed to understand policy config: %w", err)
	}

	final := make(map[string]any)

	if logMap, err := structToMap(coreLogConfig); err != nil {
		return nil, err
	} else if logMap != nil {
		final["log"] = logMap
	}

	if panelConfig.Stats != nil {
		final["stats"] = panelConfig.Stats
	}

	if panelConfig.Policy != nil {
		final["policy"] = panelConfig.Policy
	} else if policyMap, err := structToMap(corePolicyConfig); err != nil {
		return nil, err
	} else if policyMap != nil {
		final["policy"] = policyMap
	}

	if panelConfig.Api != nil {
		final["api"] = panelConfig.Api
	}

	if panelConfig.Metrics != nil {
		final["metrics"] = normalizeMetricsConfig(panelConfig.Metrics)
	}

	if dnsMap, err := structToMap(coreDnsConfig); err != nil {
		return nil, err
	} else if dnsMap != nil {
		final["dns"] = dnsMap
	}

	if routeMap, err := structToMap(coreRouterConfig); err != nil {
		return nil, err
	} else if routeMap != nil {
		log.Debugf("Routing rules: %v", routeMap["rules"])
		final["routing"] = routeMap
	}

	inbounds, err := sliceStructsToMaps(coreCustomInboundConfig)
	if err != nil {
		return nil, err
	}
	if len(inbounds) == 0 {
		final["inbounds"] = []map[string]any{}
	} else {
		final["inbounds"] = inbounds
	}

	outbounds, err := sliceStructsToMaps(coreCustomOutboundConfig)
	if err != nil {
		return nil, err
	}
	if len(outbounds) == 0 {
		final["outbounds"] = []map[string]any{}
	} else {
		final["outbounds"] = outbounds
	}

	return final, nil
}

func (p *Panel) loadCore(panelConfig *Config) *core.Instance {
	finalConfig, err := buildCoreConfigMap(panelConfig)
	if err != nil {
		log.Panicf("failed to build core config: %s", err)
	}

	if api, ok := finalConfig["api"].(map[string]any); ok {
		if tag, _ := api["tag"].(string); tag != "" {
			log.Infof("Injecting API config (tag=%s, services=%v)", tag, api["services"])
		} else {
			log.Infof("Injecting API config (services=%v)", api["services"])
		}
	}

	if _, ok := finalConfig["stats"]; ok {
		log.Info("Injecting Stats config")
	}

	if metrics, ok := finalConfig["metrics"].(map[string]any); ok {
		if listen, _ := metrics["listen"].(string); listen != "" {
			log.Infof("Injecting Metrics config (listen=%s)", listen)
		} else if tag, _ := metrics["tag"].(string); tag != "" {
			log.Infof("Injecting Metrics config (tag=%s)", tag)
		} else {
			log.Info("Injecting Metrics config")
		}
	}

	if pol, ok := finalConfig["policy"].(map[string]any); ok {
		if lv, ok := pol["levels"].(map[string]any); ok {
			keys := make([]string, 0, len(lv))
			for k := range lv {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			log.Infof("Injecting Policy config (levels=%v)", keys)
		} else {
			log.Info("Injecting Policy config (no levels)")
		}
	}

	configBytes, err := json.Marshal(finalConfig)
	if err != nil {
		log.Panicf("failed to marshal core config: %s", err)
	}
	cfgObj, err := core.LoadConfig("json", bytes.NewReader(configBytes))
	if err != nil {
		log.Panicf("failed to load core config: %s", err)
	}
	requiredApps := []*serial.TypedMessage{
		serial.ToTypedMessage(&mydispatcher.Config{}),
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}
	cfgObj.App = append(requiredApps, cfgObj.App...)
	server, err := core.New(cfgObj)
	if err != nil {
		log.Panicf("failed to create instance: %s", err)
	}
	if err := server.Start(); err != nil {
		log.Panicf("failed to start instance: %s", err)
	}
	return server
}

// Start the panel
func (p *Panel) Start() {
	p.access.Lock()
	defer p.access.Unlock()
	log.Print("Start the panel..")
	// Load Core
	server := p.loadCore(p.panelConfig)
	p.Server = server

	// Load Nodes config
	for _, nodeConfig := range p.panelConfig.NodesConfig {
		var apiClient api.API
		switch nodeConfig.PanelType {
		case "SSpanel":
			apiClient = sspanel.New(nodeConfig.ApiConfig)
		case "NewV2board", "V2board":
			apiClient = newV2board.New(nodeConfig.ApiConfig)
		case "PMpanel":
			apiClient = pmpanel.New(nodeConfig.ApiConfig)
		case "Proxypanel":
			apiClient = proxypanel.New(nodeConfig.ApiConfig)
		case "V2RaySocks":
			apiClient = v2raysocks.New(nodeConfig.ApiConfig)
		case "GoV2Panel":
			apiClient = gov2panel.New(nodeConfig.ApiConfig)
		case "BunPanel":
			apiClient = bunpanel.New(nodeConfig.ApiConfig)
		default:
			log.Panicf("Unsupport panel type: %s", nodeConfig.PanelType)
		}
		var controllerService service.Service
		// Register controller service
		controllerConfig := getDefaultControllerConfig()
		if nodeConfig.ControllerConfig != nil {
			if err := mergo.Merge(controllerConfig, nodeConfig.ControllerConfig, mergo.WithOverride); err != nil {
				log.Panicf("Read Controller Config Failed")
			}
		}
		controllerService = controller.New(server, apiClient, controllerConfig, nodeConfig.PanelType)
		p.Service = append(p.Service, controllerService)

	}

	// Start all the service
	for _, s := range p.Service {
		err := s.Start()
		if err != nil {
			log.Panicf("Panel Start failed: %s", err)
		}
	}
	p.Running = true
	return
}

// Close the panel
func (p *Panel) Close() {
	p.access.Lock()
	defer p.access.Unlock()
	for _, s := range p.Service {
		err := s.Close()
		if err != nil {
			log.Panicf("Panel Close failed: %s", err)
		}
	}
	p.Service = nil
	p.Server.Close()
	p.Running = false
	return
}

func parseConnectionConfig(c *ConnectionConfig) (policy *conf.Policy) {
	connectionConfig := getDefaultConnectionConfig()
	if c != nil {
		if _, err := diff.Merge(connectionConfig, c, connectionConfig); err != nil {
			log.Panicf("Read ConnectionConfig failed: %s", err)
		}
	}
	policy = &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connectionConfig.Handshake,
		ConnectionIdle:    &connectionConfig.ConnIdle,
		UplinkOnly:        &connectionConfig.UplinkOnly,
		DownlinkOnly:      &connectionConfig.DownlinkOnly,
		BufferSize:        &connectionConfig.BufferSize,
	}

	return
}
