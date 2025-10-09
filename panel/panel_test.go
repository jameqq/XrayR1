package panel

import "testing"

func TestBuildCoreConfigMapWithApiStatsPolicy(t *testing.T) {
	cfg := &Config{
		Api: map[string]any{
			"Tag":      "api",
			"Services": []any{"StatsService"},
		},
		Stats: map[string]any{},
		Policy: map[string]any{
			"Levels": map[string]any{
				"0": map[string]any{
					"StatsUserUplink":   true,
					"StatsUserDownlink": true,
				},
			},
		},
		Metrics: map[string]any{
			"Tag":    "Metrics",
			"Listen": "127.0.0.1:11111",
		},
	}

	final, err := buildCoreConfigMap(cfg)
	if err != nil {
		t.Fatalf("buildCoreConfigMap returned error: %v", err)
	}

	apiVal, ok := final["api"].(map[string]any)
	if !ok {
		t.Fatalf("expected api map in final config")
	}
	if tag, _ := apiVal["Tag"].(string); tag != "api" {
		t.Fatalf("unexpected api tag: %v", tag)
	}

	statsVal, ok := final["stats"].(map[string]any)
	if !ok {
		t.Fatalf("expected stats map in final config")
	}
	if len(statsVal) != 0 {
		t.Fatalf("expected empty stats map, got %v", statsVal)
	}

	policyVal, ok := final["policy"].(map[string]any)
	if !ok {
		t.Fatalf("expected policy map in final config")
	}
	levels, ok := policyVal["Levels"].(map[string]any)
	if !ok {
		t.Fatalf("expected Levels map in policy")
	}
	level0, ok := levels["0"].(map[string]any)
	if !ok {
		t.Fatalf("expected level 0 policy map")
	}
	if uplink, _ := level0["StatsUserUplink"].(bool); !uplink {
		t.Fatalf("expected StatsUserUplink true, got %v", level0["StatsUserUplink"])
	}
	if downlink, _ := level0["StatsUserDownlink"].(bool); !downlink {
		t.Fatalf("expected StatsUserDownlink true, got %v", level0["StatsUserDownlink"])
	}

	metricsVal, ok := final["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics map in final config")
	}
	if tag, _ := metricsVal["tag"].(string); tag != "Metrics" {
		t.Fatalf("unexpected metrics tag: %v", tag)
	}
	if listen, _ := metricsVal["listen"].(string); listen != "127.0.0.1:11111" {
		t.Fatalf("unexpected metrics listen: %v", listen)
	}
	if len(metricsVal) != 2 {
		t.Fatalf("expected only tag and listen in metrics, got %v", metricsVal)
	}

}
