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

}
