package main

import (
	"encoding/json"
	"fmt"

	"aegis-runtime-sdk-go/aegisruntime"
)

func main() {
	event := aegisruntime.BuildRuntimeEvent()
	payload := map[string]string{
		"language":     "go",
		"signal_kind":  event.SignalKind,
		"connector_id": "gcp-audit-log",
	}
	bytes, _ := json.Marshal(payload)
	fmt.Println(string(bytes))
}
