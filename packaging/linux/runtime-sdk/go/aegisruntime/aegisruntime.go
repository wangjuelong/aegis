package aegisruntime

const ContractVersion = "serverless.v1"

type RuntimeMetadata struct {
	Provider     string  `json:"provider"`
	Service      string  `json:"service"`
	Runtime      string  `json:"runtime"`
	Region       *string `json:"region"`
	AccountID    *string `json:"account_id"`
	InvocationID string  `json:"invocation_id"`
	ColdStart    bool    `json:"cold_start"`
	FunctionName *string `json:"function_name"`
	ContainerID  *string `json:"container_id"`
}

type RuntimeEvent struct {
	ContractVersion string          `json:"contract_version"`
	TenantID        string          `json:"tenant_id"`
	AgentID         string          `json:"agent_id"`
	SignalKind      string          `json:"signal_kind"`
	Metadata        RuntimeMetadata `json:"metadata"`
}

func BuildRuntimeEvent() RuntimeEvent {
	region := "ap-southeast-1"
	accountID := "123456789012"
	functionName := "orders-handler"
	return RuntimeEvent{
		ContractVersion: ContractVersion,
		TenantID:        "tenant-a",
		AgentID:         "runtime-sdk-go",
		SignalKind:      "HttpRequest",
		Metadata: RuntimeMetadata{
			Provider:     "AwsLambda",
			Service:      "orders-api",
			Runtime:      "go1.22",
			Region:       &region,
			AccountID:    &accountID,
			InvocationID: "invoke-1",
			ColdStart:    true,
			FunctionName: &functionName,
		},
	}
}
