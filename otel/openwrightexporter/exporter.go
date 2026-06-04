package openwrightexporter

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

type openwrightExporter struct {
	url    string
	client *http.Client
}

func newOpenWrightExporter(cfg *Config) *openwrightExporter {
	return &openwrightExporter{
		url:    cfg.Endpoint + "/v1/traces",
		client: &http.Client{},
	}
}

// pushTraces marshals the spans to OTLP/protobuf and POSTs them to the OpenWright
// sink. Normalization, hashing, Merkle commit, and signing all happen in the
// Python core on the other side — this component never touches the crypto path.
func (e *openwrightExporter) pushTraces(ctx context.Context, td ptrace.Traces) error {
	body, err := ptraceotlp.NewExportRequestFromTraces(td).MarshalProto()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// The reference sink expects uncompressed OTLP/protobuf.
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("openwright sink returned HTTP %d", resp.StatusCode)
	}
	return nil
}
