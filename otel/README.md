# `openwright` — native OpenTelemetry Collector exporter (Option B)

A native, registry-listable OpenTelemetry Collector component. Add `openwright` to
a Collector you build, and it forks a copy of trace telemetry to an OpenWright
evidence sink — the operating model of any other OTel exporter.

This is Option B from [../docs/OTEL_PROCESSOR_SCOPE.md](../docs/OTEL_PROCESSOR_SCOPE.md).
By design it is a **thin forwarder**: normalization, hashing, the Merkle commit,
and signing all happen in the single byte-exact Python core on the sink side.
The component never touches the cryptographic path, so there is no second
implementation to keep in sync — a deliberate protection of the trust model.

## Layout

```
otel/
  openwrightexporter/      the exporter component (Go module)
    config.go            endpoint config + validation
    factory.go           component factory (type "openwright", traces)
    exporter.go          marshals ptrace -> OTLP, POSTs to the sink
  builder-config.yaml    OpenTelemetry Collector Builder (ocb) manifest
  _build/                built distribution (git-ignored)
```

## Build

Requires Go and the OpenTelemetry Collector Builder (`ocb`):

```bash
go install go.opentelemetry.io/collector/cmd/builder@v0.130.0
builder --config otel/builder-config.yaml         # -> otel/_build/openwright-otelcol
```

Confirm the component is present:

```bash
otel/_build/openwright-otelcol components | grep openwright
```

## Configure

```yaml
exporters:
  openwright:
    endpoint: http://127.0.0.1:4318   # where `openwright collector` (the sink) listens

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [openwright]           # add alongside your existing exporters
```

## Verify (incl. byte-identical conformance)

```bash
OPENWRIGHT_OTELCOL=otel/_build/openwright-otelcol \
    poetry run python examples/otel_collector/verify_native_exporter.py
```

It asserts evidence is forked through the native exporter, a report verifies
offline, and — critically — the Merkle leaf hashes are **byte-identical** to
evidence produced by ingesting the same spans directly through the Python core.

Verified output:

```
PASS — native OpenWright OpenTelemetry Collector exporter (Option B)
  evidence events      : 9 (forked via the native `openwright` exporter)
  offline verification : VALID=True
  byte-identical to Python core : True (9 leaf hashes match)
```
