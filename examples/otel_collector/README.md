# Zero-code OpenTelemetry Collector integration (Option A)

Already running an OpenTelemetry Collector? Fork evidence to OpenWright **without
changing any application code** — add one exporter to your existing traces
pipeline. This is Option A from [docs/OTEL_PROCESSOR_SCOPE.md](../../docs/OTEL_PROCESSOR_SCOPE.md):
it works today, with no new components and no second collector process to run.

## How it works

The OpenTelemetry Collector natively fans out to every exporter in a pipeline.
You add `otlphttp/openwright` next to your existing backend exporter; the Collector
sends a copy of the telemetry to a `openwright collector` running as a **pure
evidence sink** (no downstream forwarding of its own). The fork is strictly
additive — a failing OpenWright sink degrades only the evidence copy, never your
primary telemetry.

```
your app --(OTLP)--> [ your OpenTelemetry Collector ]
                          |                 |
                          v                 v
                   your backend        openwright collector (sink)
                  (unchanged)          --> evidence ledger --> signed, verifiable pack
```

## Use it

1. Run the OpenWright sink:

   ```bash
   openwright collector --ledger-dir ./openwright-ledger
   ```

2. Add the `otlphttp/openwright` exporter from [`collector-config.yaml`](collector-config.yaml)
   to your existing Collector's traces pipeline, pointing at the sink.

3. Build a signed evidence pack from the ledger whenever you need one:

   ```bash
   openwright report ./openwright-ledger --key ./key.pem
   openwright verify ./openwright-out/report.json --pubkey ./key.pem
   ```

## Verify it for yourself

`verify_fanout.py` proves the whole path against a **real** collector: it boots
`otelcol-contrib` with the fan-out config, sends OTLP spans, and asserts (1) the
downstream backend received them unchanged, (2) OpenWright forked evidence, and
(3) a signed report verifies offline.

```bash
# Get a collector binary (once):
#   https://github.com/open-telemetry/opentelemetry-collector-releases/releases
OTELCOL_BIN=/path/to/otelcol-contrib \
    poetry run python examples/otel_collector/verify_fanout.py
```

Expected output:

```
PASS — zero-code OpenTelemetry Collector fan-out
  downstream spans     : 9 (forwarded unchanged)
  evidence events      : 9 (forked into the ledger)
  offline verification : VALID=True
  application changes  : none (collector config only)
```

If no collector binary is found, the script prints how to get one and exits 0.
