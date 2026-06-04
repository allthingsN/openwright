# Publishing the OpenWright packages (B16)

These are **functional, locally-verified packages** — not name reservations. The
actual publish is an outward action performed by the maintainers with registry
credentials; the commands are recorded here so it is one step when ready.

## PyPI — `openwright-core` (the producer + verifier; imports as `openwright`)

New PyPI project (the rename to `openwright-core`). Before the first publish,
register a PyPI **pending publisher** (trusted publishing, OIDC — no token):
project `openwright-core`, owner `allthingsN`, repo `openwright`, workflow
`release.yml`, environment `pypi`. Then tag `v0.6.0` to trigger `release.yml`.
The release flow is gated by the clean-venv E2E check (V15):

```bash
scripts/clean_venv_e2e.sh      # must be green
poetry build                   # sdist + wheel (openwright_core-*.whl)
git tag v0.6.0 && git push origin v0.6.0   # release.yml publishes via OIDC
```

## npm — `openwright` (in-browser/WASM verifier library)

`packages/npm/openwright/` is a working ESM package: `verifyReport(report, pem)`
runs the audited single-file Python verifier inside Pyodide. Verified locally with
`npm pack` + `npm test` (verifies an honest report, rejects a tampered one).

```bash
cd packages/npm/openwright
npm install                    # pulls the Pyodide runtime
npm test                       # smoke test (needs fixtures/, generated from the Python package)
npm publish --access public    # needs an npm token + rights to the `openwright` name
```

> The package name `openwright` may need to be claimed/transferred on npm; that
> registry step requires maintainer credentials and is intentionally not automated.

## Go module — `github.com/allthingsN/openwright/core-go`

The Go evidence core is a standard Go module (no crates: there is no Rust core, so
the Go module proxy is the distribution path). Once the repository is public:

```bash
go get github.com/allthingsN/openwright/core-go@latest                       # library
go install github.com/allthingsN/openwright/core-go/cmd/openwright-core@latest  # CLI binary
```

Both build today against the local module (`go build ./...`, `go test ./...` green;
`openwright-core emit | openwright-core verify` round-trips). Publishing is simply
making the repo public + tagging a version; the Go proxy serves it automatically.
