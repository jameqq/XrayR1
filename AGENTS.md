# Repository Guidelines

## Project Structure & Module Organization
The Go entry point is `main.go`, which forwards to the Cobra CLI in `cmd/`. Runtime orchestration, hot-reload logic, and configuration defaults live in `panel/`. Service adapters and controllers are under `service/`, while reusable helpers (rate limiting, ACME renewal, audit rules) reside in `common/`. API integrations for supported panels are grouped in `api/<panel>` and business logic for dispatching sits in `app/`. Reference configuration assets are in `release/config/`; update these whenever you adjust schema, defaults, or routing templates.

## Build, Test, and Development Commands
- `go build ./...` verifies the code compiles and catches missing dependencies. Use it before pushing.
- `go run . --config ./release/config/config.yml.example` launches the daemon with the sample config; provide a writable copy when testing live nodes.
- `go test ./...` runs the unit suite across `service`, `api`, `app`, and `common`. Add `-run <Name>` when iterating on a focused case.
- `docker build -t xrayr:dev .` produces the production image mirroring CI. Use `docker run --rm -v $(pwd)/release/config:/etc/XrayR xrayr:dev` to validate container behavior.

## Coding Style & Naming Conventions
Follow idiomatic Go formatting with `gofmt -w` (or `goimports`) before committing; tabs for indentation and CamelCase for exported identifiers are expected. Keep package-level variables private unless they form part of the public API, and prefer constructor helpers (e.g., `New...`) for complex structs. Configuration keys should match the canonical names in `panel/config.go`, and new files belong in the existing package layout unless you can justify a new top-level module.

## Testing Guidelines
Place tests beside implementation files using the `_test.go` suffix (e.g., `service/controller/controller_test.go`) and table-driven cases. When adding new backends or panel integrations, extend both happy-path and failure-path coverage, and ensure stats logic in `app/mydispatcher` remains exercised. Run `go test ./... -count=1` before every PR, and document any skipped tests in the PR body.

## Commit & Pull Request Guidelines
Recent history mixes short imperative subjects (`routing debug`) with Conventional Commits (`feat(panel): ...`). Default to `type(scope): summary` for clarity—for example, `fix(service): guard nil Stats map`—and keep the body to focused implementation notes. Each PR should outline the change intent, list test commands executed, flag any config migrations, and include screenshots or logs when touching panel flows. Reference related issues or discussions to ease triage.
