# mcp-oauth-gateway — standard recipes (go module)

default:
    @just --list

# Download dependencies + install git hooks
setup:
    go mod download
    lefthook install

# Run the project locally
dev:
    go run .

# Run the test suite (race detector on)
test:
    go test -race ./...

# Static analysis: vet + golangci-lint (standard set)
lint:
    go vet ./...
    golangci-lint run

# Auto-format (gofmt + goimports via golangci-lint)
format:
    golangci-lint fmt

# Regenerate the table of all features in features/INDEX.md
features-index:
    sh scripts/features-index.sh write

# Raise each tool in mise.lock to the newest version of its major; Renovate does the
# same weekly where it runs and may execute mise.
bump-tools:
    mise lock --bump

# Full gate — must be green before every commit
check:
    sh scripts/features-index.sh check
    @unformatted="$(gofmt -l .)"; if [ -n "$unformatted" ]; then echo "not gofmt-clean:"; echo "$unformatted"; echo "Run: just format"; exit 1; fi
    go vet ./...
    golangci-lint run
    go build -o /dev/null ./...
    go test -race ./...
    just license-check

# Build all packages; programs land in bin/ (ignored by git), libraries only compile
build:
    GOBIN="$PWD/bin" go install ./...

# License gate (part of check): every dependency's license must be allowed in
# license-policy.txt. go-licenses (via mise) lists the libraries the code imports, tests
# left out; the project's own module is not checked.
license-check:
    #!/bin/sh
    set -eu
    report=$(mktemp)
    trap 'rm -f "$report" "$report.err" "$report.tsv"' EXIT
    if ! go-licenses report ./... > "$report" 2> "$report.err"; then
      cat "$report.err" >&2
      exit 1
    fi
    awk -v self="$(go list -m)" '{
      split($0, f, ","); lic = $0; sub(/^[^,]*,[^,]*,/, "", lic)
      if (f[1] != self && index(f[1], self "/") != 1) print f[1] "\t" lic
    }' "$report" > "$report.tsv"
    sh scripts/license-check.sh "$report.tsv"
