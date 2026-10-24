# porthawk build tasks. Requires Go 1.24 or newer. No external dependencies.
VERSION ?= 1.3.0
BINARY  := porthawk
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet race fuzz fmt clean version report

# Build the binary into ./porthawk.
build:
	go build -o $(BINARY) .

# Build with the release version stamped in (shown by -version).
version:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

# Run the unit tests.
test:
	go test ./...

# Static checks: formatting, vet, and the race detector.
vet:
	test -z "$$(gofmt -l .)"
	go vet ./...

race:
	go test -race ./...

# Fuzz the parsers and banner cleaner, 30s per target.
fuzz:
	go test -run '^$$' -fuzz FuzzParsePorts -fuzztime 30s .
	go test -run '^$$' -fuzz FuzzParseTargets -fuzztime 30s .
	go test -run '^$$' -fuzz FuzzCleanBanner -fuzztime 30s .

fmt:
	gofmt -w .

clean:
	rm -f $(BINARY) report.html

# Scan localhost and write a self-contained HTML report to report.html.
# Only scan systems you own or are authorized to test.
report: build
	./$(BINARY) -t 127.0.0.1 -top 100 -f html -o report.html -q
