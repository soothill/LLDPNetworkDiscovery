.PHONY: build clean install

# Build the SNMP collector binary
build:
	go build -o snmp_collector snmp_collector.go

# Clean build artifacts
clean:
	rm -f snmp_collector go.sum

# Install Go dependencies
install:
	go mod download
	go mod tidy

# Build for different platforms
build-linux:
	GOOS=linux GOARCH=amd64 go build -o snmp_collector_linux snmp_collector.go

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -o snmp_collector_darwin snmp_collector.go

build-all: build-linux build-darwin
