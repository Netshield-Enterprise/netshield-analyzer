.PHONY: all build test clean install-deps run-server run-web

# Build everything
all: install-deps build

# Install Go dependencies
install-go-deps:
	go mod download

# Install Node dependencies
install-web-deps:
	cd web && npm install

# Install all dependencies
install-deps: install-go-deps install-web-deps

# Build Go binary
build-cli:
	go build -o netshield ./cmd/analyzer

# Build web frontend
build-web:
	cd web && npm run build

# Build both CLI and web UI
build: build-cli build-web
	@echo "✅ Build complete!"
	@echo "   CLI: ./netshield"
	@echo "   Web UI: ./netshield --serve"

# Run all tests
test:
	go test -v ./...

# Run web UI server (development)
run-server: build-cli
	./netshield --serve --project ./testdata/sample-project

# Run web development server with hot reload
run-web:
	cd web && npm run dev

# Clean build artifacts
clean:
	rm -f netshield
	rm -rf web/dist
	rm -rf web/node_modules

# Docker targets
docker-build:
	docker build -t netshield/analyzer:latest .
	@echo "✅ Docker image built: netshield/analyzer:latest"

docker-run:
	docker run -p 8080:8080 -v $(PWD)/testdata/sample-project:/project:ro netshield/analyzer:latest

docker-up:
	docker-compose up -d
	@echo "✅ NetShield running at http://localhost:8080"

docker-down:
	docker-compose down

docker-push:
	docker push netshield/analyzer:latest

# Generate demo license key
demo-key:
	@go run -ldflags="-X main.genKey=true" ./cmd/analyzer 2>/dev/null || \
	echo "NSPRO-DEMO-1234-5678"

# Help
help:
	@echo "NetShield Analyzer - Build Commands"
	@echo ""
	@echo "Usage:"
	@echo "  make install-deps  - Install all dependencies (Go + Node)"
	@echo "  make build        - Build CLI and web UI"
	@echo "  make test         - Run all tests"
	@echo "  make run-server   - Start web UI server"
	@echo "  make run-web      - Start development server with hot reload"
	@echo "  make clean        - Remove build artifacts"
	@echo ""
	@echo "Docker Commands:"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run container locally"
	@echo "  make docker-up    - Start with docker-compose"
	@echo "  make docker-down  - Stop docker-compose"
	@echo "  make docker-push  - Push to Docker Hub"
