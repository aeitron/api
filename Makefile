.PHONY: all build run test lint clean docker

PORT ?= 8000

all: test build

build:
	go build -o bin/api-gateway ./cmd/api-gateway

run:
	PORT=$(PORT) go run ./cmd/api-gateway

test:
	go test -v -race ./...

lint:
	gofmt -l .
	go vet ./...

docker:
	docker build -t aeitron/api:latest .

clean:
	rm -rf bin/
