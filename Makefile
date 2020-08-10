.PHONY: build test;

build:
	go build -o bin/identify cmd/*.go

test:
	go test -v ./test/...
