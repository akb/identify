.PHONY: build test install;

build:
	go build -o bin/identify cmd/*.go

test:
	go test -v ./test/...

install:
	cp bin/identify /usr/local/bin/identify
