.PHONY: build test install;

build:
	go build -o bin/identify cmd/*.go

test:
	go test -count=1 ./test/...

test-cmd:
	go test -v -count=1 ./test/cmd/...

test-web:
	go test -v -count=1 ./test/web/...

install:
	cp bin/identify /usr/local/bin/identify
