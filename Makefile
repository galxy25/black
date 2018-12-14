all: test

lint :
	go vet ./...

test: lint
	go test -v -cover --race
