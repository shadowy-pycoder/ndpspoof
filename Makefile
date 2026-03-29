APP_NAME=nf

.PHONY: all
all: build

.PHONY: build
build:
	CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o ./bin/${APP_NAME} ./cmd/${APP_NAME}/*.go
	sudo setcap cap_net_raw+ep ./bin/${APP_NAME}

.PHONY: test
test:
	go test ./... -v

.PHONY: clean
clean:
	find ./bin -type f -exec rm -vrf {} +

