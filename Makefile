GOBIN=$(shell pwd)/build

all:
	mkdir -p $(GOBIN)
	GOBIN=$(GOBIN) go install ./...
