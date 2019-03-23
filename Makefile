GO:=CGO_ENABLED=0 go

all:
	(cd ./cmd/ntskeserver; $(GO) build)
	(cd ./cmd/ntpserver; $(GO) build)
	(cd ./cmd/ntsclient; $(GO) build)
