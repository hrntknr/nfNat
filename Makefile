.PHONY: build_dp build_cp run test clean

GO          = go
GOOS        = linux
GOARCH      = amd64
GO111MODULE = on
GOFLAGS     = -count=1
GO_LDFLAGS  = -ldflags="-s -w"

GO_BUILD    = $(GO) build
GO_TEST     = $(GO) test -v

EXECUTABLES = bin/main
TARGETS     = $(EXECUTABLES)
GO_PKGROOT  = ./

all: build_dp build_cp run

build_dp:
	cd "$(shell pwd)/dp" && make

build_cp: $(TARGETS)	

run:
	./$(EXECUTABLES)

test: build_dp
	env GOOS=$(GOOS) GOARCH=$(GOARCH) GOFLAGS=$(GOFLAGS) $(GO_TEST) $(GO_PKGROOT)

clean:
	rm -rf $(TARGETS)
	cd "$(shell pwd)/dp" && make clean

bin/main: *.go
	env GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO_BUILD) $(GO_LDFLAGS) -o $@
