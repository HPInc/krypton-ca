GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILT_ON := $(shell hostname)
BUILD_DATE := $(shell date +%FT%T%z)

BINARY_NAME=caservice
PROTOS_DIR=.
PROTOC_PATH=/usr/local/bin
PROTOC_CMD=protoc
PROTOC_BUILD=$(PROTOC_PATH)/$(PROTOC_CMD)

# Docker images for the CA service.
CA_DOCKER_IMAGE=krypton-ca
CA_GHCR_IMAGE=ghcr.io/hpinc/krypton/$(CA_DOCKER_IMAGE)
TEST_CA_DOCKER_IMAGE=krypton-ca-test
