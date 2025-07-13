BINARY_DIR=../bin/ca

include common.mk

all: build docker-image
build: build-binaries

gosec:
	gosec ./...

# Generate golang files from the protobuf definitions.
build-proto:
	make -C ../caprotos build-proto

# Build the binaries for the service.
build-binaries: build-proto
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) \
	-ldflags "-X main.gitCommitHash=$(GIT_COMMIT) -X main.builtAt=$(BUILD_DATE) \
	-X main.builtBy=$(USER) -X main.builtOn=$(BUILT_ON)" \
	-o $(BINARY_DIR)/$(BINARY_NAME) -v
	cp -r config $(BINARY_DIR)/

# Resolve dependencies for the test.
testdeps:
	$(GOGET) google.golang.org/grpc/test/bufconn

# Build test binaries for the service.
build-test-binaries: build-proto testdeps
	@mkdir -p $(BINARY_DIR)
	make -C rpc build-test-binaries

# Create a docker image for the service.
docker-image:
	make -C docker docker-image

# Start the docker containers for the CA service and its dependencies.
start:
	bash ../tools/scripts/start-ca.sh

# Run unit tests for the CA in a docker-ized environment.
test:
	bash ../tools/scripts/test-ca.sh

tag:
	docker tag $(CA_DOCKER_IMAGE):latest $(CA_GHCR_IMAGE):latest

# Publish the CA docker image to Github.
publish: tag
	docker push $(CA_GHCR_IMAGE):latest

clean:
	$(GOCLEAN)
	docker rmi -f $(CA_DOCKER_IMAGE)
	docker image prune -f
	rm -rf $(BINARY_DIR)

.PHONY: docker-image build-proto build-binaries testdeps build-test-binaries test start publish clean
