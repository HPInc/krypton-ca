include ../common.mk
BINARY_DIR=../../bin/ca

# Build the test binary for the RPC tests.
build-test-binaries:
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOTEST) -c \
	-o $(BINARY_DIR)/$(BINARY_NAME).test

test: clean
	CGO_ENABLED=0 go test -v ./...

test-aws: clean
	KMS_PROVIDER=aws_kms CERT_STORE_PROVIDER=dynamodb CGO_ENABLED=0 go test -v ./...

clean:
	go clean -testcache
	@rm *.cert *.key *.db
