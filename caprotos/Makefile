CA_PROTOS_DOCKER_IMAGE=krypton-caprotos
CA_PROTOS_GHCR_IMAGE=ghcr.io/hpinc/krypton/$(CA_PROTOS_DOCKER_IMAGE)

PROTOS_DIR=.
PROTOC_PATH=/usr/local/bin
PROTOC_CMD=protoc
PROTOC_BUILD=$(PROTOC_PATH)/$(PROTOC_CMD)

all: docker-image

build-proto:
	$(PROTOC_BUILD) -I $(PROTOS_DIR) \
	--go_out=paths=source_relative:$(PROTOS_DIR) \
	--go-grpc_out=paths=source_relative:$(PROTOS_DIR) \
	$(PROTOS_DIR)/ca.proto $(PROTOS_DIR)/ca_common.proto \
	$(PROTOS_DIR)/tenant_signing_cert.proto $(PROTOS_DIR)/device_cert.proto

docker-image:
	docker build -t $(CA_PROTOS_DOCKER_IMAGE) -f Dockerfile .

tag:
	docker tag $(CA_PROTOS_DOCKER_IMAGE):latest $(CA_PROTOS_GHCR_IMAGE):latest

publish: docker-image tag
	docker push $(CA_PROTOS_GHCR_IMAGE):latest

clean:
	docker rmi -f $(CA_PROTOS_DOCKER_IMAGE)
