include ../common.mk

# Create a docker image for the service and a docker image for running tests.
docker-image:
	docker build -t $(TEST_CA_DOCKER_IMAGE) --target test \
	-f Dockerfile ../../
	docker build -t $(CA_DOCKER_IMAGE) --rm -f Dockerfile ../../
	docker image prune -f
