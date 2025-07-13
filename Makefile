all: docker-image

# Build all the docker images required for the CA service.
docker-image:
	make -C service docker-image

# Run unit tests for the CA service in a docker-ized environment.
test:
	make -C service test

.PHONY: docker-image test
