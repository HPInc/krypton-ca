###############################################################################
##                              Build stage
###############################################################################
FROM ghcr.io/hpinc/krypton/krypton-go-builder AS build-env

# Copy the source code over and build the CA binary.
ADD . /go/src/ca

# Copy the protocol buffers include files.
WORKDIR /go/src/ca/service
RUN cp -r /usr/local/include/google/ /go/src/ca/caprotos/
RUN make gosec build
RUN make build-test-binaries

###############################################################################
#                          Test Binary packaging stage
###############################################################################
FROM ghcr.io/hpinc/krypton/krypton-go-base AS test

WORKDIR /go/bin

COPY --from=build-env /go/src/ca/bin/ca/caservice.test .
COPY --from=build-env /go/src/ca/service/config/config.yaml .

ENTRYPOINT [ "/go/bin/caservice.test" ]

###############################################################################
##                              Packaging stage
###############################################################################
FROM ghcr.io/hpinc/krypton/krypton-go-base

# Create a lower privileged user account to run the service.
RUN adduser --disabled-password --gecos "" --home "/go/bin" \
    --shell "/sbin/nologin" --uid 1001 cacct
USER 1001

# set working directory
WORKDIR /go/bin

COPY --from=build-env /go/src/ca/bin/ca/caservice .
COPY --from=build-env /go/src/ca/service/config/config.yaml .

# Expose the gRPC port over which the CA service listens. HTTPS required.
EXPOSE 6969

# Expose the REST port over which the CA service listens.
EXPOSE 6970

# Start up the certificate authority.
ENTRYPOINT [ "/go/bin/caservice" ]
