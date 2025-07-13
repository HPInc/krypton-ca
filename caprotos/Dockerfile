###############################################################################
##                              Build stage
###############################################################################
FROM ghcr.io/hpinc/krypton/krypton-go-builder AS build-env

ADD . /go/src/caprotos
WORKDIR /go/src/caprotos

# build the source
RUN make build-proto

###############################################################################
##                              Packaging stage
###############################################################################
FROM scratch

WORKDIR /protos
COPY --from=build-env /go/src/caprotos/*.pb.go /protos/
