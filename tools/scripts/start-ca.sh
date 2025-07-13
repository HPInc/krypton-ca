#!/bin/bash
# Author: Mahesh Unnikrishnan
# Component: Krypton Certificate Authority
# (C) HP Development Company, LP
# Purpose:
# Script used to start the Krypton Certificate Authority.
NETWORK="krypton-net"
CA_CONTAINER_NAME="ca"
CA_IMAGE_NAME="krypton-ca"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# First check if the required AWS config environment variables are set.
if [[ -z "${AWS_ACCESS_KEY_ID}" ]]; then
  echo -n -e "${RED}Please specify the AWS_ACCESS_KEY_ID environment variable.${NC}"
  echo
  exit 1
fi

if [[ -z "${AWS_SECRET_ACCESS_KEY}" ]]; then
  echo -n -e "${RED}Please specify the AWS_SECRET_ACCESS_KEY environment variable.${NC}"
  echo
  exit 1
fi

echo -e "${GREEN}Shutting down existing containers and cleaning up network ...${NC}"
docker rm --force $CA_CONTAINER_NAME

# Create a docker network for the CA service.
echo "Setting up network for CA service ..."
docker network inspect $NETWORK >/dev/null 2>&1 \
  || docker network create $NETWORK

# Deploy the CA service docker container into the network.
echo -e "${GREEN}Starting the Krypton CA service ...${NC}"
docker run -d -p 6969:6969 -p 6970:6970 --net $NETWORK \
  -e GRPC_GO_LOG_VERBOSITY_LEVEL=99 -e GRPC_TRACE="all" \
  -e GO_DEBUG="http2debug=2" -e GRPC_GO_LOG_SEVERITY_LEVEL="info" \
  -e AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
  -e AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" -e AWS_REGION="us-west-2" \
  -e CA_KMS_PROVIDER="aws_kms" -e CA_CERT_STORE_PROVIDER="dynamodb" \
  --name $CA_CONTAINER_NAME $CA_IMAGE_NAME

echo "Waiting for container to start up ..."
sleep 5
retval=$(docker inspect -f "{{.State.Running}}" $CA_CONTAINER_NAME)
if [ "${retval[0]}" != true ]; then
  echo -e "${RED}Failed to start the Krypton CA service${NC}"
  exit 1
fi

docker ps --filter name=$CA_CONTAINER_NAME

# Determine the IP address of the CA container.
CA_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}.{{.IPAddress}}{{end}}' \
  $CA_CONTAINER_NAME)

echo -e "${GREEN}Krypton CA has been deployed into the docker network $NETWORK ${NC}"
echo -e " - Krypton CA IP address: $CA_IP"
