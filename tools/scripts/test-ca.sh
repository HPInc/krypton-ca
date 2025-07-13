#!/bin/bash
# Author: Mahesh Unnikrishnan
# Component: Krypton Certificate Authority
# (C) HP Development Company, LP
# Purpose:
# Script used to setup the test infrastructure for the Krypton Certificate
# Authority and execute unit tests. Tests are performed in a dockerized
# environment.
TEST_CONTAINER_NAME="ca-test"
DOCKER_COMPOSE="docker-compose"
PROJECT_NAME="ca"

GREEN='\033[0;32m'
NC='\033[0m'

pwd="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TEST_DOCKER_COMPOSE_FILE="$pwd/../../service/docker/docker-compose-test.yml"

# Try using the docker-compose utility, but fall back to 'docker compose' if
# not found. The CI build machines dont have docker-compose.
if ! command -v $DOCKER_COMPOSE &>/dev/null; then
  echo "The $DOCKER_COMPOSE command was not found. Trying docker compose"
  DOCKER_COMPOSE="docker compose"
fi

echo -e "${GREEN}Shutting down existing containers and cleaning up network ...${NC}"
docker rm --force $TEST_CONTAINER_NAME

# Bring up the CA test container and run the unit tests.
$DOCKER_COMPOSE -f "$TEST_DOCKER_COMPOSE_FILE" -p $PROJECT_NAME up \
  --exit-code-from ca-test
