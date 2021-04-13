#!/bin/bash
set -e
IMAGE="${IMAGE:-yat-partner}"
TAG="${TAG:-latest}"
DOCKER_BUILDKIT=1 docker build -t "$IMAGE:$TAG" --progress=plain .

if [ -n "$SSH_HOST" ]; then
  echo "Deploying to $SSH_HOST"
  docker save "$IMAGE:$TAG" | bzip2 | pv | ssh -o 'RemoteCommand=none' "$SSH_HOST"  'bunzip2 | docker load'
else
  echo 'Set $SSH_HOST to automatically deploy'
fi
