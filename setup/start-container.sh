#!/bin/bash

IMAGE_NAME="netem_challenge"
BASE_PORT=8000  # Student 1 will be at http://your-ip:8001, etc.

# Build the image first
docker build -t $IMAGE_NAME .

NR_OF_CONTAINERS=1

echo "Starting container ..."

# Generate unique name and port
CONTAINER_NAME="netem_container"
HOST_PORT=$((BASE_PORT + i))

# Run the container
docker run -d \
 --name "$CONTAINER_NAME" \
 -p "$HOST_PORT:7681" \
 --memory="512m" \
 --memory-swap="512m" \
 --cpus="0.5" \
 --pids-limit 50 \
 --restart unless-stopped \
 "$IMAGE_NAME"

echo "Started $CONTAINER_NAME on port $HOST_PORT"
