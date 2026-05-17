#!/bin/bash
set -e

IMAGE="netem_challenge"
CONTAINER="netem_container"
INTERNAL_PORT=7681
HOST_PORT=8000
DASHBOARD_INTERNAL=9000
DASHBOARD_HOST=9000

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "  build    Build the Docker image (first time, takes ~15 min)"
    echo "  start    Start the container"
    echo "  stop     Stop and remove the container"
    echo "  update   Copy main.c into the running container and recompile (fast)"
    echo "  run      Run the netem app inside the container"
    echo "  shell    Open a shell inside the container"
    echo "  log      Show stats output (follow container logs)"
    echo "  result   Copy output.pcap from container to current directory"
    echo "  full     build + start + run (first-time setup)"
    echo "  quick    update + run (after code changes)"
    echo ""
}

container_running() {
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"
}

container_exists() {
    docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"
}

cmd_build() {
    echo "==> Building Docker image (this compiles DPDK, grab a coffee)..."
    docker build -t "$IMAGE" setup/
    echo "==> Done. Run: $0 start"
}

cmd_start() {
    if container_running; then
        echo "Container already running. Browser: http://localhost:$HOST_PORT"
        return
    fi
    if container_exists; then
        echo "==> Removing old container..."
        docker rm -f "$CONTAINER"
    fi
    echo "==> Starting container..."
    docker run -d \
        --name "$CONTAINER" \
        -p "$HOST_PORT:$INTERNAL_PORT" \
        -p "$DASHBOARD_HOST:$DASHBOARD_INTERNAL" \
        --memory="1g" \
        --cpus="2" \
        --restart unless-stopped \
        "$IMAGE"
    echo "==> Container started."
    echo "    Browser terminal: http://localhost:$HOST_PORT  (student / keysight2026)"
    echo "    NETEM dashboard:  http://localhost:$DASHBOARD_HOST  (starts when netem runs)"
    echo "    Shell:            $0 shell"
}

cmd_stop() {
    echo "==> Stopping container..."
    docker rm -f "$CONTAINER" 2>/dev/null && echo "Done." || echo "Container was not running."
}

cmd_update() {
    if ! container_running; then
        echo "Container is not running. Run: $0 start"
        exit 1
    fi
    echo "==> Copying source files into container..."
    for f in netem/main.c netem/http.c netem/http.h netem/netem.h netem/meson.build netem/run.sh; do
        docker cp "$f" "$CONTAINER":/home/student/challenge-app/"$f"
    done
    echo "==> Recompiling inside container..."
    docker exec "$CONTAINER" bash -c "cd /home/student/challenge-app/netem && ninja -C build"
    echo "==> Done. Run: $0 run"
}

cmd_run() {
    if ! container_running; then
        echo "Container is not running. Run: $0 start"
        exit 1
    fi
    echo "==> Running netem (Ctrl+C to stop)..."
    echo "    Reads:  /home/student/input.pcap"
    echo "    Writes: /home/student/output.pcap"
    echo ""
    docker exec -it "$CONTAINER" bash -c "
        su - student -c 'cd /home/student/challenge-app/netem && ./run.sh'
    "
}

cmd_shell() {
    if ! container_running; then
        echo "Container is not running. Run: $0 start"
        exit 1
    fi
    docker exec -it "$CONTAINER" bash
}

cmd_result() {
    if ! container_running; then
        echo "Container is not running."
        exit 1
    fi
    echo "==> Copying output.pcap from container..."
    docker cp "$CONTAINER":/home/student/output.pcap ./output.pcap
    echo "==> Saved to ./output.pcap"
    echo "    Open in Wireshark to inspect results."
}

case "${1:-}" in
    build)  cmd_build  ;;
    start)  cmd_start  ;;
    stop)   cmd_stop   ;;
    update) cmd_update ;;
    run)    cmd_run    ;;
    shell)  cmd_shell  ;;
    result) cmd_result ;;
    full)
        cmd_build
        cmd_start
        cmd_run
        ;;
    quick)
        cmd_update
        cmd_run
        ;;
    *)
        usage
        ;;
esac
