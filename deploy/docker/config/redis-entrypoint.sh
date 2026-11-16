#!/bin/sh
set -eu
# AuthGuard uses the Cluster protocol; local Compose assigns every slot to one node.
redis-server --save '' --appendonly no --requirepass "$REDIS_PASSWORD" \
  --masterauth "$REDIS_PASSWORD" --cluster-enabled yes \
  --cluster-config-file /tmp/nodes.conf --cluster-node-timeout 5000 &
redis_pid=$!
trap 'kill "$redis_pid" 2>/dev/null || true' INT TERM
until redis-cli --no-auth-warning -a "$REDIS_PASSWORD" ping >/dev/null 2>&1; do
  sleep 0.2
done
if ! redis-cli --no-auth-warning -a "$REDIS_PASSWORD" cluster info | grep -q 'cluster_slots_assigned:16384'; then
  redis-cli --no-auth-warning -a "$REDIS_PASSWORD" cluster addslotsrange 0 16383
fi
wait "$redis_pid"
