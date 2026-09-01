#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

container build --progress plain --file Containerfile --target relay --tag owntransit-relay:local .
container build --progress plain --file Containerfile --target connector --tag owntransit-connector:local .
container build --progress plain --file Containerfile --target connector-poc --tag owntransit-connector-poc:local .
container build --progress plain --file Containerfile --target client --tag owntransit-client:local .
container build --progress plain --file Containerfile --target certgen --tag owntransit-certgen:local .
container build --progress plain --file Containerfile --target certgen-poc --tag owntransit-certgen-poc:local .

echo "OwnTransit production-default and explicit POC Apple Container images built."
