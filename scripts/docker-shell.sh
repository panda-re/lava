#!/usr/bin/env bash
# Run the installed LAVA tools against a persistent host workspace.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: scripts/docker-shell.sh [OPTIONS] [-- COMMAND [ARG...]]

Without COMMAND, open an interactive bash shell.
  --runtime NAME    docker (default), apptainer, or singularity
  --image IMAGE     Default: pandare/lava:latest; HPC also accepts a local SIF
  --workspace DIR   Bind and work in DIR (default: current directory)
  --panda-cache DIR Docker: reuse DIR as ~/.panda (default: host ~/.panda if present)
  --network NAME    Docker network for reaching a PostgreSQL container
  --help            Show this help

Examples:
  scripts/docker-shell.sh
  scripts/docker-shell.sh -- lava-init
  scripts/docker-shell.sh --network lava -- lava -ak toy
  scripts/docker-shell.sh --runtime apptainer --image /scratch/lava.sif -- lava -tc toy

The workspace must contain target_bins/ and target_configs/ for lava-init.
Export POSTGRES_USER and POSTGRES_PASSWORD and set the database host/port in
workspace/host.json. This launcher does not start PostgreSQL or submit HPC jobs.
The old project-name-first interface has been replaced by -- COMMAND.
HELP
}

runtime=docker
image=pandare/lava:latest
workspace=$PWD
panda_cache=${HOME}/.panda
panda_cache_explicit=false
network=
while (($#)); do
    case $1 in
        --help|-h) usage; exit 0 ;;
        --runtime|--image|--workspace|--network|--panda-cache)
            if (($# < 2)) || [[ -z $2 ]]; then
                printf 'Missing value for %s\n' "$1" >&2; exit 2
            fi
            case $1 in
                --runtime) runtime=$2 ;;
                --image) image=$2 ;;
                --workspace) workspace=$2 ;;
                --panda-cache) panda_cache=$2; panda_cache_explicit=true ;;
                --network) network=$2 ;;
            esac
            shift 2 ;;
        --) shift; break ;;
        *) printf 'Unknown option: %s (use -- before a command)\n' "$1" >&2; exit 2 ;;
    esac
done
case $runtime in
    docker|apptainer|singularity) ;;
    *) printf 'Unsupported runtime: %s\n' "$runtime" >&2; exit 2 ;;
esac
if [[ $runtime != docker && -n $network ]]; then
    printf '%s uses host networking; --network is Docker-only\n' "$runtime" >&2
    exit 2
fi
if [[ $runtime != docker && $panda_cache_explicit == true ]]; then
    printf '%s uses its normal home mount; --panda-cache is Docker-only\n' "$runtime" >&2
    exit 2
fi
if [[ $panda_cache_explicit == true && ! -d $panda_cache ]]; then
    printf 'PANDA cache directory does not exist: %s\n' "$panda_cache" >&2
    exit 2
fi
command -v "$runtime" >/dev/null || { printf '%s is not on PATH\n' "$runtime" >&2; exit 127; }
workspace=$(cd -- "$workspace" && pwd -P)
# Both Docker --mount and HPC --bind reserve commas and colons in their syntax.
if [[ $workspace == *','* || $workspace == *':'* ]]; then
    printf 'Workspace paths containing commas or colons are unsupported\n' >&2; exit 2
fi
user_name=${USER:-$(id -un)}
command_args=("$@")
if ((${#command_args[@]} == 0)); then command_args=(bash); fi

if [[ $runtime == docker ]]; then
    # Keep a writable home, but reuse the host PANDA cache when available.
    mkdir -p -- "$workspace/.lava-container-home"
    args=(run --rm --init --user "$(id -u):$(id -g)"
        --mount "type=bind,source=$workspace,target=$workspace"
        --workdir "$workspace"
        --env "HOME=$workspace/.lava-container-home" --env "USER=$user_name"
        --env LANG=C.UTF-8)
    if [[ -d $panda_cache ]]; then
        panda_cache=$(cd -- "$panda_cache" && pwd -P)
        if [[ $panda_cache == *','* || $panda_cache == *':'* ]]; then
            printf 'PANDA cache paths containing commas or colons are unsupported\n' >&2; exit 2
        fi
        args+=(--mount "type=bind,source=$panda_cache,target=$workspace/.lava-container-home/.panda")
    fi
    if [[ -t 0 ]]; then args+=(-i); fi
    if [[ -t 0 && -t 1 ]]; then args+=(-t); fi
    if [[ -n $network ]]; then args+=(--network "$network"); fi
    # Pass values by name so credentials do not appear in command arguments.
    for name in POSTGRES_USER POSTGRES_PASSWORD HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
        if [[ -v $name ]]; then args+=(--env "$name"); fi
    done
    exec docker "${args[@]}" "$image" "${command_args[@]}"
else
    if [[ $image != docker://* && $image != *://* && ! -f $image ]]; then
        image="docker://$image"
    fi
    # Explicit overrides also work when the host has APPTAINERENV_* settings.
    exec "$runtime" exec --bind "$workspace:$workspace" --pwd "$workspace" \
        --env "USER=$user_name" "$image" "${command_args[@]}"
fi
