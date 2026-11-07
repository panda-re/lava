#!/usr/bin/env bash
# Run the installed LAVA tools against a persistent host workspace.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: scripts/docker-shell.sh [OPTIONS] [COMMAND [ARG...]]

Without COMMAND, open an interactive bash shell.
  --runtime NAME    docker (default), podman, apptainer, or singularity
  --image IMAGE     Default: pandare/lava:latest; HPC also accepts a local SIF
  --workspace DIR   Bind and work in DIR (default: current directory)
  --network NAME    Docker/Podman network (default: host)
  --env-file FILE   Docker/Podman environment file (default: workspace .env if present)
  --help            Show this help

Examples:
  scripts/docker-shell.sh
  scripts/docker-shell.sh lava-init
  scripts/docker-shell.sh --runtime podman --env-file .env lava-init
  scripts/docker-shell.sh --network lava lava -ak toy
  scripts/docker-shell.sh --runtime apptainer --image /scratch/lava.sif lava -tc toy

The workspace must contain target_bins/ and target_configs/ for lava-init.
Export POSTGRES_USER and POSTGRES_PASSWORD and set the database host/port in
workspace/host.json. This launcher does not start PostgreSQL or submit HPC jobs.
Launcher options precede COMMAND; -- before COMMAND is optional.
HELP
}

runtime=docker
image=pandare/lava:latest
workspace=$PWD
network=
env_file=
while (($#)); do
    case $1 in
        --help|-h) usage; exit 0 ;;
        --runtime|--image|--workspace|--network|--env-file)
            if (($# < 2)) || [[ -z $2 ]]; then
                printf 'Missing value for %s\n' "$1" >&2; exit 2
            fi
            case $1 in
                --runtime) runtime=$2 ;;
                --image) image=$2 ;;
                --workspace) workspace=$2 ;;
                --network) network=$2 ;;
                --env-file) env_file=$2 ;;
            esac
            shift 2 ;;
        --) shift; break ;;
        -*) printf 'Unknown launcher option: %s\n' "$1" >&2; exit 2 ;;
        *) break ;;
    esac
done
case $runtime in
    docker|podman|apptainer|singularity) ;;
    *) printf 'Unsupported runtime: %s\n' "$runtime" >&2; exit 2 ;;
esac
if [[ $runtime != docker && $runtime != podman && ( -n $network || -n $env_file ) ]]; then
    printf '--network and --env-file require Docker or Podman\n' >&2
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

if [[ $runtime == docker || $runtime == podman ]]; then
    if [[ -z $env_file && -f $workspace/.env ]]; then
        env_file=$workspace/.env
    fi
    # Reuse the standard host PANDA cache at the same path inside Docker.
    panda_cache=${HOME}/.panda
    mkdir -p -- "$panda_cache"
    if [[ $panda_cache == *','* || $panda_cache == *':'* ]]; then
        printf 'PANDA cache paths containing commas or colons are unsupported\n' >&2; exit 2
    fi
    mount_label=
    if [[ $runtime == podman ]]; then mount_label=,relabel=shared; fi
    args=(run --rm --init --user "$(id -u):$(id -g)"
        --mount "type=bind,source=$workspace,target=$workspace$mount_label"
        --mount "type=bind,source=$panda_cache,target=$panda_cache$mount_label"
        --workdir "$workspace"
        --env "HOME=$HOME" --env "USER=$user_name"
        --env LANG=C.UTF-8)
    # Rootless Podman must preserve host IDs for writable bind mounts.
    if [[ $runtime == podman ]]; then args+=(--userns=keep-id); fi
    if [[ -n $env_file ]]; then args+=(--env-file "$env_file"); fi
    if [[ -t 0 ]]; then args+=(-i); fi
    if [[ -t 0 && -t 1 ]]; then args+=(-t); fi
    args+=(--network "${network:-host}")
    # Pass values by name so credentials do not appear in command arguments.
    for name in POSTGRES_USER POSTGRES_PASSWORD HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
        if [[ -v $name ]]; then args+=(--env "$name"); fi
    done
    exec "$runtime" "${args[@]}" "$image" "${command_args[@]}"
else
    if [[ $image != docker://* && $image != *://* && ! -f $image ]]; then
        image="docker://$image"
    fi
    # Explicit overrides also work when the host has APPTAINERENV_* settings.
    exec "$runtime" exec --bind "$workspace:$workspace" --pwd "$workspace" \
        --env "USER=$user_name" "$image" "${command_args[@]}"
fi
