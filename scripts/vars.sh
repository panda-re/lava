#!/bin/sh
# Set all our environment variables
# $lava, $json, and  must be set prior to calling this

if [ -z ${project_name+x} ]; then
    echo "Fatal error: project_name variable unset when calling var.sh"
    exit 1;
fi

if [ -z ${lava+x} ]; then
    echo "Fatal error: lava variable unset when calling var.sh"
    exit 1;
fi

hostjson="$lava/host.json"
if [ ! -f $hostjson ]; then
    echo "Fatal error: host.json not found. Copy host.json.example to host.json"
    exit 1;
fi

# Host Vars
qemu="$(jq -r '.qemu' $hostjson)"
qcow_dir="$(jq -r '.qcow_dir // ""' $hostjson)"
output_dir="$(jq -r '.output_dir // ""' $hostjson)"
config_dir="$(jq -r '.config_dir // ""' $hostjson)/$project_name"
tar_dir="$(jq -r '.tar_dir // ""' $hostjson)"
db_suffix="$(jq -r '.db_suffix // ""' $hostjson)"
json="${config_dir}/$project_name.json"

if [ ! -f $json ]; then
    echo "Fatal error: $json not found. Did you provide the right project name?"
    exit 1;
fi

# Project specific
name="$(jq -r .name $json)"
db="$(jq -r .db $json)$db_suffix"
extradockerargs="$(jq -r .extra_docker_args $json)"
exitCode="$(jq -r .expected_exit_code $json)"
dataflow="$(jq -r '.dataflow // "false"' $json)" # TODO use everywhere, stop passing as argument

tarfiledir="$tar_dir"
tarfile="$tarfiledir/$(jq -r '.tarfile' $json)"
directory=$output_dir

inputs=`jq -r '.inputs' $json  | jq 'join (" ")' | sed 's/\"//g' `

fixupscript="null"
if [ "$(jq -r .fixupscript $json)" != "null" ]; then
    fixupscript="$config_dir/$(jq -r .fixupscript $json)"
fi

injfixupsscript="null"
if [ "$(jq -r .injfixupsscript $json)" != "null" ]; then
    injfixupsscript="$config_dir/$(jq -r .injfixupsscript $json)"
fi

buildhost="$(jq -r '.buildhost // "docker"' $json)"
pandahost="$(jq -r '.pandahost // "localhost"' $json)"
testinghost="$(jq -r '.testinghost // "docker"' $json)"
logs="$output_dir/$name/logs"

makecmd="$(jq -r .make $json)"
install=$(jq -r .install $json)
install="${install/\{config_dir\}/$config_dir}" # Format string replacement for config_dir
post_install="$(jq -r .post_install $json)"
install_simple=$(jq -r .install_simple $json)
configure_cmd=$(jq -r '.configure // "/bin/true"' $json)
container="$(jq -r '.docker // "lava32"' $json)"

# Constants
scripts="$lava/scripts"
python="/usr/bin/python"
pdb="/usr/bin/python -m pdb "
dockername="lava32"
