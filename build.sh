#!/usr/bin/env bash

# Author: Ryan Tierney
# Date: 2022-12-22
# Purpose: Compile the Go source code using docker for any debian OS
# Notes: Update the operating_system variable in this script to compile on the debian OS of your choice
# The compiled binary will be saved in the projects working directory - save location is displayed at the end
# The docker image will not be removed. This can be used for local testing to simulate running the binary in the target OS.

set -euo pipefail

bin_name="promflow"
operating_system="debian:stretch"
pid="$$"
work_dir="$PWD"
image_name="${bin_name}"
container_name="${bin_name}_container_${pid}"

cleanup () {
    set +e
    rm "${bin_name}.tar"
    rm -rf go/
    docker rm "${container_name}" &> /dev/null
}
trap cleanup EXIT

sed -i "s/FROM .*/FROM ${operating_system}/" Dockerfile
docker build . -t ${image_name}
docker run --entrypoint="true" --name="${container_name}" "${image_name}"
docker export --output="${bin_name}.tar" "${container_name}"
tar --extract --file="${bin_name}.tar" "go/src/myproject/myproject"
mv go/src/myproject/myproject "${bin_name}"
echo "Binary built and saved to: ${work_dir}/${bin_name}"
echo "To test locally on ${operating_system}: docker run --net=host ${image_name} -h"

