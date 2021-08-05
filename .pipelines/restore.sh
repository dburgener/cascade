#!/bin/bash

# https://nickb.dev/blog/azure-pipelines-for-rust-projects
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y
echo "##vso[task.setvariable variable=PATH;]$PATH:$HOME/.cargo/bin"

# Needed for rust linking
yum -y install gcc
