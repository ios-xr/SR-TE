#!/bin/bash

# activate venv
python3.6 -m venv .venv
source .venv/bin/activate

# install grpc packages
pip install grpcio grpcio-tools

# generate python bindings for the srte proto
python -m grpc_tools.protoc --proto_path=. proto/srte_policy_api.proto --python_out=. --grpc_python_out=.

deactivate
