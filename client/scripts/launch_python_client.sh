#!/bin/bash

PYTHON=python3

check_version() {
    command -v python3.$1 > /dev/null 2>&1
    if [ $? == 0 ]; then
        PYTHON=python3.$1
    fi
}

# pick 3.6 or beyond python version
for ((i=6;i<=9;i++)); do
    check_version $i
done

#echo "Using $PYTHON to create virtual env"
# activate venv
$PYTHON -m venv .venv
source .venv/bin/activate

python -m ensurepip > /dev/null 2>&1

# install grpc packages
pip install grpcio grpcio-tools pyinstaller > /dev/null 2>&1

# generate python bindings for the srte proto
python -m grpc_tools.protoc --proto_path=. proto/srte_policy_api.proto --python_out=. --grpc_python_out=.

# python client
python srte_client.py "$@"

deactivate

#cleanup
rm -r __pycache__ > /dev/null 2>&1
rm -r proto/__pycache__ > /dev/null 2>&1

