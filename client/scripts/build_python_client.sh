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

echo "Using $PYTHON to create virtual env"
# activate venv
$PYTHON -m venv .venv
source .venv/bin/activate

python -m ensurepip

# install grpc packages
pip install grpcio grpcio-tools pyinstaller

# generate python bindings for the srte proto
python -m grpc_tools.protoc --proto_path=. proto/srte_policy_api.proto --python_out=. --grpc_python_out=.

# build python client
pyinstaller --onefile srte_client.py -p ./proto/

deactivate
mkdir bin
mv dist/srte_client bin/

#cleanup
rm -r dist
rm -r build
rm -r __pycache__
rm srte_client.spec
