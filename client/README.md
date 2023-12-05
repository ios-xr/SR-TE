## SRTE client

This repo contains an example Python client that can be used to excersise the RPCs defined in the srte proto file.
Any other language can be used for building the client by generating the corresponding language binding from the proto file.

### Building the client
Script at `./scripts/build_python_client.sh` can be used to build the client. Client gets built using the following steps:
* Enable python venv using python3.6 or higher version (python3.6 is pre-req, its is expected to be available on the server this client is being built)
* Within the virtual env, install grpcio, grpcio-tools and pyinstaller
* Generate the python bindings for proto/srte_policy_api.proto using protoc
* Run pyinstaller to build the executable
* Copy the executable to bin directory
* Cleanup

To build the executable, use following command from client directory:
`./scripts/build_python_client.sh`

### Executing the client:
```
> ./bin/srte_client -h
usage: srte_client [-h] (--policy-add | --policy-delete) -j JSON_REQUEST -a
                   ADDRESS [-u USERNAME] [-p PASSWORD] [-c CERT] [-k KEY]
                   [-C CA_CERT] [-S]

SRTE gRPC client

optional arguments:
  -h, --help            show this help message and exit

rpc:
  --policy-add          Send policy add request
  --policy-delete       Send policy delete request

request:
  -j JSON_REQUEST, --json-file JSON_REQUEST
                        JSON file containing request
  -a ADDRESS, --address ADDRESS
                        gRPC server address

credentials:
  -u USERNAME, --username USERNAME
                        User credentials
  -p PASSWORD, --password PASSWORD
                        User credentials

tls:
  -c CERT, --cert CERT  File containing client certificate
  -k KEY, --key KEY     File containing client private key
  -C CA_CERT, --ca-cert CA_CERT
                        Root certificates file for verifying the server
  -S, --strict          Perform hostname validation
```

### Lunch the python client without building it:

launch script provided starts the client in virtual enviroment to isolate installing of grpcio pacakages.

```
> ./scripts/launch_python_client.sh --policy-add -a <ip>:<port> -j testinput/srv6_explicit_path_request.json -u <username> -p <password>
Using python3.6 to create virtual env
Response: ['{"ReturnCode": 0, "Key": {"Color": 30, "Headend": "1:1::11", "Endpoint": "3:3::33"}}']
> 

```


Requirements
------------

Python >= 3.6

