# -----------------------------------------------------------------------------
# srte_client.py
#
# Rishi Desigan
# Copyright (c) 2022-2023 by Cisco Systems, Inc.
# All rights reserved.
# -----------------------------------------------------------------------------

import argparse
import json
import os
import sys

sys.path.append(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "proto")
)
from srte_client_helper import PolicyMsg, RPC, TLSCredentials, UserCredentials


def parse_args(args):
    parser = argparse.ArgumentParser(
        prog="srte_client", description="SRTE gRPC client"
    )
    rpc = parser.add_argument_group("rpc")
    rpc_group = rpc.add_mutually_exclusive_group(required=True)
    rpc_group.add_argument(
        "--policy-add",
        dest="add",
        action="store_true",
        help="Send policy add request",
    )
    rpc_group.add_argument(
        "--policy-delete",
        dest="delete",
        action="store_true",
        help="Send policy delete request",
    )
    request = parser.add_argument_group("request")
    request.add_argument(
        "-j",
        "--json-file",
        dest="json_request",
        type=str,
        required=True,
        help="JSON file containing request",
    )
    request.add_argument(
        "-a",
        "--address",
        dest="address",
        type=str,
        required=True,
        help="gRPC server address",
    )
    cred = parser.add_argument_group("credentials")
    cred.add_argument(
        "-u",
        "--username",
        dest="username",
        type=str,
        help="User credentials",
    )
    cred.add_argument(
        "-p",
        "--password",
        dest="password",
        type=str,
        help="User credentials",
    )
    tls = parser.add_argument_group("tls")
    tls.add_argument(
        "-c",
        "--cert",
        dest="cert",
        type=str,
        help="File containing client certificate",
    )
    tls.add_argument(
        "-k",
        "--key",
        dest="key",
        type=str,
        help="File containing client private key",
    )
    tls.add_argument(
        "-C",
        "--ca-cert",
        dest="ca_cert",
        type=str,
        help="Root certificates file for verifying the server",
    )
    tls.add_argument(
        "-S",
        "--strict",
        dest="strict",
        action="store_true",
        default=False,
        help="Perform hostname validation",
    )

    return parser.parse_args(args)


class PolicyRequest:
    def __init__(
        self,
        request: dict,
        address: str,
        cred: UserCredentials,
        tls: TLSCredentials,
    ) -> None:
        self.request = request
        self.address = address
        self._rpc = RPC(self.address, cred, tls)
        self._pol_msg = PolicyMsg.from_dict(self.request)

    def add(self):
        try:
            response = self._rpc.srte_policy_add(self._pol_msg)
            print("Response: {}".format(response))
            return response

        except Exception as e:
            sys.exit(e)

    def delete(self):
        response = None
        try:
            response = self._rpc.srte_policy_delete(self._pol_msg)
            print("Response: {}".format(response))
            return response

        except Exception as e:
            sys.exit(e)


def main():
    args = parse_args(sys.argv[1:])
    assert os.path.isfile(args.json_request), "File not found: {}".format(
        args.json_request
    )

    with open(args.json_request, "r") as json_req:
        request = json.load(json_req)

    credentials = None
    if args.username:
        credentials = UserCredentials(args.username, args.password)

    tls = None
    if args.cert or args.key or args.ca_cert:
        tls = TLSCredentials.from_file(
            args.cert, args.key, args.ca_cert, args.strict
        )

    policy_req = PolicyRequest(request, args.address, credentials, tls)

    if args.add:
        policy_req.add()

    else:
        policy_req.delete()


if __name__ == "__main__":
    main()

