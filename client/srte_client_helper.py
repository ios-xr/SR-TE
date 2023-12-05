# -----------------------------------------------------------------------------
# srte_client_helper.py
#
# Rishi Desigan
# Copyright (c) 2022-2023 by Cisco Systems, Inc.
# All rights reserved.
# -----------------------------------------------------------------------------

# Standard
import contextlib
import ipaddress
import json
from enum import IntEnum
from typing import List

# Third-party
import grpc

# Proto bindings
import srte_policy_api_pb2
import srte_policy_api_pb2_grpc

__all__ = (
    "IPAddress",
    "SRv6BSIDBehavior",
    "PolicyKey",
    "CandidatePath",
    "ExplicitCP",
    "TEConstraints",
    "MetricMargin",
    "MarginType",
    "SegmentConstraints",
    "Affinities",
    "MetricBounds",
    "DynamicCP",
    "CPKey",
    "SIDStructure",
    "SegmentList",
    "Policy",
    "PolicyMsg",
    "RPC",
    "OptimizationMetric",
    "ReturnCode",
    "PolicyRsp",
    "PolicyOpRsp",
    "TLSCredentials",
    "UserCredentials",
)


class IPAddress:
    def __init__(self, addr_str: str) -> None:
        self.addr_str = addr_str
        self.v4 = False
        self.addr = None

        if self._is_ipv4_addr(addr_str):
            self.v4 = True
            self.addr = self._convert_v4_str_to_int(addr_str)
        elif self._is_ipv6_addr(addr_str):
            self.v4 = False
            self.addr = self._convert_v6_str_to_byte_str(addr_str)

    def _is_ipv4_addr(self, addr: str) -> bool:
        with contextlib.suppress(Exception):
            ipaddress.IPv4Address(addr)
            return True

        return False

    def _is_ipv6_addr(self, addr: str) -> bool:
        with contextlib.suppress(Exception):
            ipaddress.IPv6Address(addr)
            return True

        return False

    def _convert_v4_str_to_int(self, addr_str: str) -> int:
        return int(ipaddress.IPv4Address(addr_str))

    def _convert_v6_str_to_byte_str(self, addr_str: str) -> bytes:
        addr_int = int(ipaddress.IPv6Address(addr_str))
        addr_byte_array = (addr_int).to_bytes(16, byteorder="big")
        return addr_byte_array

    def to_pb(self) -> srte_policy_api_pb2.IpAddress:
        if self.v4:
            return srte_policy_api_pb2.IpAddress(v4=self.addr)
        else:
            return srte_policy_api_pb2.IpAddress(v6=self.addr)

    @classmethod
    def from_pb(cls, ipaddr: srte_policy_api_pb2.IpAddress):
        addr_str = None

        if ipaddr.v4:
            addr_str = str(ipaddress.IPv4Address(ipaddr.v4))

        if ipaddr.v6:
            addr_int = int.from_bytes(ipaddr.v6, byteorder="big")
            addr_str = str(ipaddress.IPv6Address(addr_int))

        self = cls(addr_str)
        return self


class SRv6BSIDBehavior:
    ALLOC_TYPE_DYNAMIC = srte_policy_api_pb2.BindingSIDAllocationMode.BSID_DYNAMIC
    UB6_INSERT_RED = 71
    UB6_ENCAPS_RED = 72

    def __init__(
        self,
        loc_name: str,
        behavior: int = UB6_INSERT_RED,
        alloc_type: int = ALLOC_TYPE_DYNAMIC,
    ) -> None:
        self.name = loc_name
        self.behavior = behavior
        self.type = alloc_type

    def to_pb(self) -> srte_policy_api_pb2.SRv6BindingSID:
        return srte_policy_api_pb2.SRv6BindingSID(
            locatorName=self.name, behavior=self.behavior
        )

    @classmethod
    def from_dict(cls, srv6_bsid: dict):
        loc_name = srv6_bsid.get("locatorName")
        behavior = srv6_bsid.get("behavior")

        self = cls(loc_name, behavior)
        return self


class PolicyKey:
    def __init__(self, color: int, endpoint: str, src: str) -> None:
        self.color = color
        self.endpoint = endpoint
        self.src = src

    def to_pb(self) -> srte_policy_api_pb2.PolicyKey:
        endpoint_pb = (
            IPAddress(self.endpoint).to_pb() if self.endpoint else None
        )
        headend_pb = IPAddress(self.src).to_pb() if self.src else None

        return srte_policy_api_pb2.PolicyKey(
            color=self.color,
            endpoint=endpoint_pb,
            headend=headend_pb,
        )

    @classmethod
    def from_dict(cls, key: dict):
        color = key.get("color")
        endpoint = key.get("endpoint")
        src = key.get("headend")

        self = cls(color, endpoint, src)
        return self

    @classmethod
    def from_pb(cls, key: srte_policy_api_pb2.PolicyKey):
        color = key.color
        src = key.headend
        endpoint = key.endpoint

        if src:
            src = IPAddress.from_pb(src).addr_str

        if endpoint:
            endpoint = IPAddress.from_pb(endpoint).addr_str

        self = cls(color, endpoint, src)
        return self

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, PolicyKey)
            and self.color == other.color
            and self.endpoint == other.endpoint
            and self.src == other.src
        )

    def __hash__(self) -> int:
        return hash((self.color, self.endpoint, self.src))


class SIDStructure:
    def __init__(
        self, block_len: int, node_len: int, func_len: int, arg_len: int
    ) -> None:
        self.block_len = block_len
        self.node_len = node_len
        self.func_len = func_len
        self.arg_len = arg_len

    @classmethod
    def from_sid(cls, sid: str):
        # Currently works only for F3216 SIDs.
        parsed = sid.split("::")[0].split(":")
        block = parsed[0] + ":" + parsed[1]
        nodeid = parsed[2] if len(parsed) > 2 else None
        function = parsed[3] if len(parsed) > 3 else None

        block_len = 32 if block else 0
        node_len = 16 if nodeid else 0
        func_len = 16 if function else 0
        arg_len = 128 - (block_len + node_len + func_len)

        self = cls(block_len, node_len, func_len, arg_len)
        return self

    def to_pb(self) -> srte_policy_api_pb2.Segment.TypeB.Structure:
        return srte_policy_api_pb2.Segment.TypeB.Structure(
            locatorBlockLength=self.block_len,
            locatorNodeLength=self.node_len,
            functionLength=self.func_len,
            argumentLength=self.arg_len,
        )


class SegmentList:
    def __init__(
        self, name: str, segments: list, weight: int = None, srv6: bool = True
    ) -> None:
        self.name = name
        self.segments = segments
        self.weight = weight
        self.is_srv6 = srv6

    def to_pb(self) -> srte_policy_api_pb2.SegmentList:
        if self.is_srv6:
            pb_segments = self._to_pb_srv6_segments()
        else:
            pb_segments = self._to_pb_mpls_segments()

        return srte_policy_api_pb2.SegmentList(
            name=self.name, segments=pb_segments, weight=self.weight
        )

    def _to_pb_srv6_segments(self) -> List[srte_policy_api_pb2.Segment]:
        pb_segments = list()
        for segment in self.segments:
            sid = IPAddress(segment)
            assert sid.v4 is False, "{} is not valid SRv6 SID".format(sid)

            sid_struct = SIDStructure.from_sid(sid.addr_str).to_pb()

            pb_segments.append(
                srte_policy_api_pb2.Segment(
                    typeB=srte_policy_api_pb2.Segment.TypeB(
                        SID=srte_policy_api_pb2.IPv6Address(v6=sid.addr),
                        structure=sid_struct,
                    )
                )
            )

        return pb_segments

    def _to_pb_mpls_segments(self) -> List[srte_policy_api_pb2.Segment]:
        pb_segments = list()
        for segment in self.segments:
            assert isinstance(
                segment, int
            ), "{} is not a valid MPLS label".format(segment)

            pb_segments.append(
                srte_policy_api_pb2.Segment(
                    typeA=srte_policy_api_pb2.Segment.TypeA(label=segment)
                )
            )

        return pb_segments

    @classmethod
    def from_dict(cls, sl: dict):
        name = sl.get("name")
        segments = sl.get("segments")
        weight = sl.get("weight")
        srv6 = False

        _segments = list()
        if segments:
            if "typeB" in segments:
                srv6 = True
                _segments = segments["typeB"]

            else:
                srv6 = False
                _segments = segments["typeA"]

        self = cls(name, _segments, weight, srv6)
        return self


class ExplicitCP:
    def __init__(self, sls: List[SegmentList]) -> None:
        self.sls = sls

    def to_pb(self) -> srte_policy_api_pb2.ExplicitCP:
        pb_sl = list()
        for sl in self.sls:
            pb_sl.append(sl.to_pb())

        return srte_policy_api_pb2.ExplicitCP(segmentList=pb_sl)

    @classmethod
    def from_dict(cls, explicit_cp: dict):
        segment_lists = list()
        for sl in explicit_cp:
            segment_lists.append(SegmentList.from_dict(sl.get("segmentList")))

        self = cls(segment_lists)
        return self


class OptimizationMetric(IntEnum):
    TE = srte_policy_api_pb2.OptimizationMetric.TE
    IGP = srte_policy_api_pb2.OptimizationMetric.IGP
    LATENCY = srte_policy_api_pb2.OptimizationMetric.Latency
    HOPS = srte_policy_api_pb2.OptimizationMetric.HOPS

    def __str__(self) -> str:
        if self.value == self.TE:
            return "TE"

        if self.value == self.IGP:
            return "IGP"

        if self.value == self.LATENCY:
            return "LATENCY"

        if self.value == self.HOPS:
            return "HOPCOUNT"

        return "Unknown: {}".format(self.name)


class MarginType(IntEnum):
    RELATIVE = srte_policy_api_pb2.DynamicCP.MetricMargin.MarginType.RELATIVE
    ABSOLUTE = srte_policy_api_pb2.DynamicCP.MetricMargin.MarginType.ABSOLUTE


class ProtectionType(IntEnum):
    PROTECTED_PREFERRED = (
        srte_policy_api_pb2.TEConstraints.SegmentConstraints.ProtectionType.PROTECTED_PREFERRED
    )
    PROTECTED_ONLY = (
        srte_policy_api_pb2.TEConstraints.SegmentConstraints.ProtectionType.PROTECTED_ONLY
    )
    UNPROTECTED_PREFERRED = (
        srte_policy_api_pb2.TEConstraints.SegmentConstraints.ProtectionType.UNPROTECTED_PREFERRED
    )
    UNPROTECTED_ONLY = (
        srte_policy_api_pb2.TEConstraints.SegmentConstraints.ProtectionType.UNPROTECTED_ONLY
    )

    def __str__(self) -> str:
        if self.value == self.PROTECTED_PREFERRED:
            return "protected-preferred"

        if self.value == self.PROTECTED_ONLY:
            return "protected-only"

        if self.value == self.UNPROTECTED_PREFERRED:
            return "unprotected-preferred"

        if self.value == self.UNPROTECTED_ONLY:
            return "unprotected-only"

        return "Unknown: {}".format(self.name)


class MetricMargin:
    def __init__(self, m_type: MarginType = None, value: int = None) -> None:
        self.type = m_type
        self.value = value

    def to_pb(self) -> srte_policy_api_pb2.DynamicCP.MetricMargin:
        return srte_policy_api_pb2.DynamicCP.MetricMargin(
            type=self.type, value=self.value
        )

    @classmethod
    def from_dict(cls, margins: dict):
        type = margins.get("type")
        value = margins.get("value")

        self = cls(type, value)
        return self


class Affinities:
    def __init__(
        self,
        include_any: List[str] = None,
        include_all: List[str] = None,
        exclude_any: List[str] = None,
    ) -> None:
        self.include_any = include_any
        self.include_all = include_all
        self.exclude_any = exclude_any

    def to_pb(self) -> srte_policy_api_pb2.TEConstraints.Affinities:
        return srte_policy_api_pb2.TEConstraints.Affinities(
            includeAny=self.include_any,
            includeAll=self.include_all,
            excludeAny=self.exclude_any,
        )

    @classmethod
    def from_dict(cls, affinities: dict):
        include_any = affinities.get("includeAny")
        include_all = affinities.get("includeAll")
        exclude_any = affinities.get("excludeAny")

        self = cls(include_any, include_all, exclude_any)
        return self


class MetricBounds:
    def __init__(
        self, igp: int = None, te: int = None, latency: int = None
    ) -> None:
        self.igp = igp
        self.te = te
        self.latency = latency

    def to_pb(self) -> srte_policy_api_pb2.TEConstraints.MetricBounds:
        return srte_policy_api_pb2.TEConstraints.MetricBounds(
            igp=self.igp, te=self.te, latency=self.latency
        )

    @classmethod
    def from_dict(cls, metric_bounds: dict):
        igp = metric_bounds.get("igp")
        te = metric_bounds.get("te")
        latency = metric_bounds.get("latency")

        self = cls(igp, te, latency)
        return self


class SegmentConstraints:
    def __init__(
        self,
        protection: ProtectionType = None,
        flexalgo: int = None,
        msd: int = None,
    ) -> None:
        self.protection = protection
        self.flexalgo = flexalgo
        self.msd = msd

    def to_pb(self) -> srte_policy_api_pb2.TEConstraints.SegmentConstraints:
        return srte_policy_api_pb2.TEConstraints.SegmentConstraints(
            protection=self.protection, flexalgo=self.flexalgo, MSD=self.msd
        )

    @classmethod
    def from_dict(cls, segment_constraints: dict):
        protection = segment_constraints.get("protection")
        flexalgo = segment_constraints.get("flexalgo")
        msd = segment_constraints.get("MSD")

        self = cls(protection, flexalgo, msd)
        return self


class TEConstraints:
    def __init__(
        self,
        affinities: Affinities = None,
        metric_bounds: MetricBounds = None,
        segment_constraints: SegmentConstraints = None,
    ) -> None:
        self.affinities = affinities
        self.metric_bounds = metric_bounds
        self.segment_constraints = segment_constraints

    def to_pb(self) -> srte_policy_api_pb2.TEConstraints:
        affinities_pb = self.affinities.to_pb() if self.affinities else None
        metric_bounds_pb = (
            self.metric_bounds.to_pb() if self.metric_bounds else None
        )
        segment_constraints_pb = (
            self.segment_constraints.to_pb()
            if self.segment_constraints
            else None
        )

        return srte_policy_api_pb2.TEConstraints(
            affinities=affinities_pb,
            metricBounds=metric_bounds_pb,
            segmentConstraints=segment_constraints_pb,
        )

    @classmethod
    def from_dict(cls, te_constrains: dict):
        affinities = te_constrains.get("affinities")
        metric_bounds = te_constrains.get("metricBounds")
        segment_constraints = te_constrains.get("segmentConstraints")

        if affinities:
            affinities = Affinities.from_dict(affinities)

        if metric_bounds:
            metric_bounds = MetricBounds.from_dict(metric_bounds)

        if segment_constraints:
            segment_constraints = SegmentConstraints.from_dict(
                segment_constraints
            )

        self = cls(affinities, metric_bounds, segment_constraints)
        return self


class DynamicCP:
    def __init__(
        self,
        ometric: OptimizationMetric = None,
        constraints: TEConstraints = None,
        metric_margin: MetricMargin = None,
        delegate: bool = False,
    ) -> None:
        self.ometric = ometric
        self.constraints = constraints
        self.metric_margin = metric_margin
        self.delegate = delegate

    def to_pb(self) -> srte_policy_api_pb2.DynamicCP:
        constraints_pb = self.constraints.to_pb() if self.constraints else None
        metric_margin_pb = (
            self.metric_margin.to_pb() if self.metric_margin else None
        )

        return srte_policy_api_pb2.DynamicCP(
            ometric=self.ometric,
            constraints=constraints_pb,
            metricMargin=metric_margin_pb,
            delegate=self.delegate,
        )

    @classmethod
    def from_dict(cls, dynamic_cp: dict):
        ometric = dynamic_cp.get("ometric")
        constraints = dynamic_cp.get("constraints")
        metric_margin = dynamic_cp.get("metricMargin")
        delegate = bool(dynamic_cp.get("delegate"))

        if constraints:
            constraints = TEConstraints.from_dict(constraints)

        if metric_margin:
            metric_margin = MetricMargin.from_dict(metric_margin)

        self = cls(ometric, constraints, metric_margin, delegate)
        return self


class CPKey:
    def __init__(
        self,
        originator_asn: int,
        originator_addr: str,
        originator_protocol: int,
        discriminator: int,
    ) -> None:
        self.asn = originator_asn
        self.addr = originator_addr
        self.protocol = originator_protocol
        self.discr = discriminator

    def to_pb(self) -> srte_policy_api_pb2.CandidatePathKey:
        return srte_policy_api_pb2.CandidatePathKey(
            originatorID=srte_policy_api_pb2.CandidatePathKey.OriginatorID(
                ASN=self.asn, nodeID=IPAddress(self.addr).to_pb()
            ),
            discriminator=self.discr,
            originatorProtocol=self.protocol,
        )

    @classmethod
    def from_dict(cls, cp_key: dict):
        asn = None
        addr = None
        protocol = cp_key.get("originatorProtocol")
        discriminator = cp_key.get("discriminator")
        originator_id = cp_key.get("originatorID")
        if originator_id:
            asn = originator_id.get("ASN")
            addr = originator_id.get("nodeID")

        self = cls(asn, addr, protocol, discriminator)
        return self


class CandidatePath:
    MPLS_DATAPLANE = srte_policy_api_pb2.Dataplane.MPLS
    SRv6_DATAPLANE = srte_policy_api_pb2.Dataplane.SRV6

    def __init__(
        self,
        pref: int = None,
        dataplane: int = None,
        key: CPKey = None,
        explicit_cp: ExplicitCP = None,
        dynamic_cp: DynamicCP = None,
        cp_name: str = None,
    ) -> None:
        self.pref = pref
        self.dataplane = dataplane
        self.key = key
        self.explicit_cp = explicit_cp
        self.dynamic_cp = dynamic_cp
        self.cp_name = cp_name

    def to_pb(self) -> srte_policy_api_pb2.CandidatePath:
        key_pb = self.key.to_pb() if self.key else None

        if self.explicit_cp:
            explicit_cp_pb = (
                self.explicit_cp.to_pb() if self.explicit_cp else None
            )
            return srte_policy_api_pb2.CandidatePath(
                key=key_pb,
                name=self.cp_name,
                preference=self.pref,
                dataplane=self.dataplane,
                explicit=explicit_cp_pb,
            )

        dynamic_cp_pb = self.dynamic_cp.to_pb() if self.dynamic_cp else None
        return srte_policy_api_pb2.CandidatePath(
            key=key_pb,
            name=self.cp_name,
            preference=self.pref,
            dataplane=self.dataplane,
            dynamic=dynamic_cp_pb,
        )

    @classmethod
    def from_dict(cls, cp: dict):
        pref = cp.get("preference")
        dataplane = cp.get("dataplane")
        name = cp.get("name")
        cp_key = None
        explicit_cp = None
        dynamic_cp = None

        if "key" in cp:
            cp_key = CPKey.from_dict(cp.get("key"))

        if "explicit" in cp:
            explicit_cp = ExplicitCP.from_dict(cp.get("explicit"))
        elif "dynamic" in cp:
            dynamic_cp = DynamicCP.from_dict(cp.get("dynamic"))

        self = cls(pref, dataplane, cp_key, explicit_cp, dynamic_cp, name)
        return self


class Policy:
    def __init__(
        self,
        key: PolicyKey = None,
        cps: List[CandidatePath] = None,
        bsid_alloc: int = None,
        mpls_bsid: int = None,
        srv6_bsid: SRv6BSIDBehavior = None,
    ) -> None:
        self.key = key
        self.cps = cps
        self.bsid_alloc = bsid_alloc
        self.mpls_bsid = mpls_bsid
        self.srv6_bsid = srv6_bsid

    def to_pb(self) -> srte_policy_api_pb2.Policy:
        cps_pb = list()
        if self.cps:
            for cp in self.cps:
                cps_pb.append(cp.to_pb())

        key_pb = self.key.to_pb() if self.key else None
        srv6_bsid_pb = self.srv6_bsid.to_pb() if self.srv6_bsid else None

        return srte_policy_api_pb2.Policy(
            key=key_pb,
            CPs=cps_pb,
            bindingSIDAllocation=self.bsid_alloc,
            mplsBindingSID=self.mpls_bsid,
            srv6BindingSID=srv6_bsid_pb,
        )

    @classmethod
    def from_dict(cls, policy: dict):
        key = policy.get("key")
        cps = policy.get("CPs")
        bsid_alloc = policy.get("bindingSIDAllocation")
        mpls_bsid = policy.get("mplsBindingSID")
        srv6_bsid = policy.get("srv6BindingSID")

        if key:
            key = PolicyKey.from_dict(key)

        if cps:
            _cps = list()
            for cp in cps:
                _cps.append(CandidatePath.from_dict(cp))

            cps = _cps

        if srv6_bsid:
            srv6_bsid = SRv6BSIDBehavior.from_dict(srv6_bsid)

        self = cls(key, cps, bsid_alloc, mpls_bsid, srv6_bsid)
        return self


class PolicyMsg:
    def __init__(self, policies: List[Policy]) -> None:
        self.policies = policies

    def to_pb(self) -> srte_policy_api_pb2.PolicyMsg:
        policies_pb = list()
        for policy in self.policies:
            policies_pb.append(policy.to_pb())

        return srte_policy_api_pb2.PolicyMsg(policies=policies_pb)

    @classmethod
    def from_dict(cls, policies: dict):
        policy_list = policies.get("policies")
        pol_objs = list()
        for policy in policy_list:
            pol_objs.append(Policy.from_dict(policy))

        self = cls(pol_objs)
        return self


class ReturnCode(IntEnum):
    SUCCESS = srte_policy_api_pb2.ReturnCode.SUCCESS
    FAILURE = srte_policy_api_pb2.ReturnCode.FAIL


class PolicyRsp:
    def __init__(self, return_code: int = None, key: PolicyKey = None) -> None:
        self.rc = return_code
        self.key = key

    @classmethod
    def from_pb(
        cls, rc: srte_policy_api_pb2.ReturnCode, key: srte_policy_api_pb2.PolicyKey
    ):
        key = PolicyKey.from_pb(key)

        self = cls(rc, key)
        return self

    def __repr__(self) -> str:
        response = dict()
        response = {
            "ReturnCode": self.rc,
            "Key": {
                "Color": self.key.color,
                "Headend": self.key.src,
                "Endpoint": self.key.endpoint,
            },
        }

        return json.dumps(response)


class PolicyOpRsp:
    def __init__(self, responses: List[PolicyRsp]) -> None:
        self.responses = responses

    @classmethod
    def from_pb(cls, policy_responses: srte_policy_api_pb2.PolicyOpRsp):
        rsps = list()
        for response in policy_responses.responses:
            rsps.append(PolicyRsp.from_pb(response.returnCode, response.key))

        self = cls(rsps)
        return self

    def __repr__(self) -> str:
        responses = list()
        for response in self.responses:
            responses.append(repr(response))

        return str(responses)


class TLSCredentials:
    def __init__(
        self,
        cert: bytes = None,
        key: bytes = None,
        ca_cert: bytes = None,
        strict: bool = False,
    ) -> None:
        self.cert = cert
        self.key = key
        self.ca_cert = ca_cert
        self.strict = strict

    @classmethod
    def from_file(
        cls,
        cert_file: str = None,
        key_file: str = None,
        ca_cert_file: str = None,
        strict: bool = False,
    ):
        cert = None
        key = None
        ca_cert = None

        if cert_file:
            with open(cert_file, "rb") as f:
                cert = f.read()

        if key_file:
            with open(key_file, "rb") as f:
                key = f.read()

        if ca_cert_file:
            with open(ca_cert_file, "rb") as f:
                ca_cert = f.read()

        self = cls(cert, key, ca_cert, strict)
        return self

    def to_channel_credentials(self) -> grpc.ChannelCredentials:
        return grpc.ssl_channel_credentials(
            certificate_chain=self.cert,
            private_key=self.key,
            root_certificates=self.ca_cert,
        )


class UserCredentials:
    def __init__(self, username: str = None, password: str = None) -> None:
        self.username = username
        self.password = password

    def to_metadata(self) -> tuple:
        return (
            ("username", self.username),
            ("password", self.password),
        )


class RPC:
    def __init__(
        self,
        grpc_addr: str,
        credentials: UserCredentials = None,
        tls: TLSCredentials = None,
    ) -> None:
        self._grpc_addr = grpc_addr
        self._cred = credentials
        self._tls = tls

    def _get_grpc_channel(self):
        if not self._tls:
            return grpc.insecure_channel(self._grpc_addr)

        options = None
        if not self._tls.strict:
            # Skip hostname validation
            # Overriding with the common name in default certificate.
            cert_cn = "ems.cisco.com"
            options = (
                (
                    "grpc.ssl_target_name_override",
                    cert_cn,
                ),
            )

        tls_cred_chan = self._tls.to_channel_credentials()
        return grpc.secure_channel(self._grpc_addr, tls_cred_chan, options)

    def _get_metadata(self):
        if not self._cred:
            return None

        return self._cred.to_metadata()

    def srte_policy_add(self, policy_msg: PolicyMsg) -> PolicyOpRsp:
        with self._get_grpc_channel() as channel:
            stub = srte_policy_api_pb2_grpc.SRTEPolicyStub(channel)
            response = stub.SRTEPolicyAdd(
                request=policy_msg.to_pb(), metadata=self._get_metadata()
            )

        return PolicyOpRsp.from_pb(response)

    def srte_policy_delete(self, policy_msg: PolicyMsg) -> PolicyOpRsp:
        with self._get_grpc_channel() as channel:
            stub = srte_policy_api_pb2_grpc.SRTEPolicyStub(channel)
            response = stub.SRTEPolicyDelete(
                request=policy_msg.to_pb(), metadata=self._get_metadata()
            )

        return PolicyOpRsp.from_pb(response)

