# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: proto/srte_policy_api.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1bproto/srte_policy_api.proto\x12\x04SRTE\"\x19\n\x0bIPv4Address\x12\n\n\x02v4\x18\x01 \x01(\r\"\x19\n\x0bIPv6Address\x12\n\n\x02v6\x18\x01 \x01(\x0c\"#\n\tIpAddress\x12\n\n\x02v4\x18\x01 \x01(\r\x12\n\n\x02v6\x18\x02 \x01(\x0c\"_\n\tPolicyKey\x12 \n\x07headend\x18\x01 \x01(\x0b\x32\x0f.SRTE.IpAddress\x12\r\n\x05\x63olor\x18\x02 \x01(\r\x12!\n\x08\x65ndpoint\x18\x03 \x01(\x0b\x32\x0f.SRTE.IpAddress\"\xbe\x01\n\x10\x43\x61ndidatePathKey\x12\x39\n\x0coriginatorID\x18\x01 \x01(\x0b\x32#.SRTE.CandidatePathKey.OriginatorID\x12\x1a\n\x12originatorProtocol\x18\x02 \x01(\r\x12\x15\n\rdiscriminator\x18\x03 \x01(\r\x1a<\n\x0cOriginatorID\x12\x0b\n\x03\x41SN\x18\x01 \x01(\r\x12\x1f\n\x06nodeID\x18\x02 \x01(\x0b\x32\x0f.SRTE.IpAddress\"\x8e\x01\n\x0bPolicyOpRsp\x12.\n\tresponses\x18\x01 \x03(\x0b\x32\x1b.SRTE.PolicyOpRsp.PolicyRsp\x1aO\n\tPolicyRsp\x12$\n\nreturnCode\x18\x01 \x01(\x0e\x32\x10.SRTE.ReturnCode\x12\x1c\n\x03key\x18\x02 \x01(\x0b\x32\x0f.SRTE.PolicyKey\"\x89\x01\n\tPerflowCP\x12\x1e\n\x16\x44\x65\x66\x61ultForwardingclass\x18\x01 \x01(\r\x12)\n\x08mappings\x18\x02 \x03(\x0b\x32\x17.SRTE.PerflowCP.Mapping\x1a\x31\n\x07Mapping\x12\x17\n\x0f\x66orwardingClass\x18\x01 \x01(\r\x12\r\n\x05\x63olor\x18\x02 \x01(\r\"s\n\x0b\x43ompositeCP\x12\x34\n\x0b\x63onstituent\x18\x01 \x03(\x0b\x32\x1f.SRTE.CompositeCP.ConstituentCP\x1a.\n\rConstituentCP\x12\r\n\x05\x63olor\x18\x01 \x01(\r\x12\x0e\n\x06weight\x18\x02 \x01(\r\"\x82\x0b\n\x07Segment\x12$\n\x05typeA\x18\x01 \x01(\x0b\x32\x13.SRTE.Segment.TypeAH\x00\x12$\n\x05typeB\x18\x02 \x01(\x0b\x32\x13.SRTE.Segment.TypeBH\x00\x12$\n\x05typeC\x18\x03 \x01(\x0b\x32\x13.SRTE.Segment.TypeCH\x00\x12$\n\x05typeD\x18\x04 \x01(\x0b\x32\x13.SRTE.Segment.TypeDH\x00\x12$\n\x05typeE\x18\x05 \x01(\x0b\x32\x13.SRTE.Segment.TypeEH\x00\x12$\n\x05typeF\x18\x06 \x01(\x0b\x32\x13.SRTE.Segment.TypeFH\x00\x12$\n\x05typeG\x18\x07 \x01(\x0b\x32\x13.SRTE.Segment.TypeGH\x00\x12$\n\x05typeH\x18\x08 \x01(\x0b\x32\x13.SRTE.Segment.TypeHH\x00\x12$\n\x05typeI\x18\t \x01(\x0b\x32\x13.SRTE.Segment.TypeIH\x00\x12$\n\x05typeJ\x18\n \x01(\x0b\x32\x13.SRTE.Segment.TypeJH\x00\x1a\x16\n\x05TypeA\x12\r\n\x05label\x18\x01 \x01(\r\x1a\xdf\x01\n\x05TypeB\x12\x1e\n\x03SID\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv6Address\x12\x10\n\x08\x62\x65havior\x18\x02 \x01(\r\x12\x30\n\tstructure\x18\x03 \x01(\x0b\x32\x1d.SRTE.Segment.TypeB.Structure\x1ar\n\tStructure\x12\x1a\n\x12locatorBlockLength\x18\x01 \x01(\r\x12\x19\n\x11locatorNodeLength\x18\x02 \x01(\r\x12\x16\n\x0e\x66unctionLength\x18\x03 \x01(\r\x12\x16\n\x0e\x61rgumentLength\x18\x04 \x01(\r\x1a<\n\x05TypeC\x12!\n\x06prefix\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv4Address\x12\x10\n\x08\x66lexalgo\x18\x02 \x01(\r\x1a<\n\x05TypeD\x12!\n\x06prefix\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv6Address\x12\x10\n\x08\x66lexalgo\x18\x02 \x01(\r\x1a\x44\n\x05TypeE\x12!\n\x06prefix\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv4Address\x12\x18\n\x10localInterfaceID\x18\x02 \x01(\r\x1al\n\x05TypeF\x12\x30\n\x15localInterfaceAddress\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv4Address\x12\x31\n\x16remoteInterfaceAddress\x18\x02 \x01(\x0b\x32\x11.SRTE.IPv4Address\x1a\x8d\x01\n\x05TypeG\x12&\n\x0blocalPrefix\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv6Address\x12\x18\n\x10localInterfaceID\x18\x02 \x01(\r\x12\'\n\x0cremotePrefix\x18\x03 \x01(\x0b\x32\x11.SRTE.IPv6Address\x12\x19\n\x11remoteInterfaceID\x18\x04 \x01(\r\x1al\n\x05TypeH\x12\x30\n\x15localInterfaceAddress\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv6Address\x12\x31\n\x16remoteInterfaceAddress\x18\x02 \x01(\x0b\x32\x11.SRTE.IPv6Address\x1a<\n\x05TypeI\x12!\n\x06prefix\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv6Address\x12\x10\n\x08\x66lexalgo\x18\x02 \x01(\r\x1a\x8d\x01\n\x05TypeJ\x12&\n\x0blocalPrefix\x18\x01 \x01(\x0b\x32\x11.SRTE.IPv6Address\x12\x18\n\x10localInterfaceID\x18\x02 \x01(\r\x12\'\n\x0cremotePrefix\x18\x03 \x01(\x0b\x32\x11.SRTE.IPv6Address\x12\x19\n\x11remoteInterfaceID\x18\x04 \x01(\rB\x05\n\x03SID\"L\n\x0bSegmentList\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0e\n\x06weight\x18\x02 \x01(\r\x12\x1f\n\x08segments\x18\x03 \x03(\x0b\x32\r.SRTE.Segment\"4\n\nExplicitCP\x12&\n\x0bsegmentList\x18\x01 \x03(\x0b\x32\x11.SRTE.SegmentList\"\xb4\x04\n\rTEConstraints\x12\x32\n\naffinities\x18\x01 \x01(\x0b\x32\x1e.SRTE.TEConstraints.Affinities\x12\x36\n\x0cmetricBounds\x18\x02 \x01(\x0b\x32 .SRTE.TEConstraints.MetricBounds\x12\x42\n\x12segmentConstraints\x18\x03 \x01(\x0b\x32&.SRTE.TEConstraints.SegmentConstraints\x1aH\n\nAffinities\x12\x12\n\nincludeAny\x18\x01 \x03(\t\x12\x12\n\nincludeAll\x18\x02 \x03(\t\x12\x12\n\nexcludeAny\x18\x03 \x03(\t\x1a\x38\n\x0cMetricBounds\x12\x0b\n\x03igp\x18\x01 \x01(\r\x12\n\n\x02te\x18\x02 \x01(\r\x12\x0f\n\x07latency\x18\x03 \x01(\r\x1a\xee\x01\n\x12SegmentConstraints\x12I\n\nprotection\x18\x01 \x01(\x0e\x32\x35.SRTE.TEConstraints.SegmentConstraints.ProtectionType\x12\x10\n\x08\x66lexalgo\x18\x02 \x01(\r\x12\x0b\n\x03MSD\x18\x03 \x01(\r\"n\n\x0eProtectionType\x12\x17\n\x13PROTECTED_PREFERRED\x10\x00\x12\x12\n\x0ePROTECTED_ONLY\x10\x01\x12\x19\n\x15UNPROTECTED_PREFERRED\x10\x02\x12\x14\n\x10UNPROTECTED_ONLY\x10\x03\"\xa6\x02\n\tDynamicCP\x12)\n\x07ometric\x18\x01 \x01(\x0e\x32\x18.SRTE.OptimizationMetric\x12(\n\x0b\x63onstraints\x18\x02 \x01(\x0b\x32\x13.SRTE.TEConstraints\x12\x32\n\x0cmetricMargin\x18\x03 \x01(\x0b\x32\x1c.SRTE.DynamicCP.MetricMargin\x12\x10\n\x08\x64\x65legate\x18\x04 \x01(\x08\x1a~\n\x0cMetricMargin\x12\x35\n\x04type\x18\x01 \x01(\x0e\x32\'.SRTE.DynamicCP.MetricMargin.MarginType\x12\r\n\x05value\x18\x02 \x01(\r\"(\n\nMarginType\x12\x0c\n\x08RELATIVE\x10\x00\x12\x0c\n\x08\x41\x42SOLUTE\x10\x01\"\x96\x02\n\rCandidatePath\x12#\n\x03key\x18\x01 \x01(\x0b\x32\x16.SRTE.CandidatePathKey\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x12\n\npreference\x18\x03 \x01(\r\x12\"\n\tdataplane\x18\x04 \x01(\x0e\x32\x0f.SRTE.Dataplane\x12\"\n\x07\x64ynamic\x18\x05 \x01(\x0b\x32\x0f.SRTE.DynamicCPH\x00\x12$\n\x08\x65xplicit\x18\x06 \x01(\x0b\x32\x10.SRTE.ExplicitCPH\x00\x12\"\n\x07perflow\x18\x07 \x01(\x0b\x32\x0f.SRTE.PerflowCPH\x00\x12&\n\tcomposite\x18\x08 \x01(\x0b\x32\x11.SRTE.CompositeCPH\x00\x42\x04\n\x02\x43P\"W\n\x0eSRv6BindingSID\x12\x13\n\x0blocatorName\x18\x01 \x01(\t\x12\x10\n\x08\x62\x65havior\x18\x02 \x01(\r\x12\x1e\n\x03SID\x18\x03 \x01(\x0b\x32\x11.SRTE.IPv6Address\"\xe5\x01\n\x06Policy\x12\x1c\n\x03key\x18\x01 \x01(\x0b\x32\x0f.SRTE.PolicyKey\x12\x17\n\x0ftransitEligible\x18\x02 \x01(\x08\x12 \n\x03\x43Ps\x18\x03 \x03(\x0b\x32\x13.SRTE.CandidatePath\x12<\n\x14\x62indingSIDAllocation\x18\x04 \x01(\x0e\x32\x1e.SRTE.BindingSIDAllocationMode\x12\x16\n\x0emplsBindingSID\x18\x05 \x01(\r\x12,\n\x0esrv6BindingSID\x18\x06 \x01(\x0b\x32\x14.SRTE.SRv6BindingSID\"+\n\tPolicyMsg\x12\x1e\n\x08policies\x18\x01 \x03(\x0b\x32\x0c.SRTE.Policy*\x1f\n\tDataplane\x12\x08\n\x04MPLS\x10\x00\x12\x08\n\x04SRV6\x10\x01*J\n\x11\x43\x61ndidatePathType\x12\x0b\n\x07\x44YNAMIC\x10\x00\x12\x0c\n\x08\x45XPLICIT\x10\x01\x12\x0b\n\x07PERFLOW\x10\x02\x12\r\n\tCOMPOSITE\x10\x03*<\n\x12OptimizationMetric\x12\x06\n\x02TE\x10\x00\x12\x07\n\x03IGP\x10\x01\x12\x0b\n\x07Latency\x10\x02\x12\x08\n\x04HOPS\x10\x03*?\n\x18\x42indingSIDAllocationMode\x12\x11\n\rBSID_EXPLICIT\x10\x00\x12\x10\n\x0c\x42SID_DYNAMIC\x10\x01*#\n\nReturnCode\x12\x0b\n\x07SUCCESS\x10\x00\x12\x08\n\x04\x46\x41IL\x10\x01\x32y\n\nSRTEPolicy\x12\x33\n\rSRTEPolicyAdd\x12\x0f.SRTE.PolicyMsg\x1a\x11.SRTE.PolicyOpRsp\x12\x36\n\x10SRTEPolicyDelete\x12\x0f.SRTE.PolicyMsg\x1a\x11.SRTE.PolicyOpRspB\x08Z\x06.;srteb\x06proto3')

_DATAPLANE = DESCRIPTOR.enum_types_by_name['Dataplane']
Dataplane = enum_type_wrapper.EnumTypeWrapper(_DATAPLANE)
_CANDIDATEPATHTYPE = DESCRIPTOR.enum_types_by_name['CandidatePathType']
CandidatePathType = enum_type_wrapper.EnumTypeWrapper(_CANDIDATEPATHTYPE)
_OPTIMIZATIONMETRIC = DESCRIPTOR.enum_types_by_name['OptimizationMetric']
OptimizationMetric = enum_type_wrapper.EnumTypeWrapper(_OPTIMIZATIONMETRIC)
_BINDINGSIDALLOCATIONMODE = DESCRIPTOR.enum_types_by_name['BindingSIDAllocationMode']
BindingSIDAllocationMode = enum_type_wrapper.EnumTypeWrapper(_BINDINGSIDALLOCATIONMODE)
_RETURNCODE = DESCRIPTOR.enum_types_by_name['ReturnCode']
ReturnCode = enum_type_wrapper.EnumTypeWrapper(_RETURNCODE)
MPLS = 0
SRV6 = 1
DYNAMIC = 0
EXPLICIT = 1
PERFLOW = 2
COMPOSITE = 3
TE = 0
IGP = 1
Latency = 2
HOPS = 3
BSID_EXPLICIT = 0
BSID_DYNAMIC = 1
SUCCESS = 0
FAIL = 1


_IPV4ADDRESS = DESCRIPTOR.message_types_by_name['IPv4Address']
_IPV6ADDRESS = DESCRIPTOR.message_types_by_name['IPv6Address']
_IPADDRESS = DESCRIPTOR.message_types_by_name['IpAddress']
_POLICYKEY = DESCRIPTOR.message_types_by_name['PolicyKey']
_CANDIDATEPATHKEY = DESCRIPTOR.message_types_by_name['CandidatePathKey']
_CANDIDATEPATHKEY_ORIGINATORID = _CANDIDATEPATHKEY.nested_types_by_name['OriginatorID']
_POLICYOPRSP = DESCRIPTOR.message_types_by_name['PolicyOpRsp']
_POLICYOPRSP_POLICYRSP = _POLICYOPRSP.nested_types_by_name['PolicyRsp']
_PERFLOWCP = DESCRIPTOR.message_types_by_name['PerflowCP']
_PERFLOWCP_MAPPING = _PERFLOWCP.nested_types_by_name['Mapping']
_COMPOSITECP = DESCRIPTOR.message_types_by_name['CompositeCP']
_COMPOSITECP_CONSTITUENTCP = _COMPOSITECP.nested_types_by_name['ConstituentCP']
_SEGMENT = DESCRIPTOR.message_types_by_name['Segment']
_SEGMENT_TYPEA = _SEGMENT.nested_types_by_name['TypeA']
_SEGMENT_TYPEB = _SEGMENT.nested_types_by_name['TypeB']
_SEGMENT_TYPEB_STRUCTURE = _SEGMENT_TYPEB.nested_types_by_name['Structure']
_SEGMENT_TYPEC = _SEGMENT.nested_types_by_name['TypeC']
_SEGMENT_TYPED = _SEGMENT.nested_types_by_name['TypeD']
_SEGMENT_TYPEE = _SEGMENT.nested_types_by_name['TypeE']
_SEGMENT_TYPEF = _SEGMENT.nested_types_by_name['TypeF']
_SEGMENT_TYPEG = _SEGMENT.nested_types_by_name['TypeG']
_SEGMENT_TYPEH = _SEGMENT.nested_types_by_name['TypeH']
_SEGMENT_TYPEI = _SEGMENT.nested_types_by_name['TypeI']
_SEGMENT_TYPEJ = _SEGMENT.nested_types_by_name['TypeJ']
_SEGMENTLIST = DESCRIPTOR.message_types_by_name['SegmentList']
_EXPLICITCP = DESCRIPTOR.message_types_by_name['ExplicitCP']
_TECONSTRAINTS = DESCRIPTOR.message_types_by_name['TEConstraints']
_TECONSTRAINTS_AFFINITIES = _TECONSTRAINTS.nested_types_by_name['Affinities']
_TECONSTRAINTS_METRICBOUNDS = _TECONSTRAINTS.nested_types_by_name['MetricBounds']
_TECONSTRAINTS_SEGMENTCONSTRAINTS = _TECONSTRAINTS.nested_types_by_name['SegmentConstraints']
_DYNAMICCP = DESCRIPTOR.message_types_by_name['DynamicCP']
_DYNAMICCP_METRICMARGIN = _DYNAMICCP.nested_types_by_name['MetricMargin']
_CANDIDATEPATH = DESCRIPTOR.message_types_by_name['CandidatePath']
_SRV6BINDINGSID = DESCRIPTOR.message_types_by_name['SRv6BindingSID']
_POLICY = DESCRIPTOR.message_types_by_name['Policy']
_POLICYMSG = DESCRIPTOR.message_types_by_name['PolicyMsg']
_TECONSTRAINTS_SEGMENTCONSTRAINTS_PROTECTIONTYPE = _TECONSTRAINTS_SEGMENTCONSTRAINTS.enum_types_by_name['ProtectionType']
_DYNAMICCP_METRICMARGIN_MARGINTYPE = _DYNAMICCP_METRICMARGIN.enum_types_by_name['MarginType']
IPv4Address = _reflection.GeneratedProtocolMessageType('IPv4Address', (_message.Message,), {
  'DESCRIPTOR' : _IPV4ADDRESS,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.IPv4Address)
  })
_sym_db.RegisterMessage(IPv4Address)

IPv6Address = _reflection.GeneratedProtocolMessageType('IPv6Address', (_message.Message,), {
  'DESCRIPTOR' : _IPV6ADDRESS,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.IPv6Address)
  })
_sym_db.RegisterMessage(IPv6Address)

IpAddress = _reflection.GeneratedProtocolMessageType('IpAddress', (_message.Message,), {
  'DESCRIPTOR' : _IPADDRESS,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.IpAddress)
  })
_sym_db.RegisterMessage(IpAddress)

PolicyKey = _reflection.GeneratedProtocolMessageType('PolicyKey', (_message.Message,), {
  'DESCRIPTOR' : _POLICYKEY,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.PolicyKey)
  })
_sym_db.RegisterMessage(PolicyKey)

CandidatePathKey = _reflection.GeneratedProtocolMessageType('CandidatePathKey', (_message.Message,), {

  'OriginatorID' : _reflection.GeneratedProtocolMessageType('OriginatorID', (_message.Message,), {
    'DESCRIPTOR' : _CANDIDATEPATHKEY_ORIGINATORID,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.CandidatePathKey.OriginatorID)
    })
  ,
  'DESCRIPTOR' : _CANDIDATEPATHKEY,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.CandidatePathKey)
  })
_sym_db.RegisterMessage(CandidatePathKey)
_sym_db.RegisterMessage(CandidatePathKey.OriginatorID)

PolicyOpRsp = _reflection.GeneratedProtocolMessageType('PolicyOpRsp', (_message.Message,), {

  'PolicyRsp' : _reflection.GeneratedProtocolMessageType('PolicyRsp', (_message.Message,), {
    'DESCRIPTOR' : _POLICYOPRSP_POLICYRSP,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.PolicyOpRsp.PolicyRsp)
    })
  ,
  'DESCRIPTOR' : _POLICYOPRSP,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.PolicyOpRsp)
  })
_sym_db.RegisterMessage(PolicyOpRsp)
_sym_db.RegisterMessage(PolicyOpRsp.PolicyRsp)

PerflowCP = _reflection.GeneratedProtocolMessageType('PerflowCP', (_message.Message,), {

  'Mapping' : _reflection.GeneratedProtocolMessageType('Mapping', (_message.Message,), {
    'DESCRIPTOR' : _PERFLOWCP_MAPPING,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.PerflowCP.Mapping)
    })
  ,
  'DESCRIPTOR' : _PERFLOWCP,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.PerflowCP)
  })
_sym_db.RegisterMessage(PerflowCP)
_sym_db.RegisterMessage(PerflowCP.Mapping)

CompositeCP = _reflection.GeneratedProtocolMessageType('CompositeCP', (_message.Message,), {

  'ConstituentCP' : _reflection.GeneratedProtocolMessageType('ConstituentCP', (_message.Message,), {
    'DESCRIPTOR' : _COMPOSITECP_CONSTITUENTCP,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.CompositeCP.ConstituentCP)
    })
  ,
  'DESCRIPTOR' : _COMPOSITECP,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.CompositeCP)
  })
_sym_db.RegisterMessage(CompositeCP)
_sym_db.RegisterMessage(CompositeCP.ConstituentCP)

Segment = _reflection.GeneratedProtocolMessageType('Segment', (_message.Message,), {

  'TypeA' : _reflection.GeneratedProtocolMessageType('TypeA', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPEA,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeA)
    })
  ,

  'TypeB' : _reflection.GeneratedProtocolMessageType('TypeB', (_message.Message,), {

    'Structure' : _reflection.GeneratedProtocolMessageType('Structure', (_message.Message,), {
      'DESCRIPTOR' : _SEGMENT_TYPEB_STRUCTURE,
      '__module__' : 'proto.srte_policy_api_pb2'
      # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeB.Structure)
      })
    ,
    'DESCRIPTOR' : _SEGMENT_TYPEB,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeB)
    })
  ,

  'TypeC' : _reflection.GeneratedProtocolMessageType('TypeC', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPEC,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeC)
    })
  ,

  'TypeD' : _reflection.GeneratedProtocolMessageType('TypeD', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPED,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeD)
    })
  ,

  'TypeE' : _reflection.GeneratedProtocolMessageType('TypeE', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPEE,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeE)
    })
  ,

  'TypeF' : _reflection.GeneratedProtocolMessageType('TypeF', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPEF,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeF)
    })
  ,

  'TypeG' : _reflection.GeneratedProtocolMessageType('TypeG', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPEG,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeG)
    })
  ,

  'TypeH' : _reflection.GeneratedProtocolMessageType('TypeH', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPEH,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeH)
    })
  ,

  'TypeI' : _reflection.GeneratedProtocolMessageType('TypeI', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPEI,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeI)
    })
  ,

  'TypeJ' : _reflection.GeneratedProtocolMessageType('TypeJ', (_message.Message,), {
    'DESCRIPTOR' : _SEGMENT_TYPEJ,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.Segment.TypeJ)
    })
  ,
  'DESCRIPTOR' : _SEGMENT,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.Segment)
  })
_sym_db.RegisterMessage(Segment)
_sym_db.RegisterMessage(Segment.TypeA)
_sym_db.RegisterMessage(Segment.TypeB)
_sym_db.RegisterMessage(Segment.TypeB.Structure)
_sym_db.RegisterMessage(Segment.TypeC)
_sym_db.RegisterMessage(Segment.TypeD)
_sym_db.RegisterMessage(Segment.TypeE)
_sym_db.RegisterMessage(Segment.TypeF)
_sym_db.RegisterMessage(Segment.TypeG)
_sym_db.RegisterMessage(Segment.TypeH)
_sym_db.RegisterMessage(Segment.TypeI)
_sym_db.RegisterMessage(Segment.TypeJ)

SegmentList = _reflection.GeneratedProtocolMessageType('SegmentList', (_message.Message,), {
  'DESCRIPTOR' : _SEGMENTLIST,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.SegmentList)
  })
_sym_db.RegisterMessage(SegmentList)

ExplicitCP = _reflection.GeneratedProtocolMessageType('ExplicitCP', (_message.Message,), {
  'DESCRIPTOR' : _EXPLICITCP,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.ExplicitCP)
  })
_sym_db.RegisterMessage(ExplicitCP)

TEConstraints = _reflection.GeneratedProtocolMessageType('TEConstraints', (_message.Message,), {

  'Affinities' : _reflection.GeneratedProtocolMessageType('Affinities', (_message.Message,), {
    'DESCRIPTOR' : _TECONSTRAINTS_AFFINITIES,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.TEConstraints.Affinities)
    })
  ,

  'MetricBounds' : _reflection.GeneratedProtocolMessageType('MetricBounds', (_message.Message,), {
    'DESCRIPTOR' : _TECONSTRAINTS_METRICBOUNDS,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.TEConstraints.MetricBounds)
    })
  ,

  'SegmentConstraints' : _reflection.GeneratedProtocolMessageType('SegmentConstraints', (_message.Message,), {
    'DESCRIPTOR' : _TECONSTRAINTS_SEGMENTCONSTRAINTS,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.TEConstraints.SegmentConstraints)
    })
  ,
  'DESCRIPTOR' : _TECONSTRAINTS,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.TEConstraints)
  })
_sym_db.RegisterMessage(TEConstraints)
_sym_db.RegisterMessage(TEConstraints.Affinities)
_sym_db.RegisterMessage(TEConstraints.MetricBounds)
_sym_db.RegisterMessage(TEConstraints.SegmentConstraints)

DynamicCP = _reflection.GeneratedProtocolMessageType('DynamicCP', (_message.Message,), {

  'MetricMargin' : _reflection.GeneratedProtocolMessageType('MetricMargin', (_message.Message,), {
    'DESCRIPTOR' : _DYNAMICCP_METRICMARGIN,
    '__module__' : 'proto.srte_policy_api_pb2'
    # @@protoc_insertion_point(class_scope:SRTE.DynamicCP.MetricMargin)
    })
  ,
  'DESCRIPTOR' : _DYNAMICCP,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.DynamicCP)
  })
_sym_db.RegisterMessage(DynamicCP)
_sym_db.RegisterMessage(DynamicCP.MetricMargin)

CandidatePath = _reflection.GeneratedProtocolMessageType('CandidatePath', (_message.Message,), {
  'DESCRIPTOR' : _CANDIDATEPATH,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.CandidatePath)
  })
_sym_db.RegisterMessage(CandidatePath)

SRv6BindingSID = _reflection.GeneratedProtocolMessageType('SRv6BindingSID', (_message.Message,), {
  'DESCRIPTOR' : _SRV6BINDINGSID,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.SRv6BindingSID)
  })
_sym_db.RegisterMessage(SRv6BindingSID)

Policy = _reflection.GeneratedProtocolMessageType('Policy', (_message.Message,), {
  'DESCRIPTOR' : _POLICY,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.Policy)
  })
_sym_db.RegisterMessage(Policy)

PolicyMsg = _reflection.GeneratedProtocolMessageType('PolicyMsg', (_message.Message,), {
  'DESCRIPTOR' : _POLICYMSG,
  '__module__' : 'proto.srte_policy_api_pb2'
  # @@protoc_insertion_point(class_scope:SRTE.PolicyMsg)
  })
_sym_db.RegisterMessage(PolicyMsg)

_SRTEPOLICY = DESCRIPTOR.services_by_name['SRTEPolicy']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z\006.;srte'
  _DATAPLANE._serialized_start=3876
  _DATAPLANE._serialized_end=3907
  _CANDIDATEPATHTYPE._serialized_start=3909
  _CANDIDATEPATHTYPE._serialized_end=3983
  _OPTIMIZATIONMETRIC._serialized_start=3985
  _OPTIMIZATIONMETRIC._serialized_end=4045
  _BINDINGSIDALLOCATIONMODE._serialized_start=4047
  _BINDINGSIDALLOCATIONMODE._serialized_end=4110
  _RETURNCODE._serialized_start=4112
  _RETURNCODE._serialized_end=4147
  _IPV4ADDRESS._serialized_start=37
  _IPV4ADDRESS._serialized_end=62
  _IPV6ADDRESS._serialized_start=64
  _IPV6ADDRESS._serialized_end=89
  _IPADDRESS._serialized_start=91
  _IPADDRESS._serialized_end=126
  _POLICYKEY._serialized_start=128
  _POLICYKEY._serialized_end=223
  _CANDIDATEPATHKEY._serialized_start=226
  _CANDIDATEPATHKEY._serialized_end=416
  _CANDIDATEPATHKEY_ORIGINATORID._serialized_start=356
  _CANDIDATEPATHKEY_ORIGINATORID._serialized_end=416
  _POLICYOPRSP._serialized_start=419
  _POLICYOPRSP._serialized_end=561
  _POLICYOPRSP_POLICYRSP._serialized_start=482
  _POLICYOPRSP_POLICYRSP._serialized_end=561
  _PERFLOWCP._serialized_start=564
  _PERFLOWCP._serialized_end=701
  _PERFLOWCP_MAPPING._serialized_start=652
  _PERFLOWCP_MAPPING._serialized_end=701
  _COMPOSITECP._serialized_start=703
  _COMPOSITECP._serialized_end=818
  _COMPOSITECP_CONSTITUENTCP._serialized_start=772
  _COMPOSITECP_CONSTITUENTCP._serialized_end=818
  _SEGMENT._serialized_start=821
  _SEGMENT._serialized_end=2231
  _SEGMENT_TYPEA._serialized_start=1212
  _SEGMENT_TYPEA._serialized_end=1234
  _SEGMENT_TYPEB._serialized_start=1237
  _SEGMENT_TYPEB._serialized_end=1460
  _SEGMENT_TYPEB_STRUCTURE._serialized_start=1346
  _SEGMENT_TYPEB_STRUCTURE._serialized_end=1460
  _SEGMENT_TYPEC._serialized_start=1462
  _SEGMENT_TYPEC._serialized_end=1522
  _SEGMENT_TYPED._serialized_start=1524
  _SEGMENT_TYPED._serialized_end=1584
  _SEGMENT_TYPEE._serialized_start=1586
  _SEGMENT_TYPEE._serialized_end=1654
  _SEGMENT_TYPEF._serialized_start=1656
  _SEGMENT_TYPEF._serialized_end=1764
  _SEGMENT_TYPEG._serialized_start=1767
  _SEGMENT_TYPEG._serialized_end=1908
  _SEGMENT_TYPEH._serialized_start=1910
  _SEGMENT_TYPEH._serialized_end=2018
  _SEGMENT_TYPEI._serialized_start=2020
  _SEGMENT_TYPEI._serialized_end=2080
  _SEGMENT_TYPEJ._serialized_start=2083
  _SEGMENT_TYPEJ._serialized_end=2224
  _SEGMENTLIST._serialized_start=2233
  _SEGMENTLIST._serialized_end=2309
  _EXPLICITCP._serialized_start=2311
  _EXPLICITCP._serialized_end=2363
  _TECONSTRAINTS._serialized_start=2366
  _TECONSTRAINTS._serialized_end=2930
  _TECONSTRAINTS_AFFINITIES._serialized_start=2559
  _TECONSTRAINTS_AFFINITIES._serialized_end=2631
  _TECONSTRAINTS_METRICBOUNDS._serialized_start=2633
  _TECONSTRAINTS_METRICBOUNDS._serialized_end=2689
  _TECONSTRAINTS_SEGMENTCONSTRAINTS._serialized_start=2692
  _TECONSTRAINTS_SEGMENTCONSTRAINTS._serialized_end=2930
  _TECONSTRAINTS_SEGMENTCONSTRAINTS_PROTECTIONTYPE._serialized_start=2820
  _TECONSTRAINTS_SEGMENTCONSTRAINTS_PROTECTIONTYPE._serialized_end=2930
  _DYNAMICCP._serialized_start=2933
  _DYNAMICCP._serialized_end=3227
  _DYNAMICCP_METRICMARGIN._serialized_start=3101
  _DYNAMICCP_METRICMARGIN._serialized_end=3227
  _DYNAMICCP_METRICMARGIN_MARGINTYPE._serialized_start=3187
  _DYNAMICCP_METRICMARGIN_MARGINTYPE._serialized_end=3227
  _CANDIDATEPATH._serialized_start=3230
  _CANDIDATEPATH._serialized_end=3508
  _SRV6BINDINGSID._serialized_start=3510
  _SRV6BINDINGSID._serialized_end=3597
  _POLICY._serialized_start=3600
  _POLICY._serialized_end=3829
  _POLICYMSG._serialized_start=3831
  _POLICYMSG._serialized_end=3874
  _SRTEPOLICY._serialized_start=4149
  _SRTEPOLICY._serialized_end=4270
# @@protoc_insertion_point(module_scope)
