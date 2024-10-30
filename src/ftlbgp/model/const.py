# -*- coding: utf-8 -*-
# pylint: disable=I0011,I0020,I0021,I0023
# pylint: disable=W0149,W0717,R0902,R0904,R0911,R0912,R0913,R0914,R0915,R1702,R1734,R1735,R2044,R6103,C0103,C0209,C2001
# pylint: enable=I0011
# flake8: noqa
""" ftlbgp
Copyright (C) 2014-2024 Leitwert GmbH

This software is distributed under the terms of the MIT license.
It can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Author Johann SCHLAMP <schlamp@leitwert.net>
"""

# Local imports
from ..data.const import AFI_IPV4
from ..data.const import AFI_IPV6
from ..data.mrt.entry.const import MRT_NULL
from ..data.mrt.entry.const import MRT_START
from ..data.mrt.entry.const import MRT_DIE
from ..data.mrt.entry.const import MRT_I_AM_DEAD
from ..data.mrt.entry.const import MRT_PEER_DOWN
from ..data.mrt.entry.const import MRT_BGP
from ..data.mrt.entry.const import MRT_RIP
from ..data.mrt.entry.const import MRT_IDRP
from ..data.mrt.entry.const import MRT_RIPNG
from ..data.mrt.entry.const import MRT_BGP4PLUS
from ..data.mrt.entry.const import MRT_BGP4PLUS_01
from ..data.mrt.entry.const import MRT_OSPFV2
from ..data.mrt.entry.const import MRT_TABLE_DUMP
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2
from ..data.mrt.entry.const import MRT_BGP4MP
from ..data.mrt.entry.const import MRT_BGP4MP_ET
from ..data.mrt.entry.const import MRT_ISIS
from ..data.mrt.entry.const import MRT_ISIS_ET
from ..data.mrt.entry.const import MRT_OSPFV3
from ..data.mrt.entry.const import MRT_OSPFV3_ET
from ..data.mrt.entry.const import MRT_BGP_NULL
from ..data.mrt.entry.const import MRT_BGP_UPDATE
from ..data.mrt.entry.const import MRT_BGP_PREF_UPDATE
from ..data.mrt.entry.const import MRT_BGP_STATE_CHANGE
from ..data.mrt.entry.const import MRT_BGP_SYNC
from ..data.mrt.entry.const import MRT_BGP_OPEN
from ..data.mrt.entry.const import MRT_BGP_NOTIFY
from ..data.mrt.entry.const import MRT_BGP_KEEPALIVE
from ..data.mrt.entry.const import MRT_BGP4MP_ENTRY
from ..data.mrt.entry.const import MRT_BGP4MP_SNAPSHOT
from ..data.mrt.entry.const import MRT_BGP4MP_STATE_CHANGE
from ..data.mrt.entry.const import MRT_BGP4MP_STATE_CHANGE_AS4
from ..data.mrt.entry.const import MRT_BGP4MP_MESSAGE
from ..data.mrt.entry.const import MRT_BGP4MP_MESSAGE_ADDPATH
from ..data.mrt.entry.const import MRT_BGP4MP_MESSAGE_LOCAL
from ..data.mrt.entry.const import MRT_BGP4MP_MESSAGE_LOCAL_ADDPATH
from ..data.mrt.entry.const import MRT_BGP4MP_MESSAGE_AS4
from ..data.mrt.entry.const import MRT_BGP4MP_MESSAGE_AS4_ADDPATH
from ..data.mrt.entry.const import MRT_BGP4MP_MESSAGE_AS4_LOCAL
from ..data.mrt.entry.const import MRT_BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_PEER_INDEX_TABLE
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_GEO_PEER_TABLE
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_GENERIC
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_GENERIC_ADDPATH
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_IPV6_UNICAST
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_IPV6_MULTICAST
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST_ADDPATH
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST_ADDPATH
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_IPV6_UNICAST_ADDPATH
from ..data.mrt.entry.const import MRT_TABLE_DUMP_V2_RIB_IPV6_MULTICAST_ADDPATH
from ..data.mrt.bgp.const import BGP_BGP4MP_RESERVED
from ..data.mrt.bgp.const import BGP_BGP4MP_OPEN
from ..data.mrt.bgp.const import BGP_BGP4MP_UPDATE
from ..data.mrt.bgp.const import BGP_BGP4MP_NOTIFICATION
from ..data.mrt.bgp.const import BGP_BGP4MP_KEEPALIVE
from ..data.mrt.bgp.const import BGP_BGP4MP_ROUTE_REFRESH
from ..data.mrt.bgp.const import BGP_STATE_IDLE
from ..data.mrt.bgp.const import BGP_STATE_CONNECT
from ..data.mrt.bgp.const import BGP_STATE_ACTIVE
from ..data.mrt.bgp.const import BGP_STATE_OPEN_SENT
from ..data.mrt.bgp.const import BGP_STATE_OPEN_CONFIRM
from ..data.mrt.bgp.const import BGP_STATE_ESTABLISHED
from ..data.mrt.bgp.const import BGP_STATE_CLEARING
from ..data.mrt.bgp.const import BGP_STATE_DELETED
from ..data.mrt.bgp.const import BGP_CAPABILITY_RESERVED_0
from ..data.mrt.bgp.const import BGP_CAPABILITY_BGP4MP
from ..data.mrt.bgp.const import BGP_CAPABILITY_ROUTE_REFRESH
from ..data.mrt.bgp.const import BGP_CAPABILITY_OUTBOUND_FILTER
from ..data.mrt.bgp.const import BGP_CAPABILITY_MULTIPLE_ROUTES
from ..data.mrt.bgp.const import BGP_CAPABILITY_EXTENDED_NEXT_HOP
from ..data.mrt.bgp.const import BGP_CAPABILITY_BGP4MP_ET
from ..data.mrt.bgp.const import BGP_CAPABILITY_BGPSEC
from ..data.mrt.bgp.const import BGP_CAPABILITY_MULTIPLE_LABELS
from ..data.mrt.bgp.const import BGP_CAPABILITY_BGP_ROLE
from ..data.mrt.bgp.const import BGP_CAPABILITY_GRACEFUL_RESTART
from ..data.mrt.bgp.const import BGP_CAPABILITY_AS4
from ..data.mrt.bgp.const import BGP_CAPABILITY_UNKNOWN_66
from ..data.mrt.bgp.const import BGP_CAPABILITY_DYNAMIC
from ..data.mrt.bgp.const import BGP_CAPABILITY_MULTISESSION
from ..data.mrt.bgp.const import BGP_CAPABILITY_ADDPATH
from ..data.mrt.bgp.const import BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH
from ..data.mrt.bgp.const import BGP_CAPABILITY_LLGR
from ..data.mrt.bgp.const import BGP_CAPABILITY_POLICY_DISTRIBUTION
from ..data.mrt.bgp.const import BGP_CAPABILITY_FQDN
from ..data.mrt.bgp.const import BGP_CAPABILITY_BFD
from ..data.mrt.bgp.const import BGP_CAPABILITY_SOFTWARE_VERSION
from ..data.mrt.bgp.const import BGP_CAPABILITY_PRESTD_ROUTE_REFRESH
from ..data.mrt.bgp.const import BGP_CAPABILITY_PRESTD_POLICY_DISTRIBUTION
from ..data.mrt.bgp.const import BGP_CAPABILITY_PRESTD_OUTBOUND_FILTER
from ..data.mrt.bgp.const import BGP_CAPABILITY_PRESTD_MULTISESSION
from ..data.mrt.bgp.const import BGP_CAPABILITY_PRESTD_FQDN
from ..data.mrt.bgp.const import BGP_CAPABILITY_PRESTD_OPERATIONAL
from ..data.mrt.bgp.const import BGP_CAPABILITY_RESERVED_255
from ..data.mrt.bgp.const import BGP_ERROR_RESERVED
from ..data.mrt.bgp.const import BGP_ERROR_MESSAGE_HEADER
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE
from ..data.mrt.bgp.const import BGP_ERROR_HOLD_TIMER_EXPIRED
from ..data.mrt.bgp.const import BGP_ERROR_FSM
from ..data.mrt.bgp.const import BGP_ERROR_CEASE
from ..data.mrt.bgp.const import BGP_ERROR_ROUTE_REFRESH
from ..data.mrt.bgp.const import BGP_ERROR_MESSAGE_HEADER_UNSPECIFIC
from ..data.mrt.bgp.const import BGP_ERROR_MESSAGE_HEADER_CONNECTION_NOT_SYNCHRONIZED
from ..data.mrt.bgp.const import BGP_ERROR_MESSAGE_HEADER_BAD_MESSAGE_LENGTH
from ..data.mrt.bgp.const import BGP_ERROR_MESSAGE_HEADER_BAD_MESSAGE_TYPE
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_UNSPECIFIC
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_VERSION_NUMBER
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_BAD_PEER_AS
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_BAD_BGP_IDENTIFIER
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_OPTIONAL_PARAMETER
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_AUTHENTICATION_FAILURE
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_UNACCEPTABLE_HOLD_TIME
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_CAPABILITY
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_DEPRECATED_8
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_DEPRECATED_9
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_DEPRECATED_10
from ..data.mrt.bgp.const import BGP_ERROR_OPEN_MESSAGE_ROLE_MISMATCH
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_UNSPECIFIC
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_MALFORMED_ATTRIBUTE_LIST
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_UNRECOGNIZED_WELLKNOWN_ATTRIBUTE
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_MISSING_WELLKNOWN_ATTRIBUTE
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_INVALID_ATTRIBUTE_FLAGS
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_INVALID_ATTRIBUTE_LENGTH
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_INVALID_ORIGIN_ATTRIBUTE
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_AS_ROUTING_LOOP
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_INVALID_NEXTHOP_ATTRIBUTE
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_INVALID_OPTIONAL_ATTRIBUTE
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_INVALID_NETWORK_FIELD
from ..data.mrt.bgp.const import BGP_ERROR_UPDATE_MESSAGE_MALFORMED_AS_PATH
from ..data.mrt.bgp.const import BGP_ERROR_FSM_UNSPECIFIED
from ..data.mrt.bgp.const import BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_OPEN_SENT_STATE
from ..data.mrt.bgp.const import BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_OPEN_CONFIRM_STATE
from ..data.mrt.bgp.const import BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_RESERVED
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_MAX_NUMBER_PREFIXES_REACHED
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_ADMINISTRATIVE_SHUTDOWN
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_PEER_DECONFIGURED
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_ADMINISTRATIVE_RESET
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_CONNECTION_REJECTED
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_OTHER_CONFIGURATION_CHANGE
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_CONNECTION_COLLISION_RESOLUTION
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_OUT_OF_RESOURCES
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_HARD_RESET
from ..data.mrt.bgp.const import BGP_ERROR_CEASE_BFD_DOWN
from ..data.mrt.bgp.const import BGP_ERROR_ROUTE_REFRESH_RESERVED
from ..data.mrt.bgp.const import BGP_ERROR_ROUTE_REFRESH_INVALID_MESSAGE_LENGTH
from ..data.mrt.bgp.const import BGP_PATH_ATTR_RESERVED
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ORIGIN
from ..data.mrt.bgp.const import BGP_PATH_ATTR_AS_PATH
from ..data.mrt.bgp.const import BGP_PATH_ATTR_NEXT_HOP
from ..data.mrt.bgp.const import BGP_PATH_ATTR_MULTI_EXIT_DISC
from ..data.mrt.bgp.const import BGP_PATH_ATTR_LOCAL_PREF
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ATOMIC_AGGREGATE
from ..data.mrt.bgp.const import BGP_PATH_ATTR_AGGREGATOR
from ..data.mrt.bgp.const import BGP_PATH_ATTR_COMMUNITIES
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ORIGINATOR_ID
from ..data.mrt.bgp.const import BGP_PATH_ATTR_CLUSTER_LIST
from ..data.mrt.bgp.const import BGP_PATH_ATTR_DPA
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ADVERTISER
from ..data.mrt.bgp.const import BGP_PATH_ATTR_RCID_CLUSTER_ID
from ..data.mrt.bgp.const import BGP_PATH_ATTR_MP_REACH_NLRI
from ..data.mrt.bgp.const import BGP_PATH_ATTR_MP_UNREACH_NLRI
from ..data.mrt.bgp.const import BGP_PATH_ATTR_EXTENDED_COMMUNITIES
from ..data.mrt.bgp.const import BGP_PATH_ATTR_AS4_PATH
from ..data.mrt.bgp.const import BGP_PATH_ATTR_AS4_AGGREGATOR
from ..data.mrt.bgp.const import BGP_PATH_ATTR_SAFI_SPECIFIC
from ..data.mrt.bgp.const import BGP_PATH_ATTR_CONNECTOR
from ..data.mrt.bgp.const import BGP_PATH_ATTR_AS_PATHLIMIT
from ..data.mrt.bgp.const import BGP_PATH_ATTR_PMSI_TUNNEL
from ..data.mrt.bgp.const import BGP_PATH_ATTR_TUNNEL_ENCAPSULATION
from ..data.mrt.bgp.const import BGP_PATH_ATTR_TRAFFIC_ENGINEERING
from ..data.mrt.bgp.const import BGP_PATH_ATTR_IPV6_EXTENDED_COMMUNITIES
from ..data.mrt.bgp.const import BGP_PATH_ATTR_AIGP
from ..data.mrt.bgp.const import BGP_PATH_ATTR_PE_DISTINGUISHER_LABELS
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ENTROPY_LABEL_CAPABILITY
from ..data.mrt.bgp.const import BGP_PATH_ATTR_LS
from ..data.mrt.bgp.const import BGP_PATH_ATTR_VENDOR_30
from ..data.mrt.bgp.const import BGP_PATH_ATTR_VENDOR_31
from ..data.mrt.bgp.const import BGP_PATH_ATTR_LARGE_COMMUNITIES
from ..data.mrt.bgp.const import BGP_PATH_ATTR_BGPSEC_PATH
from ..data.mrt.bgp.const import BGP_PATH_ATTR_COMMUNITY_CONTAINER
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ONLY_TO_CUSTOMER
from ..data.mrt.bgp.const import BGP_PATH_ATTR_DOMAIN_PATH
from ..data.mrt.bgp.const import BGP_PATH_ATTR_SFP
from ..data.mrt.bgp.const import BGP_PATH_ATTR_BFD_DISCRIMINATOR
from ..data.mrt.bgp.const import BGP_PATH_ATTR_NHC_TMP
from ..data.mrt.bgp.const import BGP_PATH_ATTR_PREFIX_SID
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ATTR_SET
from ..data.mrt.bgp.const import BGP_PATH_ATTR_VENDOR_129
from ..data.mrt.bgp.const import BGP_PATH_ATTR_VENDOR_241
from ..data.mrt.bgp.const import BGP_PATH_ATTR_VENDOR_242
from ..data.mrt.bgp.const import BGP_PATH_ATTR_VENDOR_243
from ..data.mrt.bgp.const import BGP_PATH_ATTR_RESERVED_FOR_DEV
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ORIGIN_IGP
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ORIGIN_EGP
from ..data.mrt.bgp.const import BGP_PATH_ATTR_ORIGIN_INCOMPLETE

# Main data sources
FTL_MRT = 'mrt'
FTL_LGL = 'lgl'
FTL_BGP = 'bgp'
FTL_PARSER = 'parser'

# Generic record name
FTL_RECORD = 'FTL_RECORD'

# Generic attribute name
FTL_ATTR = 'FTL_ATTR'


def init_const_mappings(**consts):
    """ Generate type-to-string/string-to-type constant mappings.
    """
    # Iterate constants and populate constant mappings
    const_to_str, const_from_str = dict(), dict()
    for const_name, const_value in consts.items():
        const_to_str[const_value] = const_name
        const_from_str[const_name] = const_value

    # Return constant mappings
    return const_to_str, const_from_str


##############################
# BGP STATE_CHANGE CONSTANTS #
##############################

# BGP state_change state constants
(FTL_ATTR_BGP_STATE_CHANGE_STATE_TO_STR,
 FTL_ATTR_BGP_STATE_CHANGE_STATE_FROM_STR) = init_const_mappings(
    idle         = BGP_STATE_IDLE,
    connect      = BGP_STATE_CONNECT,
    active       = BGP_STATE_ACTIVE,
    open_sent    = BGP_STATE_OPEN_SENT,
    open_confirm = BGP_STATE_OPEN_CONFIRM,
    established  = BGP_STATE_ESTABLISHED,
    clearing     = BGP_STATE_CLEARING,
    deleted      = BGP_STATE_DELETED,
)

#######################
# BGP ROUTE CONSTANTS #
#######################

# BGP route source integer types
FTL_ATTR_BGP_ROUTE_SOURCE_RIB      = 0
FTL_ATTR_BGP_ROUTE_SOURCE_ANNOUNCE = 1
FTL_ATTR_BGP_ROUTE_SOURCE_WITHDRAW = 2

# BGP route source string types
FTL_ATTR_BGP_ROUTE_SOURCE_RIB_STR      = 'rib'
FTL_ATTR_BGP_ROUTE_SOURCE_ANNOUNCE_STR = 'announce'
FTL_ATTR_BGP_ROUTE_SOURCE_WITHDRAW_STR = 'withdraw'

# BGP route source constants
(FTL_ATTR_BGP_ROUTE_SOURCE_TO_STR,
 FTL_ATTR_BGP_ROUTE_SOURCE_FROM_STR) = init_const_mappings(**{
    FTL_ATTR_BGP_ROUTE_SOURCE_RIB_STR:      FTL_ATTR_BGP_ROUTE_SOURCE_RIB,
    FTL_ATTR_BGP_ROUTE_SOURCE_ANNOUNCE_STR: FTL_ATTR_BGP_ROUTE_SOURCE_ANNOUNCE,
    FTL_ATTR_BGP_ROUTE_SOURCE_WITHDRAW_STR: FTL_ATTR_BGP_ROUTE_SOURCE_WITHDRAW,
})

# BGP route origin integer types
FTL_ATTR_BGP_ROUTE_ORIGIN_IGP        = BGP_PATH_ATTR_ORIGIN_IGP
FTL_ATTR_BGP_ROUTE_ORIGIN_EGP        = BGP_PATH_ATTR_ORIGIN_EGP
FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE = BGP_PATH_ATTR_ORIGIN_INCOMPLETE

# BGP route origin string types
FTL_ATTR_BGP_ROUTE_ORIGIN_IGP_STR        = 'igp'
FTL_ATTR_BGP_ROUTE_ORIGIN_EGP_STR        = 'egp'
FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE_STR = 'incomplete'

# BGP route origin constants
(FTL_ATTR_BGP_ROUTE_ORIGIN_TO_STR,
 FTL_ATTR_BGP_ROUTE_ORIGIN_FROM_STR) = init_const_mappings(**{
    FTL_ATTR_BGP_ROUTE_ORIGIN_IGP_STR:        BGP_PATH_ATTR_ORIGIN_IGP,
    FTL_ATTR_BGP_ROUTE_ORIGIN_EGP_STR:        BGP_PATH_ATTR_ORIGIN_EGP,
    FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE_STR: BGP_PATH_ATTR_ORIGIN_INCOMPLETE,
})

##############################
# BGP NOTIFICATION CONSTANTS #
##############################

# BGP notification error code constants
(FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE_TO_STR,
 FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE_FROM_STR) = init_const_mappings(
    reserved           = BGP_ERROR_RESERVED,
    message_header     = BGP_ERROR_MESSAGE_HEADER,
    open_message       = BGP_ERROR_OPEN_MESSAGE,
    update_message     = BGP_ERROR_UPDATE_MESSAGE,
    hold_timer_expired = BGP_ERROR_HOLD_TIMER_EXPIRED,
    fsm                = BGP_ERROR_FSM,
    cease              = BGP_ERROR_CEASE,
    route_refresh      = BGP_ERROR_ROUTE_REFRESH,
)

# BGP message header error subcode constants
(FTL_ATTR_BGP_NOTIFICATION_ERROR_MESSAGE_HEADER_TO_STR,
 FTL_ATTR_BGP_NOTIFICATION_ERROR_MESSAGE_HEADER_FROM_STR) = init_const_mappings(
    unspecific                  = BGP_ERROR_MESSAGE_HEADER_UNSPECIFIC,
    connection_not_synchronized = BGP_ERROR_MESSAGE_HEADER_CONNECTION_NOT_SYNCHRONIZED,
    message_length              = BGP_ERROR_MESSAGE_HEADER_BAD_MESSAGE_LENGTH,
    message_tgype               = BGP_ERROR_MESSAGE_HEADER_BAD_MESSAGE_TYPE,
)

# BGP OPEN message error subcode constants
(FTL_ATTR_BGP_NOTIFICATION_ERROR_OPEN_MESSAGE_TO_STR,
 FTL_ATTR_BGP_NOTIFICATION_ERROR_OPEN_MESSAGE_FROM_STR) = init_const_mappings(
    unspecific                     = BGP_ERROR_OPEN_MESSAGE_UNSPECIFIC,
    unsupported_version_number     = BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_VERSION_NUMBER,
    bad_peer_as                    = BGP_ERROR_OPEN_MESSAGE_BAD_PEER_AS,
    bad_bgp_identifier             = BGP_ERROR_OPEN_MESSAGE_BAD_BGP_IDENTIFIER,
    unsupported_optional_parameter = BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_OPTIONAL_PARAMETER,
    authentication_failure         = BGP_ERROR_OPEN_MESSAGE_AUTHENTICATION_FAILURE,
    unacceptable_hold_time         = BGP_ERROR_OPEN_MESSAGE_UNACCEPTABLE_HOLD_TIME,
    unsupported_capability         = BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_CAPABILITY,
    deprecated_8                   = BGP_ERROR_OPEN_MESSAGE_DEPRECATED_8,
    deprecated_9                   = BGP_ERROR_OPEN_MESSAGE_DEPRECATED_9,
    deprecated_10                  = BGP_ERROR_OPEN_MESSAGE_DEPRECATED_10,
    role_mismatch                  = BGP_ERROR_OPEN_MESSAGE_ROLE_MISMATCH,
)

# BGP UPDATE message error subcode constants
(FTL_ATTR_BGP_NOTIFICATION_ERROR_UPDATE_MESSAGE_TO_STR,
 FTL_ATTR_BGP_NOTIFICATION_ERROR_UPDATE_MESSAGE_FROM_STR) = init_const_mappings(
    unspecific                       = BGP_ERROR_UPDATE_MESSAGE_UNSPECIFIC,
    malformed_attribute_list         = BGP_ERROR_UPDATE_MESSAGE_MALFORMED_ATTRIBUTE_LIST,
    unrecognized_wellknown_attribute = BGP_ERROR_UPDATE_MESSAGE_UNRECOGNIZED_WELLKNOWN_ATTRIBUTE,
    missing_wellknown_attribute      = BGP_ERROR_UPDATE_MESSAGE_MISSING_WELLKNOWN_ATTRIBUTE,
    invalid_attribute_flags          = BGP_ERROR_UPDATE_MESSAGE_INVALID_ATTRIBUTE_FLAGS,
    invalid_attribute_length         = BGP_ERROR_UPDATE_MESSAGE_INVALID_ATTRIBUTE_LENGTH,
    invalid_origin_attribute         = BGP_ERROR_UPDATE_MESSAGE_INVALID_ORIGIN_ATTRIBUTE,
    as_routing_loop                  = BGP_ERROR_UPDATE_MESSAGE_AS_ROUTING_LOOP,
    invalid_nexthop_attribute        = BGP_ERROR_UPDATE_MESSAGE_INVALID_NEXTHOP_ATTRIBUTE,
    invalid_optional_attribute       = BGP_ERROR_UPDATE_MESSAGE_INVALID_OPTIONAL_ATTRIBUTE,
    invalid_network_field            = BGP_ERROR_UPDATE_MESSAGE_INVALID_NETWORK_FIELD,
    malformed_as_path                = BGP_ERROR_UPDATE_MESSAGE_MALFORMED_AS_PATH,
)

# BGP finite state machine error subcode constants
(FTL_ATTR_BGP_NOTIFICATION_ERROR_FSM_TO_STR,
 FTL_ATTR_BGP_NOTIFICATION_ERROR_FSM_FROM_STR) = init_const_mappings(
    unspecified                              = BGP_ERROR_FSM_UNSPECIFIED,
    unexpected_message_in_open_sent_state    = BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_OPEN_SENT_STATE,
    unexpected_message_in_open_confirm_state = BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_OPEN_CONFIRM_STATE,
    unexpected_message_in_established_state  = BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE,
)

# BGP cease error subcode constants
(FTL_ATTR_BGP_NOTIFICATION_ERROR_CEASE_TO_STR,
 FTL_ATTR_BGP_NOTIFICATION_ERROR_CEASE_FROM_STR) = init_const_mappings(
    reserved                        = BGP_ERROR_CEASE_RESERVED,
    max_number_prefixes_reached     = BGP_ERROR_CEASE_MAX_NUMBER_PREFIXES_REACHED,
    administrative_shutdown         = BGP_ERROR_CEASE_ADMINISTRATIVE_SHUTDOWN,
    peer_deconfigured               = BGP_ERROR_CEASE_PEER_DECONFIGURED,
    administrative_reset            = BGP_ERROR_CEASE_ADMINISTRATIVE_RESET,
    connection_rejected             = BGP_ERROR_CEASE_CONNECTION_REJECTED,
    other_configuration_change      = BGP_ERROR_CEASE_OTHER_CONFIGURATION_CHANGE,
    connection_collision_resolution = BGP_ERROR_CEASE_CONNECTION_COLLISION_RESOLUTION,
    out_of_resources                = BGP_ERROR_CEASE_OUT_OF_RESOURCES,
    hard_reset                      = BGP_ERROR_CEASE_HARD_RESET,
    bfd_down                        = BGP_ERROR_CEASE_BFD_DOWN,
)

# BGP route refresh error subcode constants
(FTL_ATTR_BGP_NOTIFICATION_ERROR_ROUTE_REFRESH_TO_STR,
 FTL_ATTR_BGP_NOTIFICATION_ERROR_ROUTE_REFRESH_FROM_STR) = init_const_mappings(
    refresh_reserved               = BGP_ERROR_ROUTE_REFRESH_RESERVED,
    refresh_invalid_message_length = BGP_ERROR_ROUTE_REFRESH_INVALID_MESSAGE_LENGTH,
)

# BGP notification code/subcode code-to-constant map
FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE_TO_STR = {
    BGP_ERROR_MESSAGE_HEADER: FTL_ATTR_BGP_NOTIFICATION_ERROR_MESSAGE_HEADER_TO_STR,
    BGP_ERROR_OPEN_MESSAGE:   FTL_ATTR_BGP_NOTIFICATION_ERROR_OPEN_MESSAGE_TO_STR,
    BGP_ERROR_UPDATE_MESSAGE: FTL_ATTR_BGP_NOTIFICATION_ERROR_UPDATE_MESSAGE_TO_STR,
    BGP_ERROR_FSM:            FTL_ATTR_BGP_NOTIFICATION_ERROR_FSM_TO_STR,
    BGP_ERROR_CEASE:          FTL_ATTR_BGP_NOTIFICATION_ERROR_CEASE_TO_STR,
    BGP_ERROR_ROUTE_REFRESH:  FTL_ATTR_BGP_NOTIFICATION_ERROR_ROUTE_REFRESH_TO_STR,
}

# BGP notification code/subcode constant-to-code map
FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE_FROM_STR = dict(
    message_header = FTL_ATTR_BGP_NOTIFICATION_ERROR_MESSAGE_HEADER_FROM_STR,
    open_message   = FTL_ATTR_BGP_NOTIFICATION_ERROR_OPEN_MESSAGE_FROM_STR,
    update_message = FTL_ATTR_BGP_NOTIFICATION_ERROR_UPDATE_MESSAGE_FROM_STR,
    fsm            = FTL_ATTR_BGP_NOTIFICATION_ERROR_FSM_FROM_STR,
    cease          = FTL_ATTR_BGP_NOTIFICATION_ERROR_CEASE_FROM_STR,
    route_refresh  = FTL_ATTR_BGP_NOTIFICATION_ERROR_ROUTE_REFRESH_FROM_STR,
)

######################
# BGP OPEN CONSTANTS #
######################

# BGP open capability types
(FTL_ATTR_BGP_OPEN_CAPABILITY_TO_STR,
 FTL_ATTR_BGP_OPEN_CAPABILITY_FROM_STR) = init_const_mappings(
    reserved_0                 = BGP_CAPABILITY_RESERVED_0,
    bgp4mp                     = BGP_CAPABILITY_BGP4MP,
    route_refresh              = BGP_CAPABILITY_ROUTE_REFRESH,
    outbound_filter            = BGP_CAPABILITY_OUTBOUND_FILTER,
    multiple_routes            = BGP_CAPABILITY_MULTIPLE_ROUTES,
    extended_next_hop          = BGP_CAPABILITY_EXTENDED_NEXT_HOP,
    bgp4mp_et                  = BGP_CAPABILITY_BGP4MP_ET,
    bgpsec                     = BGP_CAPABILITY_BGPSEC,
    multiple_labels            = BGP_CAPABILITY_MULTIPLE_LABELS,
    bgp_role                   = BGP_CAPABILITY_BGP_ROLE,
    graceful_restart           = BGP_CAPABILITY_GRACEFUL_RESTART,
    as4                        = BGP_CAPABILITY_AS4,
    unknown_66                 = BGP_CAPABILITY_UNKNOWN_66,
    dynamic                    = BGP_CAPABILITY_DYNAMIC,
    multisession               = BGP_CAPABILITY_MULTISESSION,
    addpath                    = BGP_CAPABILITY_ADDPATH,
    enhanced_route_refresh     = BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH,
    llgr                       = BGP_CAPABILITY_LLGR,
    policy_distribution        = BGP_CAPABILITY_POLICY_DISTRIBUTION,
    fqdn                       = BGP_CAPABILITY_FQDN,
    bfd                        = BGP_CAPABILITY_BFD,
    software_version           = BGP_CAPABILITY_SOFTWARE_VERSION,
    prestd_route_refresh       = BGP_CAPABILITY_PRESTD_ROUTE_REFRESH,
    prestd_policy_distribution = BGP_CAPABILITY_PRESTD_POLICY_DISTRIBUTION,
    prestd_outbound_filter     = BGP_CAPABILITY_PRESTD_OUTBOUND_FILTER,
    prestd_multisession        = BGP_CAPABILITY_PRESTD_MULTISESSION,
    prestd_fqdn                = BGP_CAPABILITY_PRESTD_FQDN,
    prestd_operational         = BGP_CAPABILITY_PRESTD_OPERATIONAL,
    reserved_255               = BGP_CAPABILITY_RESERVED_255,
)

#######################
# BGP STATS CONSTANTS #
#######################

# BGP stats MRT fixes integer types
FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH  = 0
FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH = 1
FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ADDPATH    = 2
FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH   = 3
FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_NLRI       = 4

# BGP stats MRT fixes string types
FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH_STR  = 'bgp4mp_addpath'
FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH_STR = 'bgp4mp_aslength'
FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ADDPATH_STR    = 'tdv2_addpath'
FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH_STR   = 'tdv2_aslength'
FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_NLRI_STR       = 'tdv2_nlri'

# BGP stats MRT fixes constants
(FTL_ATTR_BGP_STATS_MRT_FIXES_TO_STR,
 FTL_ATTR_BGP_STATS_MRT_FIXES_FROM_STR) = init_const_mappings(**{
    FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH_STR: FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH,
    FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH_STR: FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH,
    FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ADDPATH_STR: FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ADDPATH,
    FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH_STR: FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH,
    FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_NLRI_STR: FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_NLRI,
})

# BGP stats MRT entry type constants
(FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPE_TO_STR,
 FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPE_FROM_STR) = init_const_mappings(
    null          = MRT_NULL,
    start         = MRT_START,
    die           = MRT_DIE,
    i_am_dead     = MRT_I_AM_DEAD,
    peer_down     = MRT_PEER_DOWN,
    bgp           = MRT_BGP,
    rip           = MRT_RIP,
    idrp          = MRT_IDRP,
    ripng         = MRT_RIPNG,
    bgp4plus      = MRT_BGP4PLUS,
    bgp4plus_01   = MRT_BGP4PLUS_01,
    ospfv2        = MRT_OSPFV2,
    table_dump    = MRT_TABLE_DUMP,
    table_dump_v2 = MRT_TABLE_DUMP_V2,
    bgp4mp        = MRT_BGP4MP,
    bgp4mp_et     = MRT_BGP4MP_ET,
    isis          = MRT_ISIS,
    isis_et       = MRT_ISIS_ET,
    ospfv3        = MRT_OSPFV3,
    ospfv3_et     = MRT_OSPFV3_ET,
)

# BGP stats MRT entry subtype BGP4MP constants
(FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_TO_STR,
 FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_FROM_STR) = init_const_mappings(
    entry                     = MRT_BGP4MP_ENTRY,
    snapshot                  = MRT_BGP4MP_SNAPSHOT,
    state_change              = MRT_BGP4MP_STATE_CHANGE,
    state_change_as4          = MRT_BGP4MP_STATE_CHANGE_AS4,
    message                   = MRT_BGP4MP_MESSAGE,
    message_addpath           = MRT_BGP4MP_MESSAGE_ADDPATH,
    message_local             = MRT_BGP4MP_MESSAGE_LOCAL,
    message_local_addpath     = MRT_BGP4MP_MESSAGE_LOCAL_ADDPATH,
    message_as4               = MRT_BGP4MP_MESSAGE_AS4,
    message_as4_addpath       = MRT_BGP4MP_MESSAGE_AS4_ADDPATH,
    message_as4_local         = MRT_BGP4MP_MESSAGE_AS4_LOCAL,
    message_as4_local_addpath = MRT_BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH,
)

# BGP stats MRT entry subtype BGP4MP_ET constants
FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_ET_TO_STR = FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_TO_STR
FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_ET_FROM_STR = FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_FROM_STR

# BGP stats MRT entry subtype table dump v2 constants
(FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TABLE_DUMP_V2_TO_STR,
 FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TABLE_DUMP_V2_FROM_STR) = init_const_mappings(
    peer_index_table           = MRT_TABLE_DUMP_V2_PEER_INDEX_TABLE,
    geo_peer_table             = MRT_TABLE_DUMP_V2_GEO_PEER_TABLE,
    rib_generic                = MRT_TABLE_DUMP_V2_RIB_GENERIC,
    rib_generic_addpath        = MRT_TABLE_DUMP_V2_RIB_GENERIC_ADDPATH,
    rib_ipv4_unicast           = MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST,
    rib_ipv4_multicast         = MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST,
    rib_ipv6_unicast           = MRT_TABLE_DUMP_V2_RIB_IPV6_UNICAST,
    rib_ipv6_multicast         = MRT_TABLE_DUMP_V2_RIB_IPV6_MULTICAST,
    rib_ipv4_unicast_addpath   = MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST_ADDPATH,
    rib_ipv4_multicast_addpath = MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST_ADDPATH,
    rib_ipv6_unicast_addpath   = MRT_TABLE_DUMP_V2_RIB_IPV6_UNICAST_ADDPATH,
    rib_ipv6_multicast_addpath = MRT_TABLE_DUMP_V2_RIB_IPV6_MULTICAST_ADDPATH,
)

# BGP stats MRT entry subtype BGP constants
(FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP_TO_STR,
 FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP_FROM_STR) = init_const_mappings(
    null         = MRT_BGP_NULL,
    update       = MRT_BGP_UPDATE,
    pref_update  = MRT_BGP_PREF_UPDATE,
    state_change = MRT_BGP_STATE_CHANGE,
    sync         = MRT_BGP_SYNC,
    open         = MRT_BGP_OPEN,
    notify       = MRT_BGP_NOTIFY,
    keepalive    = MRT_BGP_KEEPALIVE,
)

 # BGP stats MRT entry subtype table dump constants
(FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TABLE_DUMP_TO_STR,
 FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TABLE_DUMP_FROM_STR) = init_const_mappings(
    afi_ipv4 = AFI_IPV4,
    afi_ipv6 = AFI_IPV6,
)

# BGP stats MRT entry type/subtype type-to-constant map
FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TO_STR = {
    MRT_BGP4MP:        FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_TO_STR,
    MRT_BGP4MP_ET:     FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_ET_TO_STR,
    MRT_TABLE_DUMP_V2: FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TABLE_DUMP_V2_TO_STR,
    MRT_BGP:           FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP_TO_STR,
    MRT_TABLE_DUMP:    FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TABLE_DUMP_TO_STR,
}

# BGP stats MRT entry type/subtype constant-to-type map
FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_FROM_STR = dict(
    bgp4mp        = FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_FROM_STR,
    bgp4mp_et     = FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_BGP4MP_ET_FROM_STR,
    table_dump_v2 = FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TABLE_DUMP_V2_FROM_STR,
)

# BGP stats BGP message type constants
(FTL_ATTR_BGP_STATS_BGP_MESSAGE_TYPE_TO_STR,
 FTL_ATTR_BGP_STATS_BGP_MESSAGE_TYPE_FROM_STR) = init_const_mappings(
    reserved      = BGP_BGP4MP_RESERVED,
    open          = BGP_BGP4MP_OPEN,
    update        = BGP_BGP4MP_UPDATE,
    notification  = BGP_BGP4MP_NOTIFICATION,
    keepalive     = BGP_BGP4MP_KEEPALIVE,
    route_refresh = BGP_BGP4MP_ROUTE_REFRESH,
)

# BGP stats capability type constants
FTL_ATTR_BGP_STATS_BGP_CAPABILITY_TYPE_TO_STR = FTL_ATTR_BGP_OPEN_CAPABILITY_TO_STR
FTL_ATTR_BGP_STATS_BGP_CAPABILITY_TYPE_FROM_STR = FTL_ATTR_BGP_OPEN_CAPABILITY_FROM_STR

# BGP stats BGP path attribute constants
(FTL_ATTR_BGP_STATS_BGP_PATH_ATTR_TO_STR,
 FTL_ATTR_BGP_STATS_BGP_PATH_ATTR_FORM_STR) = init_const_mappings(
    reserved                  = BGP_PATH_ATTR_RESERVED,
    origin                    = BGP_PATH_ATTR_ORIGIN,
    as_path                   = BGP_PATH_ATTR_AS_PATH,
    next_hop                  = BGP_PATH_ATTR_NEXT_HOP,
    multi_exit_disc           = BGP_PATH_ATTR_MULTI_EXIT_DISC,
    local_pref                = BGP_PATH_ATTR_LOCAL_PREF,
    atomic_aggregate          = BGP_PATH_ATTR_ATOMIC_AGGREGATE,
    aggregator                = BGP_PATH_ATTR_AGGREGATOR,
    communities               = BGP_PATH_ATTR_COMMUNITIES,
    originator_id             = BGP_PATH_ATTR_ORIGINATOR_ID,
    cluster_list              = BGP_PATH_ATTR_CLUSTER_LIST,
    dpa                       = BGP_PATH_ATTR_DPA,
    advertiser                = BGP_PATH_ATTR_ADVERTISER,
    rcid_cluster_id           = BGP_PATH_ATTR_RCID_CLUSTER_ID,
    mp_reach_nlri             = BGP_PATH_ATTR_MP_REACH_NLRI,
    mp_unreach_nlri           = BGP_PATH_ATTR_MP_UNREACH_NLRI,
    extended_communities      = BGP_PATH_ATTR_EXTENDED_COMMUNITIES,
    as4_path                  = BGP_PATH_ATTR_AS4_PATH,
    as4_aggregator            = BGP_PATH_ATTR_AS4_AGGREGATOR,
    safi_specific             = BGP_PATH_ATTR_SAFI_SPECIFIC,
    connector                 = BGP_PATH_ATTR_CONNECTOR,
    as_pathlimit              = BGP_PATH_ATTR_AS_PATHLIMIT,
    pmsi_tunnel               = BGP_PATH_ATTR_PMSI_TUNNEL,
    tunnel_encapsulation      = BGP_PATH_ATTR_TUNNEL_ENCAPSULATION,
    traffic_engineering       = BGP_PATH_ATTR_TRAFFIC_ENGINEERING,
    ipv6_extended_communities = BGP_PATH_ATTR_IPV6_EXTENDED_COMMUNITIES,
    aigp                      = BGP_PATH_ATTR_AIGP,
    pe_distinguisher_labels   = BGP_PATH_ATTR_PE_DISTINGUISHER_LABELS,
    entropy_label_capability  = BGP_PATH_ATTR_ENTROPY_LABEL_CAPABILITY,
    ls                        = BGP_PATH_ATTR_LS,
    vendor_30                 = BGP_PATH_ATTR_VENDOR_30,
    vendor_31                 = BGP_PATH_ATTR_VENDOR_31,
    large_communities         = BGP_PATH_ATTR_LARGE_COMMUNITIES,
    bgpsec_path               = BGP_PATH_ATTR_BGPSEC_PATH,
    community_container       = BGP_PATH_ATTR_COMMUNITY_CONTAINER,
    only_to_customer          = BGP_PATH_ATTR_ONLY_TO_CUSTOMER,
    domain_path               = BGP_PATH_ATTR_DOMAIN_PATH,
    sfp                       = BGP_PATH_ATTR_SFP,
    bfd_discriminator         = BGP_PATH_ATTR_BFD_DISCRIMINATOR,
    nhc_tmp                   = BGP_PATH_ATTR_NHC_TMP,
    prefix_sid                = BGP_PATH_ATTR_PREFIX_SID,
    attr_set                  = BGP_PATH_ATTR_ATTR_SET,
    vendor_129                = BGP_PATH_ATTR_VENDOR_129,
    vendor_241                = BGP_PATH_ATTR_VENDOR_241,
    vendor_242                = BGP_PATH_ATTR_VENDOR_242,
    vendor_243                = BGP_PATH_ATTR_VENDOR_243,
    reserved_for_dev          = BGP_PATH_ATTR_RESERVED_FOR_DEV,
)

#######################
# BGP ERROR CONSTANTS #
#######################

# BGP error source integer types
FTL_ATTR_BGP_ERROR_SOURCE_MRT    = 0
FTL_ATTR_BGP_ERROR_SOURCE_LGL    = 1
FTL_ATTR_BGP_ERROR_SOURCE_PARSER = 2

# BGP error source string types
FTL_ATTR_BGP_ERROR_SOURCE_MRT_STR    = FTL_MRT
FTL_ATTR_BGP_ERROR_SOURCE_LGL_STR    = FTL_LGL
FTL_ATTR_BGP_ERROR_SOURCE_PARSER_STR = FTL_PARSER

# BGP error source constants
(FTL_ATTR_BGP_ERROR_SOURCE_TO_STR,
 FTL_ATTR_BGP_ERROR_SOURCE_FROM_STR) = init_const_mappings(**{
    FTL_ATTR_BGP_ERROR_SOURCE_MRT_STR:    FTL_ATTR_BGP_ERROR_SOURCE_MRT,
    FTL_ATTR_BGP_ERROR_SOURCE_LGL_STR:    FTL_ATTR_BGP_ERROR_SOURCE_LGL,
    FTL_ATTR_BGP_ERROR_SOURCE_PARSER_STR: FTL_ATTR_BGP_ERROR_SOURCE_PARSER,
})

# BGP error scope integer types
FTL_ATTR_BGP_ERROR_SCOPE_BASE   = 0
FTL_ATTR_BGP_ERROR_SCOPE_FILE   = 1
FTL_ATTR_BGP_ERROR_SCOPE_HEADER = 2
FTL_ATTR_BGP_ERROR_SCOPE_FORMAT = 3
FTL_ATTR_BGP_ERROR_SCOPE_DATA   = 4

# BGP error scope string types
FTL_ATTR_BGP_ERROR_SCOPE_BASE_STR   = 'base'
FTL_ATTR_BGP_ERROR_SCOPE_FILE_STR   = 'file'
FTL_ATTR_BGP_ERROR_SCOPE_HEADER_STR = 'header'
FTL_ATTR_BGP_ERROR_SCOPE_FORMAT_STR = 'format'
FTL_ATTR_BGP_ERROR_SCOPE_DATA_STR   = 'data'

# BGP error scope constants
(FTL_ATTR_BGP_ERROR_SCOPE_TO_STR,
 FTL_ATTR_BGP_ERROR_SCOPE_FROM_STR) = init_const_mappings(**{
    FTL_ATTR_BGP_ERROR_SCOPE_BASE_STR:   FTL_ATTR_BGP_ERROR_SCOPE_BASE,
    FTL_ATTR_BGP_ERROR_SCOPE_FILE_STR:   FTL_ATTR_BGP_ERROR_SCOPE_FILE,
    FTL_ATTR_BGP_ERROR_SCOPE_HEADER_STR: FTL_ATTR_BGP_ERROR_SCOPE_HEADER,
    FTL_ATTR_BGP_ERROR_SCOPE_FORMAT_STR: FTL_ATTR_BGP_ERROR_SCOPE_FORMAT,
    FTL_ATTR_BGP_ERROR_SCOPE_DATA_STR:   FTL_ATTR_BGP_ERROR_SCOPE_DATA,
})

# BGP error reason integer types
FTL_ATTR_BGP_ERROR_REASON_RUNTIME          = 0
FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA     = 1
FTL_ATTR_BGP_ERROR_REASON_INVALID_TYPE     = 2
FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR     = 3
FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL = 4
FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX   = 5
FTL_ATTR_BGP_ERROR_REASON_INVALID_ASPATH   = 6
FTL_ATTR_BGP_ERROR_REASON_INVALID_AS       = 7
FTL_ATTR_BGP_ERROR_REASON_INVALID_IP       = 8

# BGP error reason string types
FTL_ATTR_BGP_ERROR_REASON_RUNTIME_STR          = 'runtime'
FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA_STR     = 'missing_data'
FTL_ATTR_BGP_ERROR_REASON_INVALID_TYPE_STR     = 'invalid_type'
FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR_STR     = 'invalid_attr'
FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL_STR = 'invalid_protocol'
FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX_STR   = 'invalid_prefix'
FTL_ATTR_BGP_ERROR_REASON_INVALID_ASPATH_STR   = 'invalid_aspath'
FTL_ATTR_BGP_ERROR_REASON_INVALID_AS_STR       = 'invalid_as'
FTL_ATTR_BGP_ERROR_REASON_INVALID_IP_STR       = 'invalid_ip'

# BGP error reason constants
(FTL_ATTR_BGP_ERROR_REASON_TO_STR,
 FTL_ATTR_BGP_ERROR_REASON_FROM_STR) = init_const_mappings(**{
    FTL_ATTR_BGP_ERROR_REASON_RUNTIME_STR:          FTL_ATTR_BGP_ERROR_REASON_RUNTIME,
    FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA_STR:     FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA,
    FTL_ATTR_BGP_ERROR_REASON_INVALID_TYPE_STR:     FTL_ATTR_BGP_ERROR_REASON_INVALID_TYPE,
    FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR_STR:     FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR,
    FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL_STR: FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL,
    FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX_STR:   FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX,
    FTL_ATTR_BGP_ERROR_REASON_INVALID_ASPATH_STR:   FTL_ATTR_BGP_ERROR_REASON_INVALID_ASPATH,
    FTL_ATTR_BGP_ERROR_REASON_INVALID_AS_STR:       FTL_ATTR_BGP_ERROR_REASON_INVALID_AS,
    FTL_ATTR_BGP_ERROR_REASON_INVALID_IP_STR:       FTL_ATTR_BGP_ERROR_REASON_INVALID_IP,
})
