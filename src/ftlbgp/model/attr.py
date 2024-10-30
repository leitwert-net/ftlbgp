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
from .util import FTL_ATTR_SHIFT_HUMAN
from .util import generate_spec_record
from .util import generate_spec_attributes

# Generic BGP record type attribute
FTL_ATTR_BGP_RECORD_TYPE = 1 << 0

# Generic BGP record type attribute (human-readable)
FTL_ATTR_BGP_RECORD_TYPE_HUMAN = FTL_ATTR_BGP_RECORD_TYPE << FTL_ATTR_SHIFT_HUMAN

#############################
# BGP PEER_TABLE ATTRIBUTES #
#############################

# Available BGP peer_table attributes
FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID = 1 << 1
FTL_ATTR_BGP_PEER_TABLE_VIEW_NAME        = 1 << 2
FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL    = 1 << 3
FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID      = 1 << 4
FTL_ATTR_BGP_PEER_TABLE_PEER_AS          = 1 << 5
FTL_ATTR_BGP_PEER_TABLE_PEER_IP          = 1 << 6

# Available BGP peer_table attributes (human-readable)
FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID_HUMAN = FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_PEER_TABLE_VIEW_NAME_HUMAN        = FTL_ATTR_BGP_PEER_TABLE_VIEW_NAME        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL_HUMAN    = FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL    << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID_HUMAN      = FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID      << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_PEER_TABLE_PEER_AS_HUMAN          = FTL_ATTR_BGP_PEER_TABLE_PEER_AS          << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_PEER_TABLE_PEER_IP_HUMAN          = FTL_ATTR_BGP_PEER_TABLE_PEER_IP          << FTL_ATTR_SHIFT_HUMAN

# BGP peer_table attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpPeerTable = generate_spec_record('FtlAttrsBgpPeerTable', (
    ('collector_bgp_id', FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID, False),
    ('view_name',        FTL_ATTR_BGP_PEER_TABLE_VIEW_NAME,        False),
    ('peer_protocol',    FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL,    True),
    ('peer_bgp_id',      FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID,      True),
    ('peer_as',          FTL_ATTR_BGP_PEER_TABLE_PEER_AS,          True),
    ('peer_ip',          FTL_ATTR_BGP_PEER_TABLE_PEER_IP,          True),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

###############################
# BGP STATE_CHANGE ATTRIBUTES #
###############################

# Available BGP state_change attributes
FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP     = 1 << 1
FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL = 1 << 2
FTL_ATTR_BGP_STATE_CHANGE_PEER_AS       = 1 << 3
FTL_ATTR_BGP_STATE_CHANGE_PEER_IP       = 1 << 4
FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE     = 1 << 5
FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE     = 1 << 6

# Available BGP state_change attributes (human-readable)
FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP_HUMAN     = FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP     << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL_HUMAN = FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATE_CHANGE_PEER_AS_HUMAN       = FTL_ATTR_BGP_STATE_CHANGE_PEER_AS       << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATE_CHANGE_PEER_IP_HUMAN       = FTL_ATTR_BGP_STATE_CHANGE_PEER_IP       << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE_HUMAN     = FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE     << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE_HUMAN     = FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE     << FTL_ATTR_SHIFT_HUMAN

# BGP state_change attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpStateChange = generate_spec_record('FtlAttrsBgpStateChange', (
    ('timestamp',     FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP,     True),
    ('peer_protocol', FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL, True),
    ('peer_as',       FTL_ATTR_BGP_STATE_CHANGE_PEER_AS,       True),
    ('peer_ip',       FTL_ATTR_BGP_STATE_CHANGE_PEER_IP,       True),
    ('old_state',     FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE,     True),
    ('new_state',     FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE,     True),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

########################
# BGP ROUTE ATTRIBUTES #
########################

# Available BGP route attributes
FTL_ATTR_BGP_ROUTE_SOURCE               = 1 << 1
FTL_ATTR_BGP_ROUTE_SEQUENCE             = 1 << 2
FTL_ATTR_BGP_ROUTE_TIMESTAMP            = 1 << 3
FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL        = 1 << 4
FTL_ATTR_BGP_ROUTE_PEER_BGP_ID          = 1 << 5
FTL_ATTR_BGP_ROUTE_PEER_AS              = 1 << 6
FTL_ATTR_BGP_ROUTE_PEER_IP              = 1 << 7
FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL     = 1 << 8
FTL_ATTR_BGP_ROUTE_NEXTHOP_IP           = 1 << 9
FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL      = 1 << 10
FTL_ATTR_BGP_ROUTE_PREFIX               = 1 << 11
FTL_ATTR_BGP_ROUTE_PATH_ID              = 1 << 12
FTL_ATTR_BGP_ROUTE_ASPATH               = 1 << 13
FTL_ATTR_BGP_ROUTE_ORIGIN               = 1 << 14
FTL_ATTR_BGP_ROUTE_COMMUNITIES          = 1 << 15
FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES    = 1 << 16
FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES = 1 << 17
FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC      = 1 << 18
FTL_ATTR_BGP_ROUTE_ATOMIC_AGGREGATE     = 1 << 19
FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL  = 1 << 20
FTL_ATTR_BGP_ROUTE_AGGREGATOR_AS        = 1 << 21
FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP        = 1 << 22
FTL_ATTR_BGP_ROUTE_ONLY_TO_CUSTOMER     = 1 << 23
FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID        = 1 << 24
FTL_ATTR_BGP_ROUTE_CLUSTER_LIST         = 1 << 25
FTL_ATTR_BGP_ROUTE_LOCAL_PREF           = 1 << 26
FTL_ATTR_BGP_ROUTE_ATTR_SET             = 1 << 27
FTL_ATTR_BGP_ROUTE_AS_PATHLIMIT         = 1 << 28
FTL_ATTR_BGP_ROUTE_AIGP                 = 1 << 29
FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN        = 1 << 30

# Available BGP route attributes (human-readable)
FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN               = FTL_ATTR_BGP_ROUTE_SOURCE               << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_SEQUENCE_HUMAN             = FTL_ATTR_BGP_ROUTE_SEQUENCE             << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_TIMESTAMP_HUMAN            = FTL_ATTR_BGP_ROUTE_TIMESTAMP            << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN        = FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_PEER_BGP_ID_HUMAN          = FTL_ATTR_BGP_ROUTE_PEER_BGP_ID          << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_PEER_AS_HUMAN              = FTL_ATTR_BGP_ROUTE_PEER_AS              << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_PEER_IP_HUMAN              = FTL_ATTR_BGP_ROUTE_PEER_IP              << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL_HUMAN     = FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL     << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_NEXTHOP_IP_HUMAN           = FTL_ATTR_BGP_ROUTE_NEXTHOP_IP           << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL_HUMAN      = FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL      << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_PREFIX_HUMAN               = FTL_ATTR_BGP_ROUTE_PREFIX               << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_PATH_ID_HUMAN              = FTL_ATTR_BGP_ROUTE_PATH_ID              << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_ASPATH_HUMAN               = FTL_ATTR_BGP_ROUTE_ASPATH               << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_ORIGIN_HUMAN               = FTL_ATTR_BGP_ROUTE_ORIGIN               << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_COMMUNITIES_HUMAN          = FTL_ATTR_BGP_ROUTE_COMMUNITIES          << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES_HUMAN    = FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES    << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES_HUMAN = FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC_HUMAN      = FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC      << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_ATOMIC_AGGREGATE_HUMAN     = FTL_ATTR_BGP_ROUTE_ATOMIC_AGGREGATE     << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL_HUMAN  = FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL  << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_AGGREGATOR_AS_HUMAN        = FTL_ATTR_BGP_ROUTE_AGGREGATOR_AS        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP_HUMAN        = FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_ONLY_TO_CUSTOMER_HUMAN     = FTL_ATTR_BGP_ROUTE_ONLY_TO_CUSTOMER     << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID_HUMAN        = FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_CLUSTER_LIST_HUMAN         = FTL_ATTR_BGP_ROUTE_CLUSTER_LIST         << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_LOCAL_PREF_HUMAN           = FTL_ATTR_BGP_ROUTE_LOCAL_PREF           << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_ATTR_SET_HUMAN             = FTL_ATTR_BGP_ROUTE_ATTR_SET             << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_AS_PATHLIMIT_HUMAN         = FTL_ATTR_BGP_ROUTE_AS_PATHLIMIT         << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_AIGP_HUMAN                 = FTL_ATTR_BGP_ROUTE_AIGP                 << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN_HUMAN        = FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN        << FTL_ATTR_SHIFT_HUMAN

# BGP route attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpRoute = generate_spec_record('FtlAttrsBgpRoute', (
    ('source',               FTL_ATTR_BGP_ROUTE_SOURCE,               True),
    ('sequence',             FTL_ATTR_BGP_ROUTE_SEQUENCE,             True),
    ('timestamp',            FTL_ATTR_BGP_ROUTE_TIMESTAMP,            True),
    ('peer_protocol',        FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL,        True),
    ('peer_bgp_id',          FTL_ATTR_BGP_ROUTE_PEER_BGP_ID,          True),
    ('peer_as',              FTL_ATTR_BGP_ROUTE_PEER_AS,              True),
    ('peer_ip',              FTL_ATTR_BGP_ROUTE_PEER_IP,              True),
    ('nexthop_protocol',     FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL,     True),
    ('nexthop_ip',           FTL_ATTR_BGP_ROUTE_NEXTHOP_IP,           True),
    ('prefix_protocol',      FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL,      True),
    ('prefix',               FTL_ATTR_BGP_ROUTE_PREFIX,               True),
    ('path_id',              FTL_ATTR_BGP_ROUTE_PATH_ID,              True),
    ('aspath',               FTL_ATTR_BGP_ROUTE_ASPATH,               True),
    ('origin',               FTL_ATTR_BGP_ROUTE_ORIGIN,               True),
    ('communities',          FTL_ATTR_BGP_ROUTE_COMMUNITIES,          True),
    ('large_communities',    FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES,    True),
    ('extended_communities', FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES, False),
    ('multi_exit_disc',      FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC,      False),
    ('atomic_aggregate',     FTL_ATTR_BGP_ROUTE_ATOMIC_AGGREGATE,     False),
    ('aggregator_protocol',  FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL,  False),
    ('aggregator_as',        FTL_ATTR_BGP_ROUTE_AGGREGATOR_AS,        False),
    ('aggregator_ip',        FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP,        False),
    ('only_to_customer',     FTL_ATTR_BGP_ROUTE_ONLY_TO_CUSTOMER,     False),
    ('originator_id',        FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID,        False),
    ('cluster_list',         FTL_ATTR_BGP_ROUTE_CLUSTER_LIST,         False),
    ('local_pref',           FTL_ATTR_BGP_ROUTE_LOCAL_PREF,           False),
    ('attr_set',             FTL_ATTR_BGP_ROUTE_ATTR_SET,             False),
    ('as_pathlimit',         FTL_ATTR_BGP_ROUTE_AS_PATHLIMIT,         False),
    ('aigp',                 FTL_ATTR_BGP_ROUTE_AIGP,                 False),
    ('attrs_unknown',        FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN,        False),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

#############################
# BGP KEEP_ALIVE ATTRIBUTES #
#############################

# Available BGP keep_alive attributes
FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP     = 1 << 1
FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL = 1 << 2
FTL_ATTR_BGP_KEEP_ALIVE_PEER_AS       = 1 << 3
FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP       = 1 << 4

# Available BGP keep_alive attributes (human-readable)
FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP_HUMAN     = FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP     << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL_HUMAN = FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_KEEP_ALIVE_PEER_AS_HUMAN       = FTL_ATTR_BGP_KEEP_ALIVE_PEER_AS       << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP_HUMAN       = FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP       << FTL_ATTR_SHIFT_HUMAN

# BGP keep_alive attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpKeepAlive = generate_spec_record('FtlAttrsBgpKeepAlive', (
    ('timestamp',     FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP,     True),
    ('peer_protocol', FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL, True),
    ('peer_as',       FTL_ATTR_BGP_KEEP_ALIVE_PEER_AS,       True),
    ('peer_ip',       FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP,       True),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

################################
# BGP ROUTE_REFRESH ATTRIBUTES #
################################

# Available BGP route_refresh attributes
FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP        = 1 << 1
FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL    = 1 << 2
FTL_ATTR_BGP_ROUTE_REFRESH_PEER_AS          = 1 << 3
FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP          = 1 << 4
FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL = 1 << 5

# Available BGP route_refresh attributes (human-readable)
FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP_HUMAN        = FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL_HUMAN    = FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL    << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_REFRESH_PEER_AS_HUMAN          = FTL_ATTR_BGP_ROUTE_REFRESH_PEER_AS          << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP_HUMAN          = FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP          << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL_HUMAN = FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL << FTL_ATTR_SHIFT_HUMAN

# BGP route_refresh attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpRouteRefresh = generate_spec_record('FtlAttrsBgpRouteRefresh', (
    ('timestamp',        FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP,        True),
    ('peer_protocol',    FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL,    True),
    ('peer_as',          FTL_ATTR_BGP_ROUTE_REFRESH_PEER_AS,          True),
    ('peer_ip',          FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP,          True),
    ('refresh_protocol', FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL, True),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

###############################
# BGP NOTIFICATION ATTRIBUTES #
###############################

# Available BGP notification attributes
FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP     = 1 << 1
FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL = 1 << 2
FTL_ATTR_BGP_NOTIFICATION_PEER_AS       = 1 << 3
FTL_ATTR_BGP_NOTIFICATION_PEER_IP       = 1 << 4
FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE    = 1 << 5
FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE = 1 << 6
FTL_ATTR_BGP_NOTIFICATION_DATA          = 1 << 7

# Available BGP notification attributes (human-readable)
FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP_HUMAN     = FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP     << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL_HUMAN = FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_NOTIFICATION_PEER_AS_HUMAN       = FTL_ATTR_BGP_NOTIFICATION_PEER_AS       << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_NOTIFICATION_PEER_IP_HUMAN       = FTL_ATTR_BGP_NOTIFICATION_PEER_IP       << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE_HUMAN    = FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE    << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE_HUMAN = FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_NOTIFICATION_DATA_HUMAN          = FTL_ATTR_BGP_NOTIFICATION_DATA          << FTL_ATTR_SHIFT_HUMAN

# BGP notification attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpNotification = generate_spec_record('FtlAttrsBgpNotification', (
    ('timestamp',     FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP,     True),
    ('peer_protocol', FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL, True),
    ('peer_as',       FTL_ATTR_BGP_NOTIFICATION_PEER_AS,       True),
    ('peer_ip',       FTL_ATTR_BGP_NOTIFICATION_PEER_IP,       True),
    ('error_code',    FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE,    True),
    ('error_subcode', FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE, True),
    ('data',          FTL_ATTR_BGP_NOTIFICATION_DATA,          True),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

#######################
# BGP OPEN ATTRIBUTES #
#######################

# Available BGP open attributes
FTL_ATTR_BGP_OPEN_TIMESTAMP      = 1 << 1
FTL_ATTR_BGP_OPEN_PEER_PROTOCOL  = 1 << 2
FTL_ATTR_BGP_OPEN_PEER_AS        = 1 << 3
FTL_ATTR_BGP_OPEN_PEER_IP        = 1 << 4
FTL_ATTR_BGP_OPEN_VERSION        = 1 << 5
FTL_ATTR_BGP_OPEN_MY_AS          = 1 << 6
FTL_ATTR_BGP_OPEN_HOLD_TIME      = 1 << 7
FTL_ATTR_BGP_OPEN_BGP_ID         = 1 << 8
FTL_ATTR_BGP_OPEN_CAPABILITIES   = 1 << 9
FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN = 1 << 10

# Available BGP open attributes (human-readable)
FTL_ATTR_BGP_OPEN_TIMESTAMP_HUMAN      = FTL_ATTR_BGP_OPEN_TIMESTAMP      << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_PEER_PROTOCOL_HUMAN  = FTL_ATTR_BGP_OPEN_PEER_PROTOCOL  << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_PEER_AS_HUMAN        = FTL_ATTR_BGP_OPEN_PEER_AS        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_PEER_IP_HUMAN        = FTL_ATTR_BGP_OPEN_PEER_IP        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_VERSION_HUMAN        = FTL_ATTR_BGP_OPEN_VERSION        << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_MY_AS_HUMAN          = FTL_ATTR_BGP_OPEN_MY_AS          << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_HOLD_TIME_HUMAN      = FTL_ATTR_BGP_OPEN_HOLD_TIME      << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_BGP_ID_HUMAN         = FTL_ATTR_BGP_OPEN_BGP_ID         << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_CAPABILITIES_HUMAN   = FTL_ATTR_BGP_OPEN_CAPABILITIES   << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN_HUMAN = FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN << FTL_ATTR_SHIFT_HUMAN

# BGP open attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpOpen = generate_spec_record('FtlAttrsBgpOpen', (
    ('timestamp',      FTL_ATTR_BGP_OPEN_TIMESTAMP,      True),
    ('peer_protocol',  FTL_ATTR_BGP_OPEN_PEER_PROTOCOL,  True),
    ('peer_as',        FTL_ATTR_BGP_OPEN_PEER_AS,        True),
    ('peer_ip',        FTL_ATTR_BGP_OPEN_PEER_IP,        True),
    ('version',        FTL_ATTR_BGP_OPEN_VERSION,        True),
    ('my_as',          FTL_ATTR_BGP_OPEN_MY_AS,          True),
    ('hold_time',      FTL_ATTR_BGP_OPEN_HOLD_TIME,      True),
    ('bgp_id',         FTL_ATTR_BGP_OPEN_BGP_ID,         True),
    ('capabilities',   FTL_ATTR_BGP_OPEN_CAPABILITIES,   True),
    ('params_unknown', FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN, False),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

########################
# BGP STATS ATTRIBUTES #
########################

# Available BGP stats attributes
FTL_ATTR_BGP_STATS_PARSER_LIFETIME          = 1 << 1
FTL_ATTR_BGP_STATS_PARSER_RUNTIME           = 1 << 2
FTL_ATTR_BGP_STATS_PARSER_ERRORS            = 1 << 3
FTL_ATTR_BGP_STATS_LGL_RUNTIME              = 1 << 4
FTL_ATTR_BGP_STATS_LGL_ENTRIES              = 1 << 5
FTL_ATTR_BGP_STATS_LGL_ERRORS               = 1 << 6
FTL_ATTR_BGP_STATS_MRT_RUNTIME              = 1 << 7
FTL_ATTR_BGP_STATS_MRT_ENTRIES              = 1 << 8
FTL_ATTR_BGP_STATS_MRT_ERRORS               = 1 << 9
FTL_ATTR_BGP_STATS_MRT_FIXES                = 1 << 10
FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES      = 1 << 11
FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES    = 1 << 12
FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES  = 1 << 13
FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES = 1 << 14
FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4      = 1 << 15
FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6      = 1 << 16
FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV4 = 1 << 17
FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV6 = 1 << 18
FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV4 = 1 << 19
FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV6 = 1 << 20

# Available BGP stats attributes (human-readable)
FTL_ATTR_BGP_STATS_PARSER_LIFETIME_HUMAN          = FTL_ATTR_BGP_STATS_PARSER_LIFETIME          << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_PARSER_RUNTIME_HUMAN           = FTL_ATTR_BGP_STATS_PARSER_RUNTIME           << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_PARSER_ERRORS_HUMAN            = FTL_ATTR_BGP_STATS_PARSER_ERRORS            << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_LGL_RUNTIME_HUMAN              = FTL_ATTR_BGP_STATS_LGL_RUNTIME              << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_LGL_ENTRIES_HUMAN              = FTL_ATTR_BGP_STATS_LGL_ENTRIES              << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_LGL_ERRORS_HUMAN               = FTL_ATTR_BGP_STATS_LGL_ERRORS               << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_MRT_RUNTIME_HUMAN              = FTL_ATTR_BGP_STATS_MRT_RUNTIME              << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_MRT_ENTRIES_HUMAN              = FTL_ATTR_BGP_STATS_MRT_ENTRIES              << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_MRT_ERRORS_HUMAN               = FTL_ATTR_BGP_STATS_MRT_ERRORS               << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN                = FTL_ATTR_BGP_STATS_MRT_FIXES                << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES_HUMAN      = FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES      << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES_HUMAN    = FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES    << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES_HUMAN  = FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES  << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES_HUMAN = FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4_HUMAN      = FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4      << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6_HUMAN      = FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6      << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV4_HUMAN = FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV4 << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV6_HUMAN = FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV6 << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV4_HUMAN = FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV4 << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV6_HUMAN = FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV6 << FTL_ATTR_SHIFT_HUMAN

# BGP stats attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpStats = generate_spec_record('FtlAttrsBgpStats', (
    ('parser_lifetime',          FTL_ATTR_BGP_STATS_PARSER_LIFETIME,          True),
    ('parser_runtime',           FTL_ATTR_BGP_STATS_PARSER_RUNTIME,           True),
    ('parser_errors',            FTL_ATTR_BGP_STATS_PARSER_ERRORS,            True),
    ('lgl_runtime',              FTL_ATTR_BGP_STATS_LGL_RUNTIME,              True),
    ('lgl_entries',              FTL_ATTR_BGP_STATS_LGL_ENTRIES,              True),
    ('lgl_errors',               FTL_ATTR_BGP_STATS_LGL_ERRORS,               True),
    ('mrt_runtime',              FTL_ATTR_BGP_STATS_MRT_RUNTIME,              True),
    ('mrt_entries',              FTL_ATTR_BGP_STATS_MRT_ENTRIES,              True),
    ('mrt_errors',               FTL_ATTR_BGP_STATS_MRT_ERRORS,               True),
    ('mrt_fixes',                FTL_ATTR_BGP_STATS_MRT_FIXES,                True),
    ('mrt_bgp_entry_types',      FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES,      True),
    ('mrt_bgp_message_types',    FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES,    True),
    ('mrt_bgp_attribute_types',  FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES,  True),
    ('mrt_bgp_capability_types', FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES, True),
    ('bgp_routes_rib_ipv4',      FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4,      True),
    ('bgp_routes_rib_ipv6',      FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6,      True),
    ('bgp_routes_announce_ipv4', FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV4, True),
    ('bgp_routes_announce_ipv6', FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV6, True),
    ('bgp_routes_withdraw_ipv4', FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV4, True),
    ('bgp_routes_withdraw_ipv6', FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV6, True),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

########################
# BGP ERROR ATTRIBUTES #
########################

# Available BGP error attributes
FTL_ATTR_BGP_ERROR_SOURCE  = 1 << 1
FTL_ATTR_BGP_ERROR_SCOPE   = 1 << 2
FTL_ATTR_BGP_ERROR_RECORD  = 1 << 3
FTL_ATTR_BGP_ERROR_REASON  = 1 << 4
FTL_ATTR_BGP_ERROR_MESSAGE = 1 << 5
FTL_ATTR_BGP_ERROR_DATA    = 1 << 6
FTL_ATTR_BGP_ERROR_TRACE   = 1 << 7

# Available BGP error attributes (human-readable)
FTL_ATTR_BGP_ERROR_SOURCE_HUMAN  = FTL_ATTR_BGP_ERROR_SOURCE  << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ERROR_SCOPE_HUMAN   = FTL_ATTR_BGP_ERROR_SCOPE   << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ERROR_RECORD_HUMAN  = FTL_ATTR_BGP_ERROR_RECORD  << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ERROR_REASON_HUMAN  = FTL_ATTR_BGP_ERROR_REASON  << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ERROR_MESSAGE_HUMAN = FTL_ATTR_BGP_ERROR_MESSAGE << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ERROR_DATA_HUMAN    = FTL_ATTR_BGP_ERROR_DATA    << FTL_ATTR_SHIFT_HUMAN
FTL_ATTR_BGP_ERROR_TRACE_HUMAN   = FTL_ATTR_BGP_ERROR_TRACE   << FTL_ATTR_SHIFT_HUMAN

# BGP error attribute specification
# [Format] spec := (field, value, default)
FtlAttrsBgpError = generate_spec_record('FtlAttrsBgpError', (
    ('source',  FTL_ATTR_BGP_ERROR_SOURCE,  True),
    ('scope',   FTL_ATTR_BGP_ERROR_SCOPE,   True),
    ('record',  FTL_ATTR_BGP_ERROR_RECORD,  True),
    ('reason',  FTL_ATTR_BGP_ERROR_REASON,  True),
    ('message', FTL_ATTR_BGP_ERROR_MESSAGE, True),
    ('data',    FTL_ATTR_BGP_ERROR_DATA,    True),
    ('trace',   FTL_ATTR_BGP_ERROR_TRACE,   True),
), typed=FTL_ATTR_BGP_RECORD_TYPE)

######################
# ALL BGP ATTRIBUTES #
######################

# BGP attribute spec
FtlAttrsBgp = generate_spec_attributes('FtlAttrsBgp', (
    FtlAttrsBgpPeerTable,
    FtlAttrsBgpStateChange,
    FtlAttrsBgpRoute,
    FtlAttrsBgpKeepAlive,
    FtlAttrsBgpRouteRefresh,
    FtlAttrsBgpNotification,
    FtlAttrsBgpOpen,
    FtlAttrsBgpStats,
    FtlAttrsBgpError,
))