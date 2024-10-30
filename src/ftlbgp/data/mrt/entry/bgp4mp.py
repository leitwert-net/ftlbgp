# -*- coding: utf-8 -*-
# pylint: disable=I0011,I0020,I0021,I0023
# pylint: disable=W0149,W0717,R0902,R0904,R0911,R0912,R0913,R0914,R0915,R1702,R1734,R1735,R2044,R6103,C0103,C0209,C2001
# pylint: enable=I0011
""" ftlbgp
Copyright (C) 2014-2024 Leitwert GmbH

This software is distributed under the terms of the MIT license.
It can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Author Johann SCHLAMP <schlamp@leitwert.net>
"""

# Local imports
from .const import MRT_BGP4MP_ENTRY_ANY
from .const import MRT_BGP4MP_ENTRY_AS4_ANY
from .const import MRT_BGP4MP_ENTRY_ADDPATH_ANY
from .const import MRT_BGP4MP_STATE_CHANGE
from .const import MRT_BGP4MP_STATE_CHANGE_AS4
from ..bgp.msg import unpack_mrt_bgp_msg
from ...util import CACHE_TS
from ...const import IPV4
from ...const import IPV6
from ...const import IPV4_STR
from ...const import IPV6_STR
from ...const import AF_INET
from ...const import AF_INET6
from ...const import AFI_IPV4
from ...const import AFI_IPV6
from ...const import STRUCT_2B
from ...const import STRUCT_4B
from ...const import STRUCT_8B8B
from ...const import DATETIME_FORMAT_USEC
from ...const import DATETIME_FORMAT_MIN
from ...const import struct_unpack
from ...const import socket_inet_ntop
from ...const import datetime_utcfromtimestamp
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_AS
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_IP
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES_HUMAN
from ....model.const import FTL_ATTR_BGP_STATE_CHANGE_STATE_TO_STR
from ....model.const import FTL_ATTR_BGP_STATS_BGP_MESSAGE_TYPE_TO_STR
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_TYPE
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL
from ....model.record import FTL_RECORD_BGP_STATE_CHANGE
from ....model.record import FTL_RECORD_BGP_STATS
from ....model.error import FtlMrtDataError


def unpack_mrt_entry_bgp4mp(caches, stats_record, bgp_error, state_change_records, route_records, keep_alive_records,
                            route_refresh_records, notification_records, open_records, entry_bytes, mrt_subtype,
                            sequence, ts):
    """ Parse MRT BGP4MP entry.
    """
    # Check for AS4 support
    aslen, asbytelen = 2, STRUCT_2B
    if mrt_subtype in MRT_BGP4MP_ENTRY_AS4_ANY:
        aslen, asbytelen = 4, STRUCT_4B

    # Check MRT entry subtype
    elif mrt_subtype not in MRT_BGP4MP_ENTRY_ANY:
        yield from bgp_error(FtlMrtDataError(f'Unknown MRT subtype ({mrt_subtype}) for BGP4MP entry',
                                             reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_TYPE, data=entry_bytes))
        return

    ##################
    # BGP4MP PARSING #
    ##################

    # ----------------------------------------------------
    # [RFC8050] 3. MRT Subtypes for Types BGP4MP/BGP4MP_ET
    # ----------------------------------------------------
    # This document defines the following new subtypes:
    #  o  BGP4MP_MESSAGE_ADDPATH
    #  o  BGP4MP_MESSAGE_AS4_ADDPATH
    #  o  BGP4MP_MESSAGE_LOCAL_ADDPATH
    #  o  BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH

    # Check for ADD-PATH entry (RFC7911)
    addpath = mrt_subtype in MRT_BGP4MP_ENTRY_ADDPATH_ANY

    # Prepare byte offset
    offset = 0

    # ----------------------------------------------------------------------------
    # [RFC6396] 4.4.1. BGP4MP_STATE_CHANGE Subtype / 4.4.2. BGP4MP_MESSAGE Subtype
    # ----------------------------------------------------------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Peer AS Number        |        Local AS Number        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |        Interface Index        |        Address Family         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Peer IP Address (variable)               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Local IP Address (variable)              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # ------------------------------------------------------------------------------------
    # [RFC6396] 4.4.3. BGP4MP_MESSAGE_AS4 Subtype / 4.4.4. BGP4MP_STATE_CHANGE_AS4 Subtype
    # ------------------------------------------------------------------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Peer AS Number                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Local AS Number                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |        Interface Index        |        Address Family         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Peer IP Address (variable)               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Local IP Address (variable)              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Parse peer AS
    peer_as = struct_unpack(asbytelen, entry_bytes[offset:offset + aslen])[0]
    offset += aslen

    # Skip local AS
    offset += aslen

    # Skip interface index
    offset += 2

    # Parse AFI value
    afi = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
    offset += 2

    # Check AFI value
    if afi != AFI_IPV4 and afi != AFI_IPV6:  # pylint: disable=consider-using-in
        yield from bgp_error(FtlMrtDataError(f'Unknown AFI value ({afi}) in BGP4MP entry',
                                             reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=entry_bytes))
        return

    # Parse peer IP
    afinet, iplen = (AF_INET6, 16) if afi == AFI_IPV6 else (AF_INET, 4)
    peer_ip = entry_bytes[offset:offset + iplen]
    offset += iplen

    # Skip local IP
    offset += iplen

    #######################
    # BGP4MP STATE_CHANGE #
    #######################

    # ------------------------------------------------------------------------------------
    # [RFC6396] 4.4.1. BGP4MP_STATE_CHANGE Subtype / 4.4.4 BGP4MP_STATE_CHANGE_AS4 Subtype
    # ------------------------------------------------------------------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |            Old State          |          New State            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Handle state change entry
    # pylint: disable-next=consider-using-in
    if mrt_subtype == MRT_BGP4MP_STATE_CHANGE or mrt_subtype == MRT_BGP4MP_STATE_CHANGE_AS4:

        # Access state change template
        state_change_init, state_change_emit, _ = state_change_records

        # Initialize state change record
        state_change_record = list(state_change_init)

        # Add timestamp to state change record
        if FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP >= 0:
            ts_state_change = ts

            # Cache date string for minute-based timestamp
            if FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP_HUMAN:
                if caches:
                    ts_cache = caches[CACHE_TS]
                    ts_min, ts_sec = divmod(ts_state_change, 60)
                    ts_cached = ts_cache.get(ts_min, None)
                    if ts_cached is None:
                        ts_cached = datetime_utcfromtimestamp(ts).strftime(DATETIME_FORMAT_MIN)
                        ts_cache[ts_min] = ts_cached

                    # Add seconds and microseconds
                    ts_state_change = f'{ts_cached}:{ts_sec:09.6f}'

                # Do not use cache
                else:
                    ts_state_change = datetime_utcfromtimestamp(ts_state_change).strftime(DATETIME_FORMAT_USEC)

            # Add timestamp
            state_change_record[FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP] = ts_state_change

        # Add peer protocol to state change record
        if FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL >= 0:
            if FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL_HUMAN:
                state_change_record[FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL] = (IPV6_STR if afinet == AF_INET6
                                                                                else IPV4_STR)
            else:
                state_change_record[FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL] = IPV6 if afinet == AF_INET6 else IPV4

        # Add peer AS to state change record
        if FTL_ATTR_BGP_STATE_CHANGE_PEER_AS >= 0:
            state_change_record[FTL_ATTR_BGP_STATE_CHANGE_PEER_AS] = peer_as

        # Add peer IP to state change record
        if FTL_ATTR_BGP_STATE_CHANGE_PEER_IP >= 0:
            peer_ip_state_change = peer_ip
            if FTL_ATTR_BGP_STATE_CHANGE_PEER_IP_HUMAN:
                peer_ip_state_change = socket_inet_ntop(afinet, peer_ip_state_change)
            elif afinet == AF_INET6:
                net, host = struct_unpack(STRUCT_8B8B, peer_ip_state_change)
                peer_ip_state_change = (net << 64) + host
            else:
                peer_ip_state_change = struct_unpack(STRUCT_4B, peer_ip_state_change)[0]
            state_change_record[FTL_ATTR_BGP_STATE_CHANGE_PEER_IP] = peer_ip_state_change

        # Parse old state
        if FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE >= 0:
            old_state = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
            if FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE_HUMAN:
                old_state = FTL_ATTR_BGP_STATE_CHANGE_STATE_TO_STR.get(old_state, str(old_state))
            state_change_record[FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE] = old_state
        offset += 2

        # Parse new state
        if FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE >= 0:
            new_state = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
            if FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE_HUMAN:
                new_state = FTL_ATTR_BGP_STATE_CHANGE_STATE_TO_STR.get(new_state, str(new_state))
            state_change_record[FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE] = new_state
        offset += 2

        # Yield final state change record
        if FTL_RECORD_BGP_STATE_CHANGE:
            yield state_change_emit(state_change_record)
        return

    ##################
    # BGP4MP MESSAGE #
    ##################

    # ---------------------------------------------------------------------------
    # [RFC6396] 4.4.2. BGP4MP_MESSAGE Subtype / 4.4.3. BGP4MP_MESSAGE_AS4 Subtype
    # ---------------------------------------------------------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    BGP Message... (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # -----------------------------------
    # [RFC4271] 4.1 Message Header Format
    # -----------------------------------
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # +                                                               +
    # |                                                               |
    # +                                                               +
    # |                           Marker                              |
    # +                                                               +
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Length               |      Type     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Skip marker
    offset += 16

    # Skip message length
    offset += 2

    # Parse message type
    mtype = entry_bytes[offset]
    offset += 1

    # Update stats record
    if FTL_RECORD_BGP_STATS:

        # Add BGP message type
        if FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES >= 0:
            bgptype = mtype
            if FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES_HUMAN:
                bgptype = FTL_ATTR_BGP_STATS_BGP_MESSAGE_TYPE_TO_STR.get(mtype, mtype)
            bgptype = str(bgptype)
            stats_record_mrt_bgp_msg = stats_record[FTL_ATTR_BGP_STATS_MRT_BGP_MESSAGE_TYPES]
            stats_record_mrt_bgp_msg[bgptype] = stats_record_mrt_bgp_msg.get(bgptype, 0) + 1

    # Parse message
    msg_bytes = entry_bytes[offset:]
    yield from unpack_mrt_bgp_msg(caches, stats_record, bgp_error, route_records, keep_alive_records,
                                  route_refresh_records, notification_records, open_records, msg_bytes, mtype, sequence,
                                  ts, peer_as, peer_ip, afinet, aslen=aslen, addpath=addpath)
