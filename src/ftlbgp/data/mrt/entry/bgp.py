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
from .const import MRT_BGP_UPDATE
from .const import MRT_BGP_OPEN
from .const import MRT_BGP_NOTIFY
from .const import MRT_BGP_KEEPALIVE
from .const import MRT_BGP_STATE_CHANGE
from ..bgp.const import BGP_BGP4MP_UPDATE
from ..bgp.const import BGP_BGP4MP_KEEPALIVE
from ..bgp.const import BGP_BGP4MP_NOTIFICATION
from ..bgp.const import BGP_BGP4MP_OPEN
from ..bgp.msg import unpack_mrt_bgp_msg
from ...util import CACHE_TS
from ...const import IPV4
from ...const import IPV4_STR
from ...const import AF_INET
from ...const import STRUCT_2B
from ...const import STRUCT_4B
from ...const import DATETIME_FORMAT_USEC
from ...const import DATETIME_FORMAT_MIN
from ...const import struct_unpack
from ...const import socket_inet_ntop
from ...const import datetime_utcfromtimestamp
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_AS
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_IP
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATE_CHANGE_NEW_STATE_HUMAN
from ....model.const import FTL_ATTR_BGP_STATE_CHANGE_STATE_TO_STR
from ....model.record import FTL_RECORD_BGP_STATE_CHANGE


def unpack_mrt_entry_bgp(caches, stats_record, bgp_error, state_change_records, route_records, keep_alive_records,
                         route_refresh_records, notification_records, open_records, entry_bytes, mrt_subtype, sequence,
                         ts):
    """ Parse MRT BGP entry.
    """
    ###############
    # BGP PARSING #
    ###############

    # Prepare byte offset
    offset = 0

    ####################
    # BGP STATE_CHANGE #
    ####################

    # -------------------------------------------
    # [draft-ietf-grow-mrt-07] BGP_UPDATE Subtype
    # -------------------------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Peer AS number        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Peer IP address                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |            Old State          |          New State            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Parse state change message
    if mrt_subtype == MRT_BGP_STATE_CHANGE:

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
                state_change_record[FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL] = IPV4_STR
            else:
                state_change_record[FTL_ATTR_BGP_STATE_CHANGE_PEER_PROTOCOL] = IPV4

        # Add peer AS to state change record
        if FTL_ATTR_BGP_STATE_CHANGE_PEER_AS >= 0:
            peer_as = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
            state_change_record[FTL_ATTR_BGP_STATE_CHANGE_PEER_AS] = peer_as
        offset += 2

        # Add peer IP to state change record
        if FTL_ATTR_BGP_STATE_CHANGE_PEER_IP >= 0:
            peer_ip = entry_bytes[offset:offset + 4]
            if FTL_ATTR_BGP_STATE_CHANGE_PEER_IP_HUMAN:
                peer_ip = socket_inet_ntop(AF_INET, peer_ip)
            else:
                peer_ip = struct_unpack(STRUCT_4B, peer_ip)[0]
            state_change_record[FTL_ATTR_BGP_STATE_CHANGE_PEER_IP] = peer_ip
        offset += 4

        # Add old state to state change record
        if FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE >= 0:
            old_state = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
            if FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE_HUMAN:
                old_state = FTL_ATTR_BGP_STATE_CHANGE_STATE_TO_STR.get(old_state, str(old_state))
            state_change_record[FTL_ATTR_BGP_STATE_CHANGE_OLD_STATE] = old_state
        offset += 2

        # Add new state to state change record
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

    ##############
    # BGP UPDATE #
    ##############

    # -------------------------------------------
    # [draft-ietf-grow-mrt-07] BGP_UPDATE Subtype
    # -------------------------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Peer AS number        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Peer IP address                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |        Local AS number        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Local IP address                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    BGP UPDATE Contents (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Parse peer AS
    peer_as = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
    offset += 2

    # Parse peer IP
    peer_ip = entry_bytes[offset:offset + 4]
    offset += 4

    # Skip local AS
    offset += 2

    # Skip local IP
    offset += 4

    # Parse message type
    mtype = None
    if mrt_subtype == MRT_BGP_UPDATE:
        mtype = BGP_BGP4MP_UPDATE
    elif mrt_subtype == MRT_BGP_KEEPALIVE:
        mtype = BGP_BGP4MP_KEEPALIVE
    elif mrt_subtype == MRT_BGP_NOTIFY:
        mtype = BGP_BGP4MP_NOTIFICATION
    elif mrt_subtype == MRT_BGP_OPEN:
        mtype = BGP_BGP4MP_OPEN

    # Parse message
    if mtype is not None:
        msg_bytes = entry_bytes[offset:]
        yield from unpack_mrt_bgp_msg(caches, stats_record, bgp_error, route_records, keep_alive_records,
                                      route_refresh_records, notification_records, open_records, msg_bytes, mtype,
                                      sequence, ts, peer_as, peer_ip, AF_INET, aslen=2)
