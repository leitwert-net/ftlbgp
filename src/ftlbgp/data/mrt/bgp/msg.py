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

# System imports
import base64

# Local imports
from .const import BGP_SAFI_UNICAST
from .const import BGP_SAFI_MULTICAST
from .const import BGP_BGP4MP_UPDATE
from .const import BGP_BGP4MP_KEEPALIVE
from .const import BGP_BGP4MP_ROUTE_REFRESH
from .const import BGP_BGP4MP_NOTIFICATION
from .const import BGP_BGP4MP_OPEN
from .const import BGP_PARAMS_CAPABILITIES
from .nlri import unpack_mrt_bgp_nlri
from .attr import unpack_mrt_bgp_attr
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
from ....model.attr import FTL_ATTR_BGP_ROUTE_SOURCE
from ....model.attr import FTL_ATTR_BGP_ROUTE_SEQUENCE
from ....model.attr import FTL_ATTR_BGP_ROUTE_TIMESTAMP
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_AS
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_IP
from ....model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_IP
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX
from ....model.attr import FTL_ATTR_BGP_ROUTE_PATH_ID
from ....model.attr import FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP
from ....model.attr import FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_KEEP_ALIVE_PEER_AS
from ....model.attr import FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP
from ....model.attr import FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_PEER_AS
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_PEER_AS
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_PEER_IP
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_DATA
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE_HUMAN
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE_HUMAN
from ....model.attr import FTL_ATTR_BGP_NOTIFICATION_DATA_HUMAN
from ....model.attr import FTL_ATTR_BGP_OPEN_TIMESTAMP
from ....model.attr import FTL_ATTR_BGP_OPEN_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_OPEN_PEER_AS
from ....model.attr import FTL_ATTR_BGP_OPEN_PEER_IP
from ....model.attr import FTL_ATTR_BGP_OPEN_VERSION
from ....model.attr import FTL_ATTR_BGP_OPEN_MY_AS
from ....model.attr import FTL_ATTR_BGP_OPEN_HOLD_TIME
from ....model.attr import FTL_ATTR_BGP_OPEN_BGP_ID
from ....model.attr import FTL_ATTR_BGP_OPEN_CAPABILITIES
from ....model.attr import FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN
from ....model.attr import FTL_ATTR_BGP_OPEN_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_OPEN_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_OPEN_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_OPEN_BGP_ID_HUMAN
from ....model.attr import FTL_ATTR_BGP_OPEN_CAPABILITIES_HUMAN
from ....model.attr import FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV4
from ....model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV6
from ....model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV4
from ....model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV6
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES_HUMAN
from ....model.const import FTL_ATTR_BGP_ROUTE_SOURCE_ANNOUNCE
from ....model.const import FTL_ATTR_BGP_ROUTE_SOURCE_ANNOUNCE_STR
from ....model.const import FTL_ATTR_BGP_ROUTE_SOURCE_WITHDRAW
from ....model.const import FTL_ATTR_BGP_ROUTE_SOURCE_WITHDRAW_STR
from ....model.const import FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE_TO_STR
from ....model.const import FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE_TO_STR
from ....model.const import FTL_ATTR_BGP_OPEN_CAPABILITY_TO_STR
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL
from ....model.record import FTL_RECORD_BGP_ROUTE
from ....model.record import FTL_RECORD_BGP_KEEP_ALIVE
from ....model.record import FTL_RECORD_BGP_ROUTE_REFRESH
from ....model.record import FTL_RECORD_BGP_NOTIFICATION
from ....model.record import FTL_RECORD_BGP_OPEN
from ....model.record import FTL_RECORD_BGP_STATS
from ....model.error import FtlMrtDataError


def unpack_mrt_bgp_msg(caches, stats_record, bgp_error, route_records, keep_alive_records, route_refresh_records,
                       notification_records, open_records, msg_bytes, mtype, sequence, ts, peer_as, peer_ip, peer_afinet,
                       aslen=4, addpath=False):
    """ Parse MRT BGP/BGP4MP message.
    """
    # Prepare byte offset
    offset = 0

    ######################
    # BGP UPDATE MESSAGE #
    ######################

    # ------------------------------------
    # [RFC4271] 4.3. UPDATE Message Format
    # ------------------------------------
    # +-----------------------------------------------------+
    # |   Withdrawn Routes Length (2 octets)                |
    # +-----------------------------------------------------+
    # |   Withdrawn Routes (variable)                       |
    # +-----------------------------------------------------+
    # |   Total Path Attribute Length (2 octets)            |
    # +-----------------------------------------------------+
    # |   Path Attributes (variable)                        |
    # +-----------------------------------------------------+
    # |   Network Layer Reachability Information (variable) |
    # +-----------------------------------------------------+

    # Parse UPDATE message
    if mtype == BGP_BGP4MP_UPDATE:

        # Access route record template
        route_init, route_emit, route_error = route_records

        # Initialize route record reach
        route_record_reach = list(route_init)

        # Add source to route record reach
        if FTL_ATTR_BGP_ROUTE_SOURCE >= 0:
            if FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN:
                route_record_reach[FTL_ATTR_BGP_ROUTE_SOURCE] = FTL_ATTR_BGP_ROUTE_SOURCE_ANNOUNCE_STR
            else:
                route_record_reach[FTL_ATTR_BGP_ROUTE_SOURCE] = FTL_ATTR_BGP_ROUTE_SOURCE_ANNOUNCE

        # Add sequence number to route record reach
        if FTL_ATTR_BGP_ROUTE_SEQUENCE >= 0:
            route_record_reach[FTL_ATTR_BGP_ROUTE_SEQUENCE] = sequence

        # Add timestamp to route record reach
        if FTL_ATTR_BGP_ROUTE_TIMESTAMP >= 0:
            ts_route = ts

            # Cache date string for minute-based timestamp
            if FTL_ATTR_BGP_ROUTE_TIMESTAMP_HUMAN:
                if caches:
                    ts_cache = caches[CACHE_TS]
                    ts_min, ts_sec = divmod(ts_route, 60)
                    ts_cached = ts_cache.get(ts_min, None)
                    if ts_cached is None:
                        ts_cached = datetime_utcfromtimestamp(ts).strftime(DATETIME_FORMAT_MIN)
                        ts_cache[ts_min] = ts_cached

                    # Add seconds and microseconds
                    ts_route = f'{ts_cached}:{ts_sec:09.6f}'

                # Do not use cache
                else:
                    ts_route = datetime_utcfromtimestamp(ts_route).strftime(DATETIME_FORMAT_USEC)

            # Add timestamp
            route_record_reach[FTL_ATTR_BGP_ROUTE_TIMESTAMP] = ts_route

        # Add peer protocol to route record reach
        if FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL >= 0:
            if FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN:
                route_record_reach[FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL] = IPV6_STR if peer_afinet == AF_INET6 else IPV4_STR
            else:
                route_record_reach[FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL] = IPV6 if peer_afinet == AF_INET6 else IPV4

        # Add peer AS to route record reach
        if FTL_ATTR_BGP_ROUTE_PEER_AS >= 0:
            route_record_reach[FTL_ATTR_BGP_ROUTE_PEER_AS] = peer_as

        # Add peer IP to route record reach
        if FTL_ATTR_BGP_ROUTE_PEER_IP >= 0:
            peer_ip_route = peer_ip
            if FTL_ATTR_BGP_ROUTE_PEER_IP_HUMAN:
                peer_ip_route = socket_inet_ntop(peer_afinet, peer_ip_route)
            elif peer_afinet == AF_INET6:
                net, host = struct_unpack(STRUCT_8B8B, peer_ip_route)
                peer_ip_route = (net << 64) + host
            else:
                peer_ip_route = struct_unpack(STRUCT_4B, peer_ip_route)[0]
            route_record_reach[FTL_ATTR_BGP_ROUTE_PEER_IP] = peer_ip_route

        # Initialize route record unreach
        route_record_unreach = list(route_record_reach)

        # Add source to route record unreach
        if FTL_ATTR_BGP_ROUTE_SOURCE >= 0:
            if FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN:
                route_record_unreach[FTL_ATTR_BGP_ROUTE_SOURCE] = FTL_ATTR_BGP_ROUTE_SOURCE_WITHDRAW_STR
            else:
                route_record_unreach[FTL_ATTR_BGP_ROUTE_SOURCE] = FTL_ATTR_BGP_ROUTE_SOURCE_WITHDRAW

        # Initialize announced/withdrawn prefixes
        nlri, nlui = tuple(), tuple()

        # Parse UPDATE message data
        try:

            # Parse withdrawn routes length
            ulen = struct_unpack(STRUCT_2B, msg_bytes[offset:offset + 2])[0]
            offset += 2

            # Parse NLUI
            if ulen > 0:
                nlui = unpack_mrt_bgp_nlri(caches, stats_record, msg_bytes[offset:offset + ulen], AF_INET,
                                           addpath=addpath)
                offset += ulen

            # Parse attributes length
            alen = struct_unpack(STRUCT_2B, msg_bytes[offset:offset + 2])[0]
            offset += 2

            # Parse attributes
            # NOTE: BGP path attributes are applied to announced routes only (not valid for withdrawn routes)
            mp_nlri, mp_nlui = unpack_mrt_bgp_attr(caches, stats_record, route_init, route_emit, route_record_reach,
                                                   msg_bytes[offset:offset + alen], aslen=aslen, addpath=addpath)
            offset += alen

            # Parse NLRI
            rlen = len(msg_bytes) - offset
            if rlen > 0:
                nlri = unpack_mrt_bgp_nlri(caches, stats_record, msg_bytes[offset:offset + rlen], AF_INET,
                                           addpath=addpath)
                offset += rlen

            # Update NLUI/NLRI
            nlui += mp_nlui
            nlri += mp_nlri

        # Yield (or re-raise) UPDATE message errors
        except FtlMrtDataError as error:
            yield from route_error(error)
            return

        # -----------------------------------
        # [RFC4271] 4.3 UPDATE Message Format
        # -----------------------------------
        #
        # NOTE: The following procedure should be implemented by clients
        #
        # An UPDATE message SHOULD NOT include the same address prefix in the
        # WITHDRAWN ROUTES and Network Layer Reachability Information fields.
        # However, a BGP speaker MUST be able to process UPDATE messages in
        # this form. A BGP speaker SHOULD treat an UPDATE message of this form
        # as though the WITHDRAWN ROUTES do not contain the address prefix.

        # Finalize route records unreach (withdrawls)
        # NOTE: Human-readable conversions are done in unpack_mrt_bgp_attr() and unpack_mrt_bgp_nlri()
        for afinet, prefix_proto, prefix, path_id, _, _ in nlui:

            # Add prefix protocol to route record unreach
            if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL >= 0:
                route_record_unreach[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = prefix_proto

            # Add prefix to route record unreach
            if FTL_ATTR_BGP_ROUTE_PREFIX >= 0:
                route_record_unreach[FTL_ATTR_BGP_ROUTE_PREFIX] = prefix

            # Add ADD-PATH path ID to route record unreach
            if FTL_ATTR_BGP_ROUTE_PATH_ID >= 0:
                route_record_unreach[FTL_ATTR_BGP_ROUTE_PATH_ID] = path_id

            # Update stats record
            if FTL_RECORD_BGP_STATS:

                # Update IPv4 routes announced
                if afinet == AF_INET:
                    if FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV4 >= 0:
                        stats_record[FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV4] += 1

                # Update IPv6 routes announced
                elif afinet == AF_INET6:  # pylint: disable=confusing-consecutive-elif
                    if FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV6 >= 0:
                        stats_record[FTL_ATTR_BGP_STATS_BGP_ROUTES_WITHDRAW_IPV6] += 1

            # Yield final route record unreach
            if FTL_RECORD_BGP_ROUTE:
                yield route_emit(route_record_unreach)

        # Finalize route records reach (announcements)
        # NOTE: Human-readable conversions are done in unpack_mrt_bgp_attr() and unpack_mrt_bgp_nlri()
        for afinet, prefix_proto, prefix, path_id, nexthop_proto, nexthop_ip in nlri:

            # Initialize route record reach_mp
            # NOTE: Route records might contain a pre-MP NEXT_HOP attribute that applies to all pre-MP NLRIs,
            # NOTE: so records must be re-initialized for MP NLRI entries
            route_record_reach_mp = route_record_reach

            # Add nexthop protocol to route record reach_mp
            if FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL >= 0 and nexthop_proto is not None:
                route_record_reach_mp = list(route_record_reach)
                route_record_reach_mp[FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL] = nexthop_proto

                # Add nexthop IP to route record reach_mp
                if FTL_ATTR_BGP_ROUTE_NEXTHOP_IP >= 0:
                    route_record_reach_mp[FTL_ATTR_BGP_ROUTE_NEXTHOP_IP] = nexthop_ip

            # Add prefix protocol to route record reach_mp
            if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL >= 0:
                route_record_reach_mp[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = prefix_proto

            # Add prefix to route record reach_mp
            if FTL_ATTR_BGP_ROUTE_PREFIX >= 0:
                route_record_reach_mp[FTL_ATTR_BGP_ROUTE_PREFIX] = prefix

            # Add ADD-PATH path ID to route record reach_mp
            if FTL_ATTR_BGP_ROUTE_PATH_ID >= 0:
                route_record_reach_mp[FTL_ATTR_BGP_ROUTE_PATH_ID] = path_id

            # Update stats record
            if FTL_RECORD_BGP_STATS:

                # Update IPv4 routes withdrawn
                if afinet == AF_INET:
                    if FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV4 >= 0:
                        stats_record[FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV4] += 1

                # Update IPv6 routes withdrawn
                elif afinet == AF_INET6:  # pylint: disable=confusing-consecutive-elif
                    if FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV6 >= 0:
                        stats_record[FTL_ATTR_BGP_STATS_BGP_ROUTES_ANNOUNCE_IPV6] += 1

            # Yield final route record reach_mp
            if FTL_RECORD_BGP_ROUTE:
                yield route_emit(route_record_reach_mp)

    #########################
    # BGP KEEPALIVE MESSAGE #
    #########################

    # ---------------------------------------
    # [RFC4271] 4.4. KEEPALIVE Message Format
    # ---------------------------------------
    # A KEEPALIVE message consists of only the message header and has a
    # length of 19 octets.

    # Parse KEEPALIVE message
    elif mtype == BGP_BGP4MP_KEEPALIVE:

        # Access keep alive record template
        keep_alive_init, keep_alive_emit, _ = keep_alive_records

        # Initialize keep alive record
        keep_alive_record = list(keep_alive_init)

        # Add timestamp to keep alive record
        if FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP >= 0:
            ts_keep_alive = ts

            # Cache date string for minute-based timestamp
            if FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP_HUMAN:
                if caches:
                    ts_cache = caches[CACHE_TS]
                    ts_min, ts_sec = divmod(ts_keep_alive, 60)
                    ts_cached = ts_cache.get(ts_min, None)
                    if ts_cached is None:
                        ts_cached = datetime_utcfromtimestamp(ts).strftime(DATETIME_FORMAT_MIN)
                        ts_cache[ts_min] = ts_cached

                    # Add seconds and microseconds
                    ts_keep_alive = f'{ts_cached}:{ts_sec:09.6f}'

                # Do not use cache
                else:
                    ts_keep_alive = datetime_utcfromtimestamp(ts_keep_alive).strftime(DATETIME_FORMAT_USEC)

            # Add timestamp
            keep_alive_record[FTL_ATTR_BGP_KEEP_ALIVE_TIMESTAMP] = ts_keep_alive

        # Add peer protocol to keep alive record
        if FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL >= 0:
            if FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL_HUMAN:
                keep_alive_record[FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL] = (IPV6_STR if peer_afinet == AF_INET6
                                                                            else IPV4_STR)
            else:
                keep_alive_record[FTL_ATTR_BGP_KEEP_ALIVE_PEER_PROTOCOL] = IPV6 if peer_afinet == AF_INET6 else IPV4

        # Add peer AS to keep alive record
        if FTL_ATTR_BGP_KEEP_ALIVE_PEER_AS >= 0:
            keep_alive_record[FTL_ATTR_BGP_KEEP_ALIVE_PEER_AS] = peer_as

        # Add peer IP to keep alive record
        if FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP >= 0:
            peer_ip_keep_alive = peer_ip
            if FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP_HUMAN:
                peer_ip_keep_alive = socket_inet_ntop(peer_afinet, peer_ip_keep_alive)
            elif peer_afinet == AF_INET6:
                net, host = struct_unpack(STRUCT_8B8B, peer_ip_keep_alive)
                peer_ip_keep_alive = (net << 64) + host
            else:
                peer_ip_keep_alive = struct_unpack(STRUCT_4B, peer_ip_keep_alive)[0]
            keep_alive_record[FTL_ATTR_BGP_KEEP_ALIVE_PEER_IP] = peer_ip_keep_alive

        # Yield final keep alive record
        if FTL_RECORD_BGP_KEEP_ALIVE:
            yield keep_alive_emit(keep_alive_record)

    #############################
    # BGP ROUTE_REFRESH MESSAGE #
    #############################

    # ----------------------------------
    # [RFC2918] 3. Route-REFRESH Message
    # ----------------------------------
    # 0       7      15      23      31
    # +-------+-------+-------+-------+
    # |      AFI      | Res.  | SAFI  |
    # +-------+-------+-------+-------+

    # Parse ROUTE_REFRESH message
    elif mtype == BGP_BGP4MP_ROUTE_REFRESH:  # pylint: disable=confusing-consecutive-elif

        # Access route refresh template
        route_refresh_init, route_refresh_emit, _ = route_refresh_records

        # Initialize route refresh record
        route_refresh_record = list(route_refresh_init)

        # Add timestamp to route refresh record
        if FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP >= 0:
            ts_route_refresh = ts

            # Cache date string for minute-based timestamp
            if FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP_HUMAN:
                if caches:
                    ts_cache = caches[CACHE_TS]
                    ts_min, ts_sec = divmod(ts_route_refresh, 60)
                    ts_cached = ts_cache.get(ts_min, None)
                    if ts_cached is None:
                        ts_cached = datetime_utcfromtimestamp(ts).strftime(DATETIME_FORMAT_MIN)
                        ts_cache[ts_min] = ts_cached

                    # Add seconds and microseconds
                    ts_route_refresh = f'{ts_cached}:{ts_sec:09.6f}'

                # Do not use cache
                else:
                    ts_route_refresh = datetime_utcfromtimestamp(ts_route_refresh).strftime(DATETIME_FORMAT_USEC)

            # Add timestamp
            route_refresh_record[FTL_ATTR_BGP_ROUTE_REFRESH_TIMESTAMP] = ts_route_refresh

        # Add peer protocol to route refresh record
        if FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL >= 0:
            if FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL_HUMAN:
                route_refresh_record[FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL] = (IPV6_STR if peer_afinet == AF_INET6
                                                                                  else IPV4_STR)
            else:
                route_refresh_record[FTL_ATTR_BGP_ROUTE_REFRESH_PEER_PROTOCOL] = IPV6 if peer_afinet == AF_INET6 else IPV4

        # Add peer AS to route refresh record
        if FTL_ATTR_BGP_ROUTE_REFRESH_PEER_AS >= 0:
            route_refresh_record[FTL_ATTR_BGP_ROUTE_REFRESH_PEER_AS] = peer_as

        # Add peer IP to route refresh record
        if FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP >= 0:
            peer_ip_route_refresh = peer_ip
            if FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP_HUMAN:
                peer_ip_route_refresh = socket_inet_ntop(peer_afinet, peer_ip_route_refresh)
            elif peer_afinet == AF_INET6:
                net, host = struct_unpack(STRUCT_8B8B, peer_ip_route_refresh)
                peer_ip_route_refresh = (net << 64) + host
            else:
                peer_ip_route_refresh = struct_unpack(STRUCT_4B, peer_ip_route_refresh)[0]
            route_refresh_record[FTL_ATTR_BGP_ROUTE_REFRESH_PEER_IP] = peer_ip_route_refresh

        # Parse AFI value
        refresh_afi = struct_unpack(STRUCT_2B, msg_bytes[offset:offset + 2])[0]
        offset += 2

        # Skip reserved byte
        offset += 1

        # Parse SAFI value
        refresh_safi = msg_bytes[offset]

        # Check AFI value
        if refresh_afi != AFI_IPV4 and refresh_afi != AFI_IPV6:  # pylint: disable=consider-using-in
            yield from bgp_error(FtlMrtDataError(f'Invalid AFI value ({refresh_afi}) in BGP4MP route-refresh',
                                                 reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=msg_bytes))
            return

        # Check SAFI value
        if refresh_safi != BGP_SAFI_UNICAST and refresh_safi != BGP_SAFI_MULTICAST:  # pylint: disable=consider-using-in
            yield from bgp_error(FtlMrtDataError(f'Unsupported SAFI value ({refresh_safi}) in BGP4MP route-refresh',
                                                 reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=msg_bytes))
            return

        # Parse protocol
        if FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL >= 0:
            refresh_proto = IPV6 if refresh_afi == AFI_IPV6 else IPV4
            if FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL_HUMAN:
                refresh_proto = IPV6_STR if refresh_afi == AFI_IPV6 else IPV4_STR
            route_refresh_record[FTL_ATTR_BGP_ROUTE_REFRESH_REFRESH_PROTOCOL] = refresh_proto

        # Yield final route refresh record
        if FTL_RECORD_BGP_ROUTE_REFRESH:
            yield route_refresh_emit(route_refresh_record)

    ############################
    # BGP NOTIFICATION MESSAGE #
    ############################

    # -------------------------------------
    # [RFC4271] NOTIFICATION Message Format
    # -------------------------------------
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Error code    | Error subcode |   Data (variable)             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Parse NOTIFICATION message
    elif mtype == BGP_BGP4MP_NOTIFICATION:  # pylint: disable=confusing-consecutive-elif

        # Access notification template
        notification_init, notification_emit, _ = notification_records

        # Initialize notification record
        notification_record = list(notification_init)

        # Add timestamp to notification record
        if FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP >= 0:
            ts_notification = ts

            # Cache date string for minute-based timestamp
            if FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP_HUMAN:
                if caches:
                    ts_cache = caches[CACHE_TS]
                    ts_min, ts_sec = divmod(ts_notification, 60)
                    ts_cached = ts_cache.get(ts_min, None)
                    if ts_cached is None:
                        ts_cached = datetime_utcfromtimestamp(ts).strftime(DATETIME_FORMAT_MIN)
                        ts_cache[ts_min] = ts_cached

                    # Add seconds and microseconds
                    ts_notification = f'{ts_cached}:{ts_sec:09.6f}'

                # Do not use cache
                else:
                    ts_notification = datetime_utcfromtimestamp(ts_notification).strftime(DATETIME_FORMAT_USEC)

            # Add timestamp
            notification_record[FTL_ATTR_BGP_NOTIFICATION_TIMESTAMP] = ts_notification

        # Add peer protocol to notification record
        if FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL >= 0:
            if FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL_HUMAN:
                notification_record[FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL] = (IPV6_STR if peer_afinet == AF_INET6
                                                                                else IPV4_STR)
            else:
                notification_record[FTL_ATTR_BGP_NOTIFICATION_PEER_PROTOCOL] = IPV6 if peer_afinet == AF_INET6 else IPV4

        # Add peer AS to notification record
        if FTL_ATTR_BGP_NOTIFICATION_PEER_AS >= 0:
            notification_record[FTL_ATTR_BGP_NOTIFICATION_PEER_AS] = peer_as

        # Add peer IP to notification record
        if FTL_ATTR_BGP_NOTIFICATION_PEER_IP >= 0:
            peer_ip_notification = peer_ip
            if FTL_ATTR_BGP_NOTIFICATION_PEER_IP_HUMAN:
                peer_ip_notification = socket_inet_ntop(peer_afinet, peer_ip_notification)
            elif peer_afinet == AF_INET6:
                net, host = struct_unpack(STRUCT_8B8B, peer_ip_notification)
                peer_ip_notification = (net << 64) + host
            else:
                peer_ip_notification = struct_unpack(STRUCT_4B, peer_ip_notification)[0]
            notification_record[FTL_ATTR_BGP_NOTIFICATION_PEER_IP] = peer_ip_notification

        # Parse error code
        err_code_int = msg_bytes[offset]
        if FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE >= 0:
            err_code = err_code_int
            if FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE_HUMAN:
                err_code = FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE_TO_STR.get(err_code, str(err_code))
            notification_record[FTL_ATTR_BGP_NOTIFICATION_ERROR_CODE] = err_code
        offset += 1

        # Parse error subcode
        if FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE >= 0:
            err_scode = msg_bytes[offset]
            if FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE_HUMAN:
                err_scode = FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE_TO_STR.get(err_code_int,
                                                                               dict()).get(err_scode, str(err_scode))
            notification_record[FTL_ATTR_BGP_NOTIFICATION_ERROR_SUBCODE] = err_scode
        offset += 1

        # Parse data
        if FTL_ATTR_BGP_NOTIFICATION_DATA >= 0:
            if offset < len(msg_bytes):
                data = msg_bytes[offset:]
                if FTL_ATTR_BGP_NOTIFICATION_DATA_HUMAN:
                    notification_record[FTL_ATTR_BGP_NOTIFICATION_DATA] = ' '.join('{:02x}'.format(byte) for byte in data)
                else:
                    notification_record[FTL_ATTR_BGP_NOTIFICATION_DATA] = base64.b64encode(data).decode('ascii')

        # Yield final notification record
        if FTL_RECORD_BGP_NOTIFICATION:
            yield notification_emit(notification_record)

    ####################
    # BGP OPEN MESSAGE #
    ####################

    # ----------------------------------
    # [RFC4271] 4.2. OPEN Message Format
    # ----------------------------------
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+
    # |    Version    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     My Autonomous System      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Hold Time           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         BGP Identifier                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Opt Parm Len  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # |             Optional Parameters (variable)                    |
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # 0                   1
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
    # |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
    #
    # Parameter Type is a one octet field that unambiguously
    # identifies individual parameters. Parameter Length is a one
    # octet field that contains the length of the Parameter Value
    # field in octets. Parameter Value is a variable length field
    # that is interpreted according to the value of the Parameter
    # Type field.

    # Parse OPEN message
    elif mtype == BGP_BGP4MP_OPEN:  # pylint: disable=confusing-consecutive-elif

        # Access open template
        open_init, open_emit, _ = open_records

        # Initialize open record
        open_record = list(open_init)

        # Add timestamp to open record
        if FTL_ATTR_BGP_OPEN_TIMESTAMP >= 0:
            ts_open = ts

            # Cache date string for minute-based timestamp
            if FTL_ATTR_BGP_OPEN_TIMESTAMP_HUMAN:
                if caches:
                    ts_cache = caches[CACHE_TS]
                    ts_min, ts_sec = divmod(ts_open, 60)
                    ts_cached = ts_cache.get(ts_min, None)
                    if ts_cached is None:
                        ts_cached = datetime_utcfromtimestamp(ts).strftime(DATETIME_FORMAT_MIN)
                        ts_cache[ts_min] = ts_cached

                    # Add seconds and microseconds
                    ts_open = f'{ts_cached}:{ts_sec:09.6f}'

                # Do not use cache
                else:
                    ts_open = datetime_utcfromtimestamp(ts_open).strftime(DATETIME_FORMAT_USEC)

            # Add timestamp
            open_record[FTL_ATTR_BGP_OPEN_TIMESTAMP] = ts_open

        # Add peer protocol to open record
        if FTL_ATTR_BGP_OPEN_PEER_PROTOCOL >= 0:
            if FTL_ATTR_BGP_OPEN_PEER_PROTOCOL_HUMAN:
                open_record[FTL_ATTR_BGP_OPEN_PEER_PROTOCOL] = IPV6_STR if peer_afinet == AF_INET6 else IPV4_STR
            else:
                open_record[FTL_ATTR_BGP_OPEN_PEER_PROTOCOL] = IPV6 if peer_afinet == AF_INET6 else IPV4

        # Add peer AS to open record
        if FTL_ATTR_BGP_OPEN_PEER_AS >= 0:
            open_record[FTL_ATTR_BGP_OPEN_PEER_AS] = peer_as

        # Add peer IP to open record
        if FTL_ATTR_BGP_OPEN_PEER_IP >= 0:
            peer_ip_open = peer_ip
            if FTL_ATTR_BGP_OPEN_PEER_IP_HUMAN:
                peer_ip_open = socket_inet_ntop(peer_afinet, peer_ip_open)
            elif peer_afinet == AF_INET6:
                net, host = struct_unpack(STRUCT_8B8B, peer_ip_open)
                peer_ip_open = (net << 64) + host
            else:
                peer_ip_open = struct_unpack(STRUCT_4B, peer_ip_open)[0]
            open_record[FTL_ATTR_BGP_OPEN_PEER_IP] = peer_ip_open

        # Parse version
        if FTL_ATTR_BGP_OPEN_VERSION >= 0:
            open_record[FTL_ATTR_BGP_OPEN_VERSION] = msg_bytes[offset]
        offset += 1

        # Parse my AS (2 byte only)
        if FTL_ATTR_BGP_OPEN_MY_AS >= 0:
            open_record[FTL_ATTR_BGP_OPEN_MY_AS] = struct_unpack(STRUCT_2B, msg_bytes[offset:offset + 2])[0]
        offset += 2

        # Parse hold time
        if FTL_ATTR_BGP_OPEN_HOLD_TIME >= 0:
            open_record[FTL_ATTR_BGP_OPEN_HOLD_TIME] = struct_unpack(STRUCT_2B, msg_bytes[offset:offset + 2])[0]
        offset += 2

        # Parse BGP ID (IPv4 only)
        if FTL_ATTR_BGP_OPEN_BGP_ID >= 0:
            bgp_id = msg_bytes[offset:offset + 4]
            if FTL_ATTR_BGP_OPEN_BGP_ID_HUMAN:
                open_record[FTL_ATTR_BGP_OPEN_BGP_ID] = socket_inet_ntop(AF_INET, bgp_id)
            else:
                open_record[FTL_ATTR_BGP_OPEN_BGP_ID] = struct_unpack(STRUCT_4B, bgp_id)[0]
        offset += 4

        ###################
        # BGP OPEN PARAMS #
        ###################

        # Parse optional param length
        optlen = msg_bytes[offset]
        offset += 1

        # Parse optional params
        cur_offset, end_offset = offset, offset + optlen
        offset = end_offset
        while cur_offset < end_offset:

            # Parse optional parameter type
            otype = msg_bytes[cur_offset]
            cur_offset += 1

            # Parse optional parameter length
            olen = msg_bytes[cur_offset]
            cur_offset += 1

            # Prepare optional parameter byte offsets
            c_offset, e_offset = cur_offset, cur_offset + olen
            cur_offset = e_offset

            # ---------------------------------------------------------------
            # [RFC3392] 4. Capabilities Optional Parameter (Parameter Type 2)
            # ---------------------------------------------------------------
            # +------------------------------+
            # | Capability Code (1 octet)    |
            # +------------------------------+
            # | Capability Length (1 octet)  |
            # +------------------------------+
            # | Capability Value (variable)  |
            # +------------------------------+

            # Parse capabilities optional parameter
            if otype == BGP_PARAMS_CAPABILITIES:
                if FTL_ATTR_BGP_OPEN_CAPABILITIES >= 0:

                    # Parse capabilities
                    while c_offset < e_offset:

                        # Parse capability code
                        ccode = msg_bytes[c_offset]
                        ccode_stats = ccode
                        if FTL_ATTR_BGP_OPEN_CAPABILITIES_HUMAN:
                            ccode = FTL_ATTR_BGP_OPEN_CAPABILITY_TO_STR.get(ccode, str(ccode))
                        c_offset += 1

                        # Parse capability length
                        clen = msg_bytes[c_offset]
                        c_offset += 1

                        # Parse capability data
                        cdata = None
                        if clen > 0:
                            cdata = msg_bytes[c_offset:c_offset + clen]
                            if FTL_ATTR_BGP_OPEN_CAPABILITIES_HUMAN:
                                cdata = ' '.join('{:02x}'.format(byte) for byte in cdata)
                            else:
                                cdata = base64.b64encode(cdata).decode('ascii')
                            c_offset += clen

                        # Add capability code and data
                        if open_record[FTL_ATTR_BGP_OPEN_CAPABILITIES] is None:
                            open_record[FTL_ATTR_BGP_OPEN_CAPABILITIES] = tuple([(ccode, cdata)])
                        else:
                            open_record[FTL_ATTR_BGP_OPEN_CAPABILITIES] += tuple([(ccode, cdata)])

                        # Update stats record
                        if FTL_RECORD_BGP_STATS:

                            # Add BGP message type
                            if FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES >= 0:
                                if FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES_HUMAN:
                                    ccode_stats = FTL_ATTR_BGP_OPEN_CAPABILITY_TO_STR.get(ccode_stats, ccode_stats)
                                ccode_stats = str(ccode_stats)
                                stats_record_mrt_bgp_cap = stats_record[FTL_ATTR_BGP_STATS_MRT_BGP_CAPABILITY_TYPES]
                                stats_record_mrt_bgp_cap[ccode_stats] = stats_record_mrt_bgp_cap.get(ccode_stats, 0) + 1

            # Parse unsupported optional parameters
            elif FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN >= 0:  # pylint: disable=confusing-consecutive-elif
                odata = msg_bytes[c_offset:e_offset]
                if FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN_HUMAN:
                    odata = ' '.join('{:02x}'.format(byte) for byte in odata)
                else:
                    odata = base64.b64encode(odata).decode('ascii')
                if open_record[FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN] is None:
                    open_record[FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN] = tuple([(otype, odata)])
                else:
                    open_record[FTL_ATTR_BGP_OPEN_PARAMS_UNKNOWN] += tuple([(otype, odata)])

        # Yield final open record
        if FTL_RECORD_BGP_OPEN:
            yield open_emit(open_record)
