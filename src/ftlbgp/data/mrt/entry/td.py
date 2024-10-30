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
from ..bgp.attr import unpack_mrt_bgp_attr
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
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX
from ....model.attr import FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4
from ....model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6
from ....model.const import FTL_ATTR_BGP_ROUTE_SOURCE_RIB
from ....model.const import FTL_ATTR_BGP_ROUTE_SOURCE_RIB_STR
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL
from ....model.record import FTL_RECORD_BGP_ROUTE
from ....model.record import FTL_RECORD_BGP_STATS
from ....model.error import FtlMrtDataError


def unpack_mrt_entry_td_rib(caches, stats_record, route_records, entry_bytes, mrt_subtype):
    """ Parse MRT table dump entry.
    """
    # ------------------------------
    # [RFC6396] 4.2. TABLE_DUMP Type
    # ------------------------------
    # The Subtype field is used to encode whether the RIB entry contains
    # IPv4 or IPv6 [RFC2460] addresses. There are two possible values for
    # the Subtype as shown below.
    #
    #     1    AFI_IPv4
    #     2    AFI_IPv6
    #
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         View Number           |       Sequence Number         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Prefix (variable)                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Prefix Length |    Status     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Originated Time                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Peer IP Address (variable)                 |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Peer AS             |       Attribute Length        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                   BGP Attribute... (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Check AFI value
    if (mrt_subtype != AFI_IPV4 and mrt_subtype != AFI_IPV6):  # pylint: disable=consider-using-in
        raise FtlMrtDataError(f'Unknown AFI value ({mrt_subtype}) in table dump entry',
                              reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=entry_bytes)

    # Access route record template
    route_init, route_emit, route_error = route_records

    # Initialize route record
    route_record = list(route_init)

    # Add source to route record
    if FTL_ATTR_BGP_ROUTE_SOURCE >= 0:
        if FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN:
            route_record[FTL_ATTR_BGP_ROUTE_SOURCE] = FTL_ATTR_BGP_ROUTE_SOURCE_RIB_STR
        else:
            route_record[FTL_ATTR_BGP_ROUTE_SOURCE] = FTL_ATTR_BGP_ROUTE_SOURCE_RIB

    # Add prefix protocol to route record
    afinet = AF_INET6 if mrt_subtype == AFI_IPV6 else AF_INET
    if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL >= 0:
        if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL_HUMAN:
            route_record[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = IPV6_STR if afinet == AF_INET6 else IPV4_STR
        else:
            route_record[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = IPV6 if afinet == AF_INET6 else IPV4

    # Prepare byte offset
    offset = 0

    # Skip view number
    offset += 2

    # Add sequence number to route record
    if FTL_ATTR_BGP_ROUTE_SEQUENCE >= 0:
        route_record[FTL_ATTR_BGP_ROUTE_SEQUENCE] = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
    offset += 2

    # Add prefix protocol to route record
    if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL >= 0:
        if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL_HUMAN:
            route_record[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = IPV6_STR if afinet == AF_INET6 else IPV4_STR
        else:
            route_record[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = IPV6 if afinet == AF_INET6 else IPV4

    # Parse prefix bytes
    preflen = 16 if afinet == AF_INET6 else 4
    prefix = entry_bytes[offset:offset + preflen]
    if FTL_ATTR_BGP_ROUTE_PREFIX_HUMAN:
        prefix = socket_inet_ntop(afinet, prefix)
    elif afinet == AF_INET6:
        net, host = struct_unpack(STRUCT_8B8B, prefix)
        prefix = (net << 64) + host
    else:
        prefix = struct_unpack(STRUCT_4B, prefix)[0]
    offset += preflen

    # Parse prefix mask
    mask = entry_bytes[offset]
    offset += 1

    # Add prefix to route record
    if FTL_ATTR_BGP_ROUTE_PREFIX >= 0:
        if FTL_ATTR_BGP_ROUTE_PREFIX_HUMAN:
            route_record[FTL_ATTR_BGP_ROUTE_PREFIX] = f'{prefix}/{mask}'
        else:
            route_record[FTL_ATTR_BGP_ROUTE_PREFIX] = (prefix, mask)

    # Skip status
    offset += 1

    # Parse timestamp
    if FTL_ATTR_BGP_ROUTE_TIMESTAMP >= 0:
        ts = float(struct_unpack(STRUCT_4B, entry_bytes[offset:offset + 4])[0])
        if FTL_ATTR_BGP_ROUTE_TIMESTAMP_HUMAN:

            # Cache date string for minute-based timestamp
            if caches:
                ts_cache = caches[CACHE_TS]
                ts_min, ts_sec = divmod(ts, 60)
                ts_cached = ts_cache.get(ts_min, None)
                if ts_cached is None:
                    ts_cached = datetime_utcfromtimestamp(ts).strftime(DATETIME_FORMAT_MIN)
                    ts_cache[ts_min] = ts_cached

                # Add seconds and microseconds
                ts = f'{ts_cached}:{ts_sec:09.6f}'

            # Do not use cache
            else:
                ts = datetime_utcfromtimestamp(ts).strftime(DATETIME_FORMAT_USEC)

        # Add timestamp to route record
        route_record[FTL_ATTR_BGP_ROUTE_TIMESTAMP] = ts
    offset += 4

    # Add peer protocol to route record
    if FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL >= 0:
        if FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN:
            route_record[FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL] = (IPV6_STR if afinet == AF_INET6 else IPV4_STR)
        else:
            route_record[FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL] = IPV6 if afinet == AF_INET6 else IPV4

    # Add peer IP to route record
    iplen = 16 if afinet == AF_INET6 else 4
    peer_ip = entry_bytes[offset:offset + iplen]
    if FTL_ATTR_BGP_ROUTE_PEER_IP_HUMAN:
        peer_ip = socket_inet_ntop(afinet, peer_ip)
    elif afinet == AF_INET6:
        net, host = struct_unpack(STRUCT_8B8B, peer_ip)
        peer_ip = (net << 64) + host
    else:
        peer_ip = struct_unpack(STRUCT_4B, peer_ip)[0]
    if FTL_ATTR_BGP_ROUTE_PEER_IP >= 0:
        route_record[FTL_ATTR_BGP_ROUTE_PEER_IP] = peer_ip
    offset += iplen

    # Add peer AS to route record
    peer_as = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
    if FTL_ATTR_BGP_ROUTE_PEER_AS >= 0:
        route_record[FTL_ATTR_BGP_ROUTE_PEER_AS] = peer_as
    offset += 2

    # Parse attributes length
    alen = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
    offset += 2

    # Parse attributes
    attr_bytes = entry_bytes[offset:offset + alen]
    offset += alen
    try:
        unpack_mrt_bgp_attr(caches, stats_record, route_init, route_emit, route_record, attr_bytes, aslen=2, rib=True)

    # Yield (or re-raise) attribute errors
    except FtlMrtDataError as error:
        yield from route_error(error)
        return

    # Update stats record
    if FTL_RECORD_BGP_STATS:

        # Update IPv4 RIB routes
        if afinet == AF_INET:
            if FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4 >= 0:
                stats_record[FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4] += 1

        # Update IPv6 RIB routes
        if afinet == AF_INET6:
            if FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6 >= 0:
                stats_record[FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6] += 1

    # Yield final route record
    if FTL_RECORD_BGP_ROUTE:
        yield route_emit(route_record)
