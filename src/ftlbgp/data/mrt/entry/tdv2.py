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
from .const import MRT_TABLE_DUMP_V2_RIB_SPECIFIC_ANY
from .const import MRT_TABLE_DUMP_V2_RIB_GENERIC_ANY
from .const import MRT_TABLE_DUMP_V2_RIB_IPV6_ANY
from ..bgp.attr import unpack_mrt_bgp_attr
from ..bgp.nlri import unpack_mrt_bgp_nlri
from ..bgp.const import BGP_SAFI_UNICAST
from ..bgp.const import BGP_SAFI_MULTICAST
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
from ...const import UTF8
from ...const import DATETIME_FORMAT_USEC
from ...const import DATETIME_FORMAT_MIN
from ...const import struct_unpack
from ...const import socket_inet_ntop
from ...const import datetime_utcfromtimestamp
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_VIEW_NAME
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_AS
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_IP
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID_HUMAN
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID_HUMAN
from ....model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_SOURCE
from ....model.attr import FTL_ATTR_BGP_ROUTE_SEQUENCE
from ....model.attr import FTL_ATTR_BGP_ROUTE_TIMESTAMP
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_BGP_ID
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_AS
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_IP
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX
from ....model.attr import FTL_ATTR_BGP_ROUTE_PATH_ID
from ....model.attr import FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_TIMESTAMP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_BGP_ID_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PEER_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4
from ....model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_FIXES
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN
from ....model.const import FTL_ATTR_BGP_ROUTE_SOURCE_RIB
from ....model.const import FTL_ATTR_BGP_ROUTE_SOURCE_RIB_STR
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ADDPATH
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ADDPATH_STR
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_TYPE
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX
from ....model.record import FTL_RECORD_BGP_PEER_TABLE
from ....model.record import FTL_RECORD_BGP_ROUTE
from ....model.record import FTL_RECORD_BGP_STATS
from ....model.error import FtlMrtHeaderError
from ....model.error import FtlMrtDataError


# pylint: disable-next=unused-argument
def unpack_mrt_entry_tdv2_index(caches, stats_record, peer_table_records, entry_bytes, peer_table):
    """ Parse MRT peer index table.
    """
    # Access peer table record template
    peer_table_init, peer_table_emit, _ = peer_table_records

    # Initialize peer table record view
    peer_table_record_view = list(peer_table_init)

    # -----------------------------------------
    # [RFC6396] 4.3.1. PEER_INDEX_TABLE Subtype
    # -----------------------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Collector BGP ID                         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |       View Name Length        |     View Name (variable)      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Peer Count           |    Peer Entries (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Prepare byte offset
    offset = 0

    # Parse collector BGP ID (IPv4 only)
    if FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID >= 0:
        col_bgp_id = entry_bytes[offset:offset + 4]
        if FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID_HUMAN:
            peer_table_record_view[FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID] = socket_inet_ntop(AF_INET, col_bgp_id)
        else:
            peer_table_record_view[FTL_ATTR_BGP_PEER_TABLE_COLLECTOR_BGP_ID] = struct_unpack(STRUCT_4B, col_bgp_id)[0]
    offset += 4

    # Parse view name length
    view_name_length = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
    offset += 2

    # Parse view name
    if view_name_length > 0:
        if FTL_ATTR_BGP_PEER_TABLE_VIEW_NAME >= 0:
            view_name = bytes(entry_bytes[offset:offset + view_name_length]).decode(UTF8)
            peer_table_record_view[FTL_ATTR_BGP_PEER_TABLE_VIEW_NAME] = view_name
        offset += view_name_length

    # Parse peer count
    peer_count = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
    offset += 2

    # Parse peer entries
    for _ in range(peer_count):

        # Initialize peer table record
        peer_table_record = list(peer_table_record_view)

        # -----------------------------------------
        # [RFC6396] 4.3.1. PEER_INDEX_TABLE Subtype
        # -----------------------------------------
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |   Peer Type   |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                         Peer BGP ID                           |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                   Peer IP Address (variable)                  |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                        Peer AS (variable)                     |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        # Parse peer type
        peer_type = entry_bytes[offset]
        offset += 1

        # Parse peer protocol and AS length
        afinet, iplen = (AF_INET6, 16) if peer_type & 1 else (AF_INET, 4)
        asfmt, aslen = (STRUCT_4B, 4) if peer_type & 2 else (STRUCT_2B, 2)

        # Add peer protocol to peer table record
        peer_proto_int, peer_proto_str = (IPV6, IPV6_STR) if afinet == AF_INET6 else (IPV4, IPV4_STR)
        if FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL >= 0:
            peer_proto = peer_proto_str if FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL_HUMAN else peer_proto_int
            peer_table_record[FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL] = peer_proto

        # Add peer BGP ID to peer table record
        peer_bgp_id = entry_bytes[offset:offset + 4]
        peer_bgp_id_str = socket_inet_ntop(AF_INET, peer_bgp_id)
        peer_bgp_id_int = struct_unpack(STRUCT_4B, peer_bgp_id)[0]
        if FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID >= 0:
            peer_bgp_id = peer_bgp_id_str if FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID_HUMAN else peer_bgp_id_int
            peer_table_record[FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID] = peer_bgp_id
        offset += 4

        # Add peer IP to peer table record
        peer_ip = entry_bytes[offset:offset + iplen]
        peer_ip_str = socket_inet_ntop(afinet, peer_ip)
        if afinet == AF_INET6:
            net, host = struct_unpack(STRUCT_8B8B, peer_ip)
            peer_ip_int = (net << 64) + host
        else:
            peer_ip_int = struct_unpack(STRUCT_4B, peer_ip)[0]
        if FTL_ATTR_BGP_PEER_TABLE_PEER_IP >= 0:
            peer_ip = peer_ip_str if FTL_ATTR_BGP_PEER_TABLE_PEER_IP_HUMAN else peer_ip_int
            peer_table_record[FTL_ATTR_BGP_PEER_TABLE_PEER_IP] = peer_ip
        offset += iplen

        # Add peer AS to peer table record
        peer_as = struct_unpack(asfmt, entry_bytes[offset:offset + aslen])[0]
        if FTL_ATTR_BGP_PEER_TABLE_PEER_AS >= 0:
            peer_table_record[FTL_ATTR_BGP_PEER_TABLE_PEER_AS] = peer_as
        offset += aslen

        # Update peer table
        peer_proto_route = peer_proto_str if FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN else peer_proto_int
        peer_ip_route = peer_ip_str if FTL_ATTR_BGP_ROUTE_PEER_IP_HUMAN else peer_ip_int
        peer_bgp_id_route = peer_bgp_id_str if FTL_ATTR_BGP_ROUTE_PEER_BGP_ID_HUMAN else peer_bgp_id_int
        peer_table.append((peer_proto_route, peer_bgp_id_route, peer_as, peer_ip_route))

        # Yield peer table record
        if FTL_RECORD_BGP_PEER_TABLE:
            yield peer_table_emit(peer_table_record)


def unpack_mrt_entry_tdv2_rib(caches, stats_record, route_records, entry_bytes, mrt_subtype, peer_table,
                              addpath=False, addpath_error=None):
    """ Parse MRT table dump v2.
    """
    # Prepare ADD-PATH RIB flag and protocol
    addpath_rib, afinet = addpath, None

    # Access route record template
    route_init, route_emit, route_error = route_records

    # Initialize route record prefix
    route_record_prefix = list(route_init)

    # Add source to route record prefix
    if FTL_ATTR_BGP_ROUTE_SOURCE >= 0:
        if FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN:
            route_record_prefix[FTL_ATTR_BGP_ROUTE_SOURCE] = FTL_ATTR_BGP_ROUTE_SOURCE_RIB_STR
        else:
            route_record_prefix[FTL_ATTR_BGP_ROUTE_SOURCE] = FTL_ATTR_BGP_ROUTE_SOURCE_RIB

    # Prepare byte offset
    offset = 0

    # Parse sequence number
    if FTL_ATTR_BGP_ROUTE_SEQUENCE >= 0:
        route_record_prefix[FTL_ATTR_BGP_ROUTE_SEQUENCE] = struct_unpack(STRUCT_4B, entry_bytes[offset:offset + 4])[0]
    offset += 4

    # Parse AFI/SAFI-specific RIB entries
    if mrt_subtype in MRT_TABLE_DUMP_V2_RIB_SPECIFIC_ANY:

        # -----------------------------------------------
        # [RFC6396] 4.3.2. AFI/SAFI-Specific RIB Subtypes
        # -----------------------------------------------
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                         Sequence Number                       |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # | Prefix Length |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                        Prefix (variable)                      |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |         Entry Count           |  RIB Entries (variable)
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        try:
            # Parse prefix
            # NOTE: Human-readable conversions are done in unpack_mrt_bgp_nlri()
            preflen = (entry_bytes[offset] + 7) // 8 + 1
            afinet = AF_INET6 if mrt_subtype in MRT_TABLE_DUMP_V2_RIB_IPV6_ANY else AF_INET
            _, prefix_proto, prefix, _, _, _ = next(iter(unpack_mrt_bgp_nlri(stats_record, caches,
                                                                             entry_bytes[offset:offset + preflen],
                                                                             afinet)))
            offset += preflen

            # Add prefix protocol to route record prefix
            if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL >= 0:
                route_record_prefix[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = prefix_proto

            # Add prefix to route record prefix
            if FTL_ATTR_BGP_ROUTE_PREFIX >= 0:
                route_record_prefix[FTL_ATTR_BGP_ROUTE_PREFIX] = prefix

        # Yield (or re-raise) prefix errors
        except FtlMrtDataError as error:
            yield from route_error(error)
            return
        except StopIteration:
            yield from route_error(FtlMrtDataError('Unable to decode prefix for table dump v2 entry',
                                                   reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX, data=entry_bytes))
            return

    # Parse generic RIB entries
    elif mrt_subtype in MRT_TABLE_DUMP_V2_RIB_GENERIC_ANY:

        # -------------------------------------
        # [RFC6396] 4.3.3.  RIB_GENERIC Subtype
        # -------------------------------------
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                         Sequence Number                       |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |    Address Family Identifier  |Subsequent AFI |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |     Network Layer Reachability Information (variable)         |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |         Entry Count           |  RIB Entries (variable)
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        # Parse AFI value
        afi = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
        offset += 2

        # Parse SAFI value
        safi = entry_bytes[offset]
        offset += 1

        # Parse prefix
        try:
            # Check AFI value
            if afi != AFI_IPV4 and afi != AFI_IPV6:  # pylint: disable=consider-using-in
                raise FtlMrtDataError(f'Invalid AFI value ({afi}) in table dump v2 RIB_GENERIC entry',
                                      reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=entry_bytes)

            # Check SAFI value
            if safi != BGP_SAFI_UNICAST and safi != BGP_SAFI_MULTICAST:  # pylint: disable=consider-using-in
                raise FtlMrtDataError(f'Unsupported SAFI value ({safi}) in table dump v2 RIB_GENERIC entry',
                                      reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=entry_bytes)

            # Parse prefix
            # NOTE: Human-readable conversions are done in unpack_mrt_bgp_nlri()
            preflen = (entry_bytes[offset] + 7) // 8 + 1
            afinet = AF_INET6 if afi == AFI_IPV6 else AF_INET
            _, prefix_proto, prefix, path_id, _, _ = next(iter(unpack_mrt_bgp_nlri(caches, stats_record,
                                                                                   entry_bytes[offset:offset + preflen],
                                                                                   afinet, addpath=addpath)))
            offset += preflen

            # Add prefix protocol to route record prefix
            if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL >= 0:
                route_record_prefix[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = prefix_proto

            # Add prefix to route record prefix
            if FTL_ATTR_BGP_ROUTE_PREFIX >= 0:
                route_record_prefix[FTL_ATTR_BGP_ROUTE_PREFIX] = prefix

            # Add ADD-PATH path ID to route record prefix
            addpath_rib = False
            if path_id is not None:
                if FTL_ATTR_BGP_ROUTE_PATH_ID >= 0:
                    route_record_prefix[FTL_ATTR_BGP_ROUTE_PATH_ID] = path_id

        # Yield (or re-raise) prefix errors
        except FtlMrtDataError as error:
            yield from route_error(error)
            return
        except StopIteration:
            yield from route_error(FtlMrtDataError('Unable to decode prefix for table dump v2 entry',
                                                   reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX, data=entry_bytes))
            return

    # Parse unknown MRT subtype
    else:
        yield from route_error(FtlMrtHeaderError(f'Unknown MRT subtype ({mrt_subtype}) for table dump v2 entry',
                                                 reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_TYPE, data=entry_bytes))
        return

    # Parse entry count
    entry_count = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
    offset += 2

    # ----------------------------
    # [RFC6396] 4.3.4. RIB Entries
    # ----------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Peer Index            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Originated Time                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |      Attribute Length         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    BGP Attributes... (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Sanitize RIB entries
    static_offset = 8 if addpath is False else 12
    cur_entries, cur_offset, end_offset = 0, offset + static_offset, len(entry_bytes) + static_offset
    while cur_offset < end_offset:
        cur_offset += static_offset + struct_unpack(STRUCT_2B, entry_bytes[cur_offset - 2:cur_offset])[0]
        cur_entries += 1

    # ---------------------------------------------
    # [RFC8050] 4.1. AFI/SAFI-Specific RIB Subtypes
    # ---------------------------------------------
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Peer Index            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Originated Time                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Path Identifier                       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |      Attribute Length         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    BGP Attributes... (variable)
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Handle invalid RIB entries
    if cur_entries != entry_count or cur_offset != end_offset:

        # Prepare data error
        if addpath_error is None:
            addpath_error = FtlMrtDataError('Unable to decode table dump v2 RIB entries',
                                            reason=FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA, data=entry_bytes)

        # Retry with ADD-PATH support
        # NOTE: Some MRT exporters include path IDs but fail to set an ADD-PATH entry subtype (RFC7911)
        if addpath is False:
            yield from unpack_mrt_entry_tdv2_rib(caches, stats_record, route_records, entry_bytes, mrt_subtype,
                                                 peer_table, addpath=True, addpath_error=addpath_error)
            return

        # Retry failed
        yield from route_error(addpath_error)
        return

    # Check for ADD-PATH fixes
    if addpath is True and addpath_error is not None:

        # Update stats record
        if FTL_RECORD_BGP_STATS:

            # Add ADD-PATH fix
            if FTL_ATTR_BGP_STATS_MRT_FIXES >= 0:
                fixtype = str(FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ADDPATH)
                if FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN:
                    fixtype = FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ADDPATH_STR
                stats_record_fix = stats_record[FTL_ATTR_BGP_STATS_MRT_FIXES]
                stats_record_fix[fixtype] = stats_record_fix.get(fixtype, 0) + 1

    # Parse RIB entries
    for _ in range(entry_count):

        # Initialize route record
        route_record = list(route_record_prefix)

        # Parse peer index and access peer table
        # NOTE: Human-readable conversions are done in unpack_mrt_entry_tdv2_index()
        if (FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL >= 0 or FTL_ATTR_BGP_ROUTE_PEER_BGP_ID >= 0
            or FTL_ATTR_BGP_ROUTE_PEER_AS >= 0 or FTL_ATTR_BGP_ROUTE_PEER_IP >= 0):
            peer_index = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
            peer_proto, peer_bgp_id, peer_as, peer_ip = peer_table[peer_index]
            if FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL] = peer_proto
            if FTL_ATTR_BGP_ROUTE_PEER_BGP_ID >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_PEER_BGP_ID] = peer_bgp_id
            if FTL_ATTR_BGP_ROUTE_PEER_AS >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_PEER_AS] = peer_as
            if FTL_ATTR_BGP_ROUTE_PEER_IP >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_PEER_IP] = peer_ip
        offset += 2

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

            # Add timestamp
            route_record[FTL_ATTR_BGP_ROUTE_TIMESTAMP] = ts
        offset += 4

        # Parse ADD-PATH path ID
        if addpath_rib is True:
            route_record[FTL_ATTR_BGP_ROUTE_PATH_ID] = struct_unpack(STRUCT_4B, entry_bytes[offset:offset + 4])[0]
            offset += 4

        # Parse attributes length
        alen = struct_unpack(STRUCT_2B, entry_bytes[offset:offset + 2])[0]
        offset += 2

        # Parse attributes
        attr_bytes = entry_bytes[offset:offset + alen]
        offset += alen
        try:
            unpack_mrt_bgp_attr(caches, stats_record, route_init, route_emit, route_record, attr_bytes, aslen=4,
                                addpath=addpath, rib=True)

        # Yield (or re-raise) attribute errors
        except FtlMrtDataError as error:
            yield from route_error(error)
            continue

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
