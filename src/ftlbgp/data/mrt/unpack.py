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
from .entry.bgp import unpack_mrt_entry_bgp
from .entry.bgp4mp import unpack_mrt_entry_bgp4mp
from .entry.tdv2 import unpack_mrt_entry_tdv2_index
from .entry.tdv2 import unpack_mrt_entry_tdv2_rib
from .entry.td import unpack_mrt_entry_td_rib
from .entry.const import MRT_VALID
from .entry.const import MRT_BGP
from .entry.const import MRT_BGP4MP
from .entry.const import MRT_BGP4MP_ET
from .entry.const import MRT_TABLE_DUMP
from .entry.const import MRT_TABLE_DUMP_V2
from .entry.const import MRT_TABLE_DUMP_V2_PEER_INDEX_TABLE
from .entry.const import MRT_TABLE_DUMP_V2_RIB_ADDPATH_ANY
from .entry.const import MRT_HEADER_BYTES
from .entry.const import MRT_DATA_BYTES
from ..const import STRUCT_2B
from ..const import STRUCT_4B
from ..const import struct_unpack
from ...parser import FtlParserFunc
from ...model.attr import FTL_ATTR_BGP_STATS_MRT_ENTRIES
from ...model.attr import FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES
from ...model.attr import FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES_HUMAN
from ...model.const import FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPE_TO_STR
from ...model.const import FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TO_STR
from ...model.record import FTL_RECORD_BGP_STATS
from ...model.error import FtlMrtError
from ...model.error import FtlMrtFormatError
from ...model.error import FtlMrtHeaderError
from ...model.error import FtlMrtDataError


@FtlParserFunc
def unpack_mrt_data(inputfile, caches, stats_record, bgp_records, bgp_error):
    """ Parse MRT byte stream.
    """
    # Prepare peer table data structure and sequence number
    peer_table, sequence = list(), 0

    # Prepare memory for MRT header bytes (fixed length)
    header_bytes = memoryview(bytearray(MRT_HEADER_BYTES))

    # Prepare MRT header fields
    ts, mrt_type, mrt_subtype, length = None, None, None, None

    # Prepare memory for MRT data bytes (dynamic length)
    data_bytes = memoryview(bytearray(MRT_DATA_BYTES))
    entry_bytes = memoryview(bytearray())

    # Access BGP record templates
    peer_table_records = bgp_records.peer_table
    state_change_records = bgp_records.state_change
    route_records = bgp_records.route
    keep_alive_records = bgp_records.keep_alive
    route_refresh_records = bgp_records.route_refresh
    notification_records = bgp_records.notification
    open_records = bgp_records.open

    # Read MRT byte stream
    first_record = True
    while True:
        try:
            # Read MRT header bytes
            n_read = 0
            try:
                n_read = inputfile.readinto(header_bytes)
            except Exception:  # pylint: disable=broad-except
                pass

            # Check MRT header bytes
            if n_read < MRT_HEADER_BYTES:
                if n_read > 0:
                    raise FtlMrtHeaderError(f'Incomplete MRT header ({n_read}B<{MRT_HEADER_BYTES}B)')
                break

            # ------------------------------
            # [RFC6396] 2. MRT Common Header
            # ------------------------------
            #  0                   1                   2                   3
            #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                           Timestamp                           |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |             Type              |            Subtype            |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                             Length                            |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                      Message... (variable)
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            # Parse MRT header data
            ts = float(struct_unpack(STRUCT_4B, header_bytes[:4])[0])
            mrt_type = struct_unpack(STRUCT_2B, header_bytes[4:6])[0]
            mrt_subtype = struct_unpack(STRUCT_2B, header_bytes[6:8])[0]
            length = struct_unpack(STRUCT_4B, header_bytes[8:12])[0]

            # Check MRT entry type
            if mrt_type not in MRT_VALID:
                raise FtlMrtHeaderError(f'Unknown MRT type ({mrt_type})', data=header_bytes)

            # Check MRT entry length
            if length == 0:
                raise FtlMrtHeaderError('Empty MRT record', data=header_bytes)
            if length > MRT_DATA_BYTES:
                raise FtlMrtHeaderError(f'MRT record too large ({length}B)', data=header_bytes)

            # Update stats record
            if FTL_RECORD_BGP_STATS:

                # Add entry
                if FTL_ATTR_BGP_STATS_MRT_ENTRIES >= 0:
                    stats_record[FTL_ATTR_BGP_STATS_MRT_ENTRIES] += 1

                # Add entry type
                if FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES >= 0:
                    stats_record_mrt_entry_types = stats_record[FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES]
                    etype, estype = mrt_type, mrt_subtype
                    if FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPES_HUMAN:
                        estype = FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_SUBTYPE_TO_STR.get(etype, dict()).get(estype, estype)
                        etype = FTL_ATTR_BGP_STATS_MRT_BGP_ENTRY_TYPE_TO_STR.get(etype, etype)
                    etype_str = f'{etype}|{estype}'
                    stats_record_mrt_entry_types[etype_str] = stats_record_mrt_entry_types.get(etype_str, 0) + 1

            # Slice MRT data bytes to current entry length
            entry_bytes = data_bytes[:length]

            # Read MRT entry bytes
            n_read = 0
            try:
                n_read = inputfile.readinto(entry_bytes)
            except Exception:  # pylint: disable=broad-except
                pass

            # Check MRT entry bytes
            if n_read < length:
                raise FtlMrtHeaderError(f'Incomplete MRT record ({n_read}B<{length}B)', data=header_bytes)

            ##########
            # BGP4MP #
            ##########

            # Parse MRT BGP4MP entry
            if mrt_type == MRT_BGP4MP:

                # Increase sequence number
                sequence += 1

                # Yield BGP4MP records
                yield from unpack_mrt_entry_bgp4mp(caches, stats_record, bgp_error, state_change_records, route_records,
                                                   keep_alive_records, route_refresh_records, notification_records,
                                                   open_records, entry_bytes, mrt_subtype, sequence, ts)

            #############
            # BGP4MP_ET #
            #############

            # Parse MRT BGP4MP_ET entry
            elif mrt_type == MRT_BGP4MP_ET:

                # ------------------------------------------
                # [RFC6396] 3. Extended Timestamp MRT Header
                # ------------------------------------------
                #  0                   1                   2                   3
                #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                # |                           Timestamp                           |
                # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                # |             Type              |            Subtype            |
                # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                # |                             Length                            |
                # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                # |                      Microsecond Timestamp                    |
                # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                # |                      Message... (variable)
                # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                # Increase sequence number
                sequence += 1

                # Parse millisecond timestamp
                ts += struct_unpack(STRUCT_4B, entry_bytes[:4])[0] / 1000000.0
                entry_bytes = entry_bytes[4:]

                # Yield BGP4MP records
                yield from unpack_mrt_entry_bgp4mp(caches, stats_record, bgp_error, state_change_records, route_records,
                                                   keep_alive_records, route_refresh_records, notification_records,
                                                   open_records, entry_bytes, mrt_subtype, sequence, ts)

            #################
            # TABLE_DUMP_V2 #
            #################

            # Parse MRT TABLE_DUMP_V2 entry
            elif mrt_type == MRT_TABLE_DUMP_V2:

                # Extract peer table
                if mrt_subtype == MRT_TABLE_DUMP_V2_PEER_INDEX_TABLE:
                    yield from unpack_mrt_entry_tdv2_index(caches, stats_record, peer_table_records, entry_bytes,
                                                           peer_table)

                    # Finalize peer table
                    peer_table = tuple(peer_table)
                    continue

                # ------------------------------------------------
                # [RFC8050] 4. MRT Subtypes for Type TABLE_DUMP_V2
                # ------------------------------------------------
                # This document defines the following new subtypes:
                #  o  RIB_IPV4_UNICAST_ADDPATH
                #  o  RIB_IPV4_MULTICAST_ADDPATH
                #  o  RIB_IPV6_UNICAST_ADDPATH
                #  o  RIB_IPV6_MULTICAST_ADDPATH
                #  o  RIB_GENERIC_ADDPATH

                # Check for ADD-PATH entry (RFC7911)
                addpath = mrt_subtype in MRT_TABLE_DUMP_V2_RIB_ADDPATH_ANY

                # Yield RIB records
                yield from unpack_mrt_entry_tdv2_rib(caches, stats_record, route_records, entry_bytes, mrt_subtype,
                                                     peer_table, addpath=addpath)

            ##############
            # TABLE_DUMP #
            ##############

            # Parse MRT TABLE_DUMP entry
            elif mrt_type == MRT_TABLE_DUMP:

                # Yield RIB records
                yield from unpack_mrt_entry_td_rib(caches, stats_record, route_records, entry_bytes, mrt_subtype)

            #######
            # BGP #
            #######

            # Parse MRT BGP entry
            elif mrt_type == MRT_BGP:

                # Increase sequence number
                sequence += 1

                # Yield BGP records
                yield from unpack_mrt_entry_bgp(caches, stats_record, bgp_error, state_change_records, route_records,
                                                keep_alive_records, route_refresh_records, notification_records,
                                                open_records, entry_bytes, mrt_subtype, sequence, ts)

            # Successfully parsed first record
            first_record = False

        # Re-raise already handled header exceptions as format exceptions
        except FtlMrtHeaderError as error:

            # Raise format error for invalid first header
            if first_record is True:
                raise FtlMrtFormatError(error=error)  # pylint: disable=raise-missing-from

            # Yield (or re-raise) other header errors
            # NOTE: We abort parsing in case of any header error
            yield from bgp_error(error)
            return

        # Re-raise already handled record errors
        except FtlMrtError as error:
            raise error

        # Yield (or re-raise) unhandled exceptions
        except Exception as exc:  # pylint: disable=broad-exception-caught
            yield from bgp_error(FtlMrtDataError('Unhandled data error', data=b''.join((header_bytes, entry_bytes)),
                                                 trace=True, exception=exc))
