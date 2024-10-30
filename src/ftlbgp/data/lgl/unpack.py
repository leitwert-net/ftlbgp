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
import re

# Local imports
from ..const import IPV4
from ..const import IPV6
from ..const import IPV4_STR
from ..const import IPV6_STR
from ..const import AF_INET
from ..const import AF_INET6
from ..const import STRUCT_4B
from ..const import STRUCT_8B8B
from ..const import socket_inet_pton
from ..const import struct_unpack
from ...parser import FtlParserFunc
from ...model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL
from ...model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID
from ...model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_AS
from ...model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL_HUMAN
from ...model.attr import FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID_HUMAN
from ...model.attr import FTL_ATTR_BGP_ROUTE_SOURCE
from ...model.attr import FTL_ATTR_BGP_ROUTE_SEQUENCE
from ...model.attr import FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL
from ...model.attr import FTL_ATTR_BGP_ROUTE_PEER_BGP_ID
from ...model.attr import FTL_ATTR_BGP_ROUTE_PEER_AS
from ...model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL
from ...model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_IP
from ...model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL
from ...model.attr import FTL_ATTR_BGP_ROUTE_PREFIX
from ...model.attr import FTL_ATTR_BGP_ROUTE_ASPATH
from ...model.attr import FTL_ATTR_BGP_ROUTE_ORIGIN
from ...model.attr import FTL_ATTR_BGP_ROUTE_LOCAL_PREF
from ...model.attr import FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC
from ...model.attr import FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN
from ...model.attr import FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN
from ...model.attr import FTL_ATTR_BGP_ROUTE_PEER_BGP_ID_HUMAN
from ...model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL_HUMAN
from ...model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_IP_HUMAN
from ...model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL_HUMAN
from ...model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_HUMAN
from ...model.attr import FTL_ATTR_BGP_ROUTE_ORIGIN_HUMAN
from ...model.attr import FTL_ATTR_BGP_STATS_LGL_ENTRIES
from ...model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4
from ...model.attr import FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6
from ...model.const import FTL_ATTR_BGP_ROUTE_SOURCE_RIB
from ...model.const import FTL_ATTR_BGP_ROUTE_SOURCE_RIB_STR
from ...model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_IGP
from ...model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_IGP_STR
from ...model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_EGP
from ...model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_EGP_STR
from ...model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE
from ...model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE_STR
from ...model.const import FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA
from ...model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR
from ...model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_ASPATH
from ...model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX
from ...model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_AS
from ...model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_IP
from ...model.record import FTL_RECORD_BGP_PEER_TABLE
from ...model.record import FTL_RECORD_BGP_ROUTE
from ...model.record import FTL_RECORD_BGP_STATS
from ...model.error import FtlLglError
from ...model.error import FtlLglHeaderError
from ...model.error import FtlLglFormatError
from ...model.error import FtlLglDataError

# Header parts
HEADER_PEER_AS = 'local AS'
HEADER_PEER_BGP_ID = 'local router ID is'
HEADER_LOCAL_PREF = 'Default local pref'

# Header regex
HEADER_REGEX = re.compile(r'^\s+Network\s+Next Hop\s+Metric\s+LocPrf\s+Weight\s+Path\s*$')
HEADER_REGEX_ALT = re.compile(r'^\s+P\s+Pref\s+Time\s+Destination\s+Next Hop\s+If\s+Path\s*$')

# Route parts
ROUTE_ASHOPS = r'(?:(?:\d+\s?)|(?:{(?:\d+,?)+}\s?))'
ROUTE_STATUS = '[sdh*>=irSR ]'
ROUTE_ORIGIN = '[ie?]'
ROUTE_STATUS_ALT = '[s*>i ]'
ROUTE_ORIGIN_ALT = '[ie?a]'

# Route regex
ROUTE_REGEX = re.compile(
    r'^{route_status}{{3,4}}'    # Route status  (ignored, required)
    r'(\S+)?\s+'                 # Prefix        (group 1, optional)
    r'(\S+)\s+'                  # Next hop      (group 2, required)
    r'\s{{1,7}}(\d+)?'           # MED metric    (group 3, optional)
    r'\s{{1,7}}(\d+)?'           # Local-pref    (group 4, optional)
    r'\s{{1,7}}(?:\d+)?'         # Weight        (ignored, optional)
    r'(?:\s({route_ashops}+))?'  # AS path       (group 5, optional)
    r'\s({route_origin}{{1}})'   # Route origin  (group 6, required)
    r''.format(route_status=ROUTE_STATUS, route_ashops=ROUTE_ASHOPS, route_origin=ROUTE_ORIGIN)
)
ROUTE_REGEX_ALT = re.compile(
    r'^{route_status}{{2}}'        # Route status  (ignored, required)
    r'(?:\S)?\s{{1,2}}'            # P (unknown)   (ignored, optional)
    r'\s{{1,3}}(\d+)?'             # Local-pref    (group 1, optional)
    r'\s+\d{{2}}:\d{{2}}:\d{{2}}'  # Timestamp     (ignored, required)
    r'\s+(\S+)\s+'                 # Prefix        (group 2, required)
    r'(\S+)\s+'                    # Next hop      (group 3, required)
    r'(?:\S+)?\s+'                 # Interface     (ignored, optional)
    r'(?:\s({route_ashops}+))?'    # AS path       (group 4, optional)
    r'\s({route_origin}{{1}})'     # Route origin  (group 5, required)
    r''.format(route_status=ROUTE_STATUS_ALT, route_ashops=ROUTE_ASHOPS, route_origin=ROUTE_ORIGIN_ALT)
)

# Totals regex
ROUTE_TOTAL1_REGEX = re.compile(r'^Displayed\s+(\d+) routes and\s+(\d+) total paths$')
ROUTE_TOTAL2_REGEX = re.compile(r'^Total number of prefixes (\d+)$')
ROUTE_HEADER_REGEX = re.compile(r'^View \S+ \S+ (\d+) routes$')


@FtlParserFunc(text_input='utf-8')
# pylint: disable-next=unused-argument
def unpack_lgl_data(inputfile, caches, stats_record, bgp_records, bgp_error):
    """ Parse looking glass RIB dumps in plain text format.
    """
    # Access BGP record templates
    route_init, route_emit, route_error = bgp_records.route
    peer_table_init, peer_table_emit, peer_table_error = bgp_records.peer_table

    # Initialize route record header
    route_record_header = list(route_init)

    # Add source to route record header
    if FTL_ATTR_BGP_ROUTE_SOURCE >= 0:
        source = FTL_ATTR_BGP_ROUTE_SOURCE_RIB_STR if FTL_ATTR_BGP_ROUTE_SOURCE_HUMAN else FTL_ATTR_BGP_ROUTE_SOURCE_RIB
        route_record_header[FTL_ATTR_BGP_ROUTE_SOURCE] = source

    ##############
    # BGP HEADER #
    ##############

    # ------------------------
    # [PCH] % sh bgp ipv4 wide
    # ------------------------
    # BGP table version is 147996423, local router ID is 74.80.112.4, vrf id 0
    # Default local pref 100, local AS 3856
    # Status codes:  s suppressed, d damped, h history, * valid, > best, = multipath,
    #                i internal, r RIB-failure, S Stale, R Removed
    # Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
    # Origin codes:  i - IGP, e - EGP, ? - incomplete
    #
    #    Network          Next Hop            Metric LocPrf Weight Path

    # -------------------------
    # [RIPE] % sh bgp ipv4 wide
    # -------------------------
    # View #0 inet 64059 routes
    # Status code: s suppressed, * valid, > best, i - internal
    # Origin codes: i - IGP, e - EGP, ? - incomplete, a - aggregate
    #
    #   P Pref Time     Destination                Next Hop                 If      Path

    # Prepare dump data
    line = None

    try:
        # Prepare dump status
        alt_mode = False
        dump_valid = False
        header_errors = list()

        # Prepare details
        peer_as, peer_bgp_id = None, None
        prefixes, routes = None, None

        # Parse dump header
        try:
            for line in inputfile:

                # Extract totals from first line for sanitarization
                match = ROUTE_HEADER_REGEX.match(line)
                if match is not None:
                    try:
                        prefixes = int(match.group(1))
                    except ValueError:
                        pass

                # Extract default local-pref
                if HEADER_LOCAL_PREF in line:
                    try:
                        # Try to parse local-pref
                        locpref = int(line.split(HEADER_LOCAL_PREF, 1)[1].strip().split(None, 1)[0].rstrip(',').strip())

                        # Add local-pref to route record header
                        if FTL_ATTR_BGP_ROUTE_LOCAL_PREF >= 0:
                            route_record_header[FTL_ATTR_BGP_ROUTE_LOCAL_PREF] = locpref

                    # Store header error
                    except Exception as exc:  # pylint: disable=broad-except
                        header_errors.append((route_error, FtlLglDataError('Unable to decode local-pref',
                                              reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR, data=line, exception=exc)))

                # Extract peer AS
                if HEADER_PEER_AS in line:
                    try:
                        # Try to parse peer AS
                        peer_as = int(line.split(HEADER_PEER_AS, 1)[1].strip().split(None, 1)[0].rstrip(',').strip())

                        # Add peer AS to route record header
                        if FTL_ATTR_BGP_ROUTE_PEER_AS >= 0:
                            route_record_header[FTL_ATTR_BGP_ROUTE_PEER_AS] = peer_as

                    # Store header error
                    except Exception as exc:  # pylint: disable=broad-except
                        header_errors.append((peer_table_error, FtlLglDataError('Unable to decode peer AS',
                                              reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_AS, data=line, exception=exc)))

                # Extract peer BGP ID (IPv4 only)
                if HEADER_PEER_BGP_ID in line:
                    try:
                        # Try to parse peer BGP ID
                        peer_bgp_id = line.split(HEADER_PEER_BGP_ID, 1)[1].strip().split(None, 1)[0].rstrip(',').strip()
                        peer_bgp_id_int = struct_unpack(STRUCT_4B, socket_inet_pton(AF_INET, peer_bgp_id))[0]

                        # Add peer BGP ID to route record header
                        peer_bgp_id = peer_bgp_id if FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID_HUMAN else peer_bgp_id_int
                        if FTL_ATTR_BGP_ROUTE_PEER_BGP_ID >= 0:
                            peer_bgp_id_route = peer_bgp_id if FTL_ATTR_BGP_ROUTE_PEER_BGP_ID_HUMAN else peer_bgp_id_int
                            route_record_header[FTL_ATTR_BGP_ROUTE_PEER_BGP_ID] = peer_bgp_id_route

                    # Store header error
                    except Exception as exc:  # pylint: disable=broad-except
                        header_errors.append((peer_table_error, FtlLglDataError('Unable to decode peer BGP ID',
                                              reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_IP, data=line, exception=exc)))

                # Check for valid table start
                if HEADER_REGEX.match(line) is not None:
                    dump_valid = True
                    break

                # Check for alternative table start (early RIPE RIS)
                if HEADER_REGEX_ALT.match(line) is not None:
                    alt_mode = True
                    dump_valid = True
                    break

        # Always raise critical file reading errors
        except Exception as exc:
            # pylint: disable-next=raise-missing-from
            raise FtlLglHeaderError('Unknown lgl format', data=line, exception=exc)

        # Always raise critical header errors
        if dump_valid is False:
            raise FtlLglHeaderError('No BGP table found', data=line)

        # Yield (or re-raise) remaining header errors
        for record_error, error in header_errors:
            yield from record_error(error)

        # Prepare peer table record
        peer_table_record = None
        if peer_as is not None or peer_bgp_id is not None:

            # Initialize peer table record
            peer_table_record = list(peer_table_init)

            # Add peer AS to peer table record
            if peer_as is not None:
                if FTL_ATTR_BGP_PEER_TABLE_PEER_AS >= 0:
                    peer_table_record[FTL_ATTR_BGP_PEER_TABLE_PEER_AS] = peer_as

            # Add peer BGP ID to peer table record
            if peer_bgp_id is not None:
                if FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID >= 0:
                    peer_table_record[FTL_ATTR_BGP_PEER_TABLE_PEER_BGP_ID] = peer_bgp_id

        #############
        # BGP TABLE #
        #############

        # ------------------------
        # [PCH] % sh bgp ipv4 wide
        # ------------------------
        #    Network          Next Hop            Metric LocPrf Weight Path
        # *  1.0.0.0/24       206.126.236.19           0             0 3257 13335 i
        # *>                  206.126.237.30           0             0 13335 i
        # *> 1.0.16.0/24      206.126.236.23           0             0 2497 2519 i

        # -------------------------
        # [RIPE] % sh bgp ipv4 wide
        # -------------------------
        #   P Pref Time     Destination                Next Hop                 If      Path
        # > B    0 11:53:59 3.0.0.0/8                  193.0.0.56               eth0    3333 286 701 80 i
        # * B    0 11:53:46 3.0.0.0/8                  193.0.0.59               eth0    3333 286 701 80 i

        # Prepare record parser
        n_routes4, n_routes6, n_prefixes = 0, 0, 0

        # Initialize route record and parser state
        route_record_prefix, route_record_proto, last_prefix = None, None, None
        multiline = ''

        # Prepare regex
        route_regex = ROUTE_REGEX
        if alt_mode is True:
            route_regex = ROUTE_REGEX_ALT

        # Iterate input lines
        for line in inputfile:

            # Skip empty lines
            line = line.rstrip()  # pylint: disable=redefined-loop-name
            if len(line) == 0:
                route_record_prefix = None
                route_record_proto = None
                multiline = ''
                continue

            # Update multiline
            multiline += line

            # Parse multiline route (with or without prefix)
            match = route_regex.match(multiline)
            if match is not None:

                # Reset parser state
                multiline = ''

                # Extract route details
                prefix, nexthop_ip, med, locpref, aspath, origin = None, None, None, None, None, None
                if alt_mode is False:
                    prefix, nexthop_ip, med, locpref, aspath, origin = match.groups()
                else:
                    locpref, prefix, nexthop_ip, aspath, origin = match.groups()

                ##############
                # BGP PREFIX #
                ##############

                # Extract prefix
                if prefix is not None:

                    # Reset route record
                    route_record_prefix = None
                    route_record_proto = None

                    # Prepare prefix
                    prefix_int, mask = 0, 0
                    proto = IPV6 if ':' in prefix else IPV4
                    try:
                        # Ignore shortened prefix notation for /8 and /16
                        if prefix.endswith('.0.0') is True:
                            raise ValueError(f'indecisive classful {IPV4_STR} prefix ({prefix})')

                        # Fix shortened prefix notation for /24
                        if prefix.endswith('.0') is True:
                            prefix += '/24'

                        # Parse prefix
                        prefix_str, mask = prefix.split('/', 1)
                        if proto == IPV6:
                            net, host = struct_unpack(STRUCT_8B8B, socket_inet_pton(AF_INET6, prefix_str))
                            prefix_int = (net << 64) + host
                        else:
                            prefix_int = struct_unpack(STRUCT_4B, socket_inet_pton(AF_INET, prefix_str))[0]

                        # Sanitize prefix
                        max_mask, mask = (128 if proto == IPV6 else 32), int(mask)
                        shift = max_mask - mask
                        if mask > max_mask:
                            raise ValueError(f'invalid {IPV6_STR if proto == IPV6 else IPV4_STR} mask (/{mask})')
                        if (prefix_int >> shift) << shift != prefix_int:
                            raise ValueError(f'misaligned prefix ({prefix})')

                    # Handler errors
                    except ValueError as exc:

                        # Yield (or re-raise) route error
                        yield from route_error(FtlLglDataError('Unable to decode prefix',
                                               reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX, data=line, exception=exc))

                        # Reset parser state
                        multiline = ''
                        continue

                    # Clone route record (filled with header data)
                    route_record_prefix = list(route_record_header)
                    route_record_proto = proto

                    # Update prefix count
                    if prefix != last_prefix:
                        n_prefixes += 1
                    last_prefix = prefix

                    # Add sequence to route record prefix
                    if FTL_ATTR_BGP_ROUTE_SEQUENCE >= 0:
                        route_record_prefix[FTL_ATTR_BGP_ROUTE_SEQUENCE] = n_prefixes

                    # Add peer protocol to route record prefix
                    if FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL >= 0:
                        peer_proto = proto
                        if FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL_HUMAN:
                            peer_proto = IPV6_STR if peer_proto == IPV6 else IPV4_STR
                        route_record_prefix[FTL_ATTR_BGP_ROUTE_PEER_PROTOCOL] = peer_proto

                    # Add prefix protocol to route record prefix
                    if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL >= 0:
                        prefix_proto = proto
                        if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL_HUMAN:
                            prefix_proto = IPV6_STR if prefix_proto == IPV6 else IPV4_STR
                        route_record_prefix[FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL] = prefix_proto

                    # Add prefix to route record prefix
                    if not FTL_ATTR_BGP_ROUTE_PREFIX_HUMAN:
                        prefix = (prefix_int, mask)
                    if FTL_ATTR_BGP_ROUTE_PREFIX >= 0:
                        route_record_prefix[FTL_ATTR_BGP_ROUTE_PREFIX] = prefix

                    # Add peer protocol to peer table record and yield on first prefix
                    # NOTE: We assume that all routes in a given looking glass dump share the same peer protocol
                    if FTL_RECORD_BGP_PEER_TABLE:
                        if peer_table_record is not None:
                            if FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL >= 0:
                                peer_proto = proto
                                if FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL_HUMAN:
                                    peer_proto = IPV6_STR if peer_proto == IPV6 else IPV4_STR
                                peer_table_record[FTL_ATTR_BGP_PEER_TABLE_PEER_PROTOCOL] = peer_proto

                            # Yield and nullify final peer table record
                            yield peer_table_emit(peer_table_record)
                            peer_table_record = None

                # Should not happen (only on errors or table start with missing first line)
                if route_record_prefix is None:
                    continue

                #############
                # BGP ROUTE #
                #############

                # Clone route record (filled with header+prefix data)
                route_record = list(route_record_prefix)

                # Extract nexthop protocol and IP
                try:
                    nexthop_ip_int = None
                    nexthop_proto = IPV6 if ':' in nexthop_ip else IPV4
                    if nexthop_proto == IPV6:
                        net, host = struct_unpack(STRUCT_8B8B, socket_inet_pton(AF_INET6, nexthop_ip))
                        nexthop_ip_int = (net << 64) + host
                    else:
                        nexthop_ip_int = struct_unpack(STRUCT_4B, socket_inet_pton(AF_INET, nexthop_ip))[0]
                    if FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL >= 0:
                        if FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL_HUMAN:
                            nexthop_proto = IPV6_STR if nexthop_proto == IPV6 else IPV4_STR
                        route_record[FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL] = nexthop_proto
                    if FTL_ATTR_BGP_ROUTE_NEXTHOP_IP >= 0:
                        if not FTL_ATTR_BGP_ROUTE_NEXTHOP_IP_HUMAN:
                            nexthop_ip = nexthop_ip_int
                        route_record[FTL_ATTR_BGP_ROUTE_NEXTHOP_IP] = nexthop_ip

                # Handle error
                except ValueError as exc:

                    # Yield (or re-raise) route error
                    yield from route_error(FtlLglDataError('Unable to decode nexthop IP',
                                           reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_IP, data=line, exception=exc))

                    # Reset route record and parser state
                    route_record_prefix = None
                    route_record_proto = None
                    multiline = ''
                    continue

                # Extract MED metric
                try:
                    if med is not None:
                        med_int = int(med)

                        # Add MED metric to route record
                        if FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC >= 0:
                            route_record[FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC] = med_int

                # Handle error
                except ValueError as exc:

                    # Yield (or re-raise) route error
                    yield from route_error(FtlLglDataError('Unable to decode MED metric',
                                           reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR, data=line, exception=exc))

                    # Reset route record and parser state
                    route_record_prefix = None
                    route_record_proto = None
                    multiline = ''
                    continue

                # Extract local pref
                try:
                    if locpref is not None:
                        locpref_int = int(locpref)

                        # Add local_pref to route record
                        if FTL_ATTR_BGP_ROUTE_LOCAL_PREF >= 0:
                            route_record[FTL_ATTR_BGP_ROUTE_LOCAL_PREF] = locpref_int

                # Handle error
                except ValueError as exc:

                    # Yield (or re-raise) route error
                    yield from route_error(FtlLglDataError('Unable to decode local-pref',
                                           reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR, data=line, exception=exc))

                    # Reset route record and parser state
                    route_record_prefix = None
                    route_record_proto = None
                    multiline = ''
                    continue

                # Extract AS path
                try:
                    aspath = (tuple() if aspath is None else
                              tuple(tuple(sorted(set(int(y) for y in x[1:-1].split(',') if len(y) > 0)))
                                    if x[0] == '{' else int(x) for x in aspath.split()))

                    # Add AS path to route record
                    if FTL_ATTR_BGP_ROUTE_ASPATH >= 0:
                        route_record[FTL_ATTR_BGP_ROUTE_ASPATH] = aspath

                # Handle error
                except ValueError as exc:

                    # Yield (or re-raise) route error
                    yield from route_error(FtlLglDataError('Unable to decode AS path',
                                           reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_ASPATH, data=line, exception=exc))

                    # Reset route record and parser state
                    route_record_prefix = None
                    route_record_proto = None
                    multiline = ''
                    continue

                # Add origin to route record
                if FTL_ATTR_BGP_ROUTE_ORIGIN >= 0:
                    origin_value = None
                    if origin == 'i':
                        origin_value = (FTL_ATTR_BGP_ROUTE_ORIGIN_IGP_STR if FTL_ATTR_BGP_ROUTE_ORIGIN_HUMAN else
                                        FTL_ATTR_BGP_ROUTE_ORIGIN_IGP)
                    elif origin == 'e':
                        origin_value = (FTL_ATTR_BGP_ROUTE_ORIGIN_EGP_STR if FTL_ATTR_BGP_ROUTE_ORIGIN_HUMAN else
                                        FTL_ATTR_BGP_ROUTE_ORIGIN_EGP)
                    elif origin == '?':
                        origin_value = (FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE_STR if FTL_ATTR_BGP_ROUTE_ORIGIN_HUMAN else
                                        FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE)
                    if origin_value is not None:
                        route_record[FTL_ATTR_BGP_ROUTE_ORIGIN] = origin_value

                # Update stats
                if route_record_proto == IPV6:
                    n_routes6 += 1
                else:
                    n_routes4 += 1

                # Yield final route
                if FTL_RECORD_BGP_ROUTE:
                    yield route_emit(route_record)

        #############
        # BGP STATS #
        #############

        #  ------------------------
        #  [PCH] % sh bgp ipv4 wide
        #  ------------------------
        #  Displayed  612636 routes and 1443316 total paths

        #  ------------------------
        #  [PCH] % sh bgp ipv4 wide
        #  ------------------------
        #  Total number of prefixes 612636

        # Extract totals from last line for sanitarization
        match = ROUTE_TOTAL1_REGEX.match(multiline)
        if match is not None:
            try:
                prefixes = int(match.group(1))
                routes = int(match.group(2))
            except ValueError:
                pass
        else:
            match = ROUTE_TOTAL2_REGEX.match(multiline)
            if match is not None:
                try:
                    prefixes = int(match.group(1))
                except ValueError:
                    pass

        # Check prefix parsing result
        if prefixes is not None and prefixes != n_prefixes:
            message = 'Mismatching number of looking glass prefixes ({:,}/{:,})'.format(n_prefixes, prefixes)
            yield from bgp_error(FtlLglDataError(message, reason=FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA, data=line))

        # Check route parsing result
        if routes is not None and routes != n_routes4 + n_routes6:
            message = 'Mismatching number of looking glass routes ({:,}/{:,})'.format(n_routes4 + n_routes6, routes)
            yield from bgp_error(FtlLglDataError(message, reason=FTL_ATTR_BGP_ERROR_REASON_MISSING_DATA, data=line))

        # Update stats record
        if FTL_RECORD_BGP_STATS:

            # Add number of entries
            if FTL_ATTR_BGP_STATS_LGL_ENTRIES >= 0:
                stats_record[FTL_ATTR_BGP_STATS_LGL_ENTRIES] += n_prefixes

            # Add number of RIB routes
            if FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4 >= 0:
                stats_record[FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV4] += n_routes4

            # Add number of RIB routes
            if FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6 >= 0:
                stats_record[FTL_ATTR_BGP_STATS_BGP_ROUTES_RIB_IPV6] += n_routes6

    # Re-raise already handled header exceptions as format exceptions
    except FtlLglHeaderError as error:
        raise FtlLglFormatError(error=error)  # pylint: disable=raise-missing-from

    # Re-raise already handled record errors
    except FtlLglError as error:
        raise error

    # Yield (or re-raise) unhandled exceptions
    except Exception as exc:  # pylint: disable=broad-exception-caught
        yield from bgp_error(FtlLglDataError('Unhandled data error', data=line, trace=True, exception=exc))
