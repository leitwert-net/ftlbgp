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
from ...const import IPV4
from ...const import IPV6
from ...const import IPV4_STR
from ...const import IPV6_STR
from ...const import AF_INET
from ...const import AF_INET6
from ...const import STRUCT_4B
from ...const import STRUCT_8B8B
from ...const import struct_unpack
from ...const import socket_inet_ntop
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX
from ....model.attr import FTL_ATTR_BGP_ROUTE_PATH_ID
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_PREFIX_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_FIXES
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH_STR
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX
from ....model.record import FTL_RECORD_BGP_STATS
from ....model.error import FtlMrtDataError


def unpack_mrt_bgp_nlri(caches, stats_record, nlri_bytes, afinet, nexthop_proto=None, nexthop_ip=None, addpath=False,
                        addpath_error=None, relaxed=False):
    """ Parse MRT NLRI list.
    """
    # Initialize NLRI list and protocol
    nlri, prefix_proto = list(), None

    # Parse protocol
    iplen, ipbits = (16, 128) if afinet == AF_INET6 else (4, 32)
    if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL >= 0:
        if FTL_ATTR_BGP_ROUTE_PREFIX_PROTOCOL_HUMAN:
            prefix_proto = IPV6_STR if afinet == AF_INET6 else IPV4_STR
        else:
            prefix_proto = IPV6 if afinet == AF_INET6 else IPV4

    # --------------------------
    # [RFC4760] 5. NLRI Encoding
    # --------------------------
    # The Network Layer Reachability information is encoded as one or more
    # 2-tuples of the form <length, prefix>, whose fields are described
    # below:
    #
    # +---------------------------+
    # |   Length (1 octet)        |
    # +---------------------------+
    # |   Prefix (variable)       |
    # +---------------------------+
    #
    # The use and the meaning of these fields are as follows:
    #
    # a) Length:
    #
    #    The Length field indicates the length, in bits, of the address
    #    prefix. A length of zero indicates a prefix that matches all (as
    #    specified by the address family) addresses (with prefix, itself,
    #    of zero octets).
    #
    # b) Prefix:
    #
    #    The Prefix field contains an address prefix followed by enough
    #    trailing bits to make the end of the field fall on an octet
    #    boundary. Note that the value of trailing bits is irrelevant.

    # Prepare byte offset
    offset = 0

    # Parse NLRI list
    try:
        nlrilen = len(nlri_bytes)
        while offset < nlrilen:

            # Initialize prefix and ADD-PATH path ID
            prefix, path_id = None, None

            # ------------------------------------
            # [RFC7911] 3. Extended NLRI Encodings
            # ------------------------------------
            # In order to carry the Path Identifier in an UPDATE message, the NLRI
            # encoding MUST be extended by prepending the Path Identifier field,
            # which is of four octets.
            #
            # For example, the NLRI encoding specified in [RFC4271] is extended as
            # the following:
            #
            # +--------------------------------+
            # | Path Identifier (4 octets)     |
            # +--------------------------------+
            # | Length (1 octet)               |
            # +--------------------------------+
            # | Prefix (variable)              |
            # +--------------------------------+
            #
            # The Path Identifier specified in Section 3 can be used to advertise
            # multiple paths for the same address prefix without subsequent
            # advertisements replacing the previous ones. Apart from the fact that
            # this is now possible, the route advertisement rules of [RFC4271] are
            # not changed. In particular, a new advertisement for a given address
            # prefix and a given Path Identifier replaces a previous advertisement
            # for the same address prefix and Path Identifier. If a BGP speaker
            # receives a message to withdraw a prefix with a Path Identifier not
            # seen before, it SHOULD silently ignore it.
            #
            # A BGP speaker SHOULD include the best route [RFC4271] when more than
            # one path is advertised to a neighbor, unless it is a path received
            # from that neighbor.
            #
            # As the Path Identifiers are locally assigned, and may or may not be
            # persistent across a control plane restart of a BGP speaker.

            # Handle ADD-PATH path ID
            if addpath is True:

                # Check remaining bytes
                if offset + 5 > nlrilen:
                    raise ValueError('incomplete ADD-PATH prefix')

                # Parse ADD-PATH path ID
                if FTL_ATTR_BGP_ROUTE_PATH_ID >= 0:
                    path_id = struct_unpack(STRUCT_4B, nlri_bytes[offset:offset + 4])[0]
                offset += 4

            # Parse prefix mask
            mask = nlri_bytes[offset]
            plen = (mask + 7) // 8
            offset += 1

            # Check remaining bytes
            if offset + plen > nlrilen:
                raise ValueError('incomplete prefix')

            # Parse prefix bytes
            prefix_bytes = nlri_bytes[offset:offset + plen]
            if plen < iplen:
                prefix_bytes = b''.join((prefix_bytes, bytearray(iplen - plen)))
            offset += plen

            # Check for invalid mask
            if mask > ipbits:
                raise ValueError(f'invalid {IPV6_STR if afinet == AF_INET6 else IPV4_STR} mask (/{mask})')

            # Parse prefix address
            prefix_int = 0
            if afinet == AF_INET6:
                net, host = struct_unpack(STRUCT_8B8B, prefix_bytes)
                prefix_int = (net << 64) + host
            else:
                prefix_int = struct_unpack(STRUCT_4B, prefix_bytes)[0]

            # Check for invalid address (passes #1 and #2 only)
            if relaxed is False:

                # Blacklist default routes
                if mask == 0:
                    raise ValueError(f'invalid {IPV6_STR if afinet == AF_INET6 else IPV4_STR} default route')

                # Blacklist 0.0.0.0/8 and 240.0.0.0/4 [RFC791/RFC1112]
                if afinet == AF_INET:
                    if not 0xffffff < prefix_int < 0xf0000000:
                        raise ValueError(f'invalid {IPV4_STR} address ({socket_inet_ntop(afinet, prefix_bytes)}/{mask})')

                # Whitelist 2000::/3 [RFC4291]
                elif mask < 3 or prefix_int >> 125 != 1:  # pylint: disable=confusing-consecutive-elif

                    # Whitelist fc00::/7 [RFC8190]
                    if mask < 7 or prefix_int >> 120 not in {0xfc, 0xfd}:

                        # Whitelist ff00::/8 [RFC2373]
                        if mask < 8 or prefix_int >> 120 != 0xff:

                            # Whitelist fe80::/10 [RFC4291]
                            if mask < 10 or prefix_int >> 118 != 0x3fa:

                                # Whitelist 2620:4f:8000::/48 and 64:ff9b:1::/48 [RFC7534/RFC8215]
                                if mask < 48 or prefix_int >> 80 not in {0x2620004f8000, 0x64ff9b0001}:

                                    # Whitelist 100::/64 [RFC6666]
                                    if mask < 64 or prefix_int >> 64 != 0x100000000000000:

                                        # Whitelist 64:ff9b::/96 and ::ffff:0:0/96 (and 0::/96) [RFC6052/RFC4291]
                                        if mask < 96 or prefix_int >> 32 not in {0x64ff9b0000000000000000, 0xffff, 0x0}:

                                            # Invalid ipv6 prefix
                                            raise ValueError(f'invalid {IPV6_STR} address '
                                                             f'({socket_inet_ntop(afinet, prefix_bytes)}/{mask})')

            # Check for invalid alignment
            shift = ipbits - mask
            if (prefix_int >> shift) << shift != prefix_int:
                raise ValueError(f'misaligned prefix ({socket_inet_ntop(afinet, prefix_bytes)}/{mask})')

            # Parse prefix
            if FTL_ATTR_BGP_ROUTE_PREFIX >= 0:
                if FTL_ATTR_BGP_ROUTE_PREFIX_HUMAN:
                    prefix = f'{socket_inet_ntop(afinet, prefix_bytes)}/{mask}'
                else:
                    prefix = (prefix_int, mask)

            # Update NLRI list
            nlri.append((afinet, prefix_proto, prefix, path_id, nexthop_proto, nexthop_ip))

    # Handle prefix errors
    except ValueError as exc:

        # Prepare data error
        first_try = False
        if addpath_error is None:
            first_try = True
            addpath_error = FtlMrtDataError('Unable to decode NLRI entries',
                                            reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PREFIX, data=nlri_bytes,
                                            exception=exc)

        # Allow for less strict NLRI parsing
        if relaxed is False:

            # Retry with ADD-PATH support
            # NOTE: Some MRT exporters include path IDs but fail to set an ADD-PATH message subtype (RFC7911)
            if addpath is False:
                return unpack_mrt_bgp_nlri(caches, stats_record, nlri_bytes, afinet, nexthop_proto=nexthop_proto,
                                           nexthop_ip=nexthop_ip, addpath=True, addpath_error=addpath_error)

            # Retry with relaxed prefix validation (after ADD-PATH retry failed)
            if first_try is False:
                return unpack_mrt_bgp_nlri(caches, stats_record, nlri_bytes, afinet, nexthop_proto=nexthop_proto,
                                           nexthop_ip=nexthop_ip, addpath=False, addpath_error=addpath_error,
                                           relaxed=True)

        # All retries failed
        raise addpath_error  # pylint: disable=raise-missing-from

    # Check for ADD-PATH fixes
    if addpath is True and addpath_error is not None:

        # Update stats record
        if FTL_RECORD_BGP_STATS:

            # Add ADD-PATH fix
            if FTL_ATTR_BGP_STATS_MRT_FIXES >= 0:
                fixtype = str(FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH)
                if FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN:
                    fixtype = FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH_STR
                stats_record_fix = stats_record[FTL_ATTR_BGP_STATS_MRT_FIXES]
                stats_record_fix[fixtype] = stats_record_fix.get(fixtype, 0) + 1

    # Return NRLI listTTR_BGP_STATS_MRT_FIXES_BGP4MP_ADDPATH
    return tuple(nlri)
