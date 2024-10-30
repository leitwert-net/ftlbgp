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
from .const import BGP_PATH_ATTR_ORIGIN
from .const import BGP_PATH_ATTR_AS_PATH
from .const import BGP_PATH_ATTR_AS4_PATH
from .const import BGP_PATH_ATTR_AS_PATH_SEGMENT_SET
from .const import BGP_PATH_ATTR_AS_PATH_SEGMENT_CONFED_SET
from .const import BGP_PATH_ATTR_AS4_PATH_AS_TRANS
from .const import BGP_PATH_ATTR_NEXT_HOP
from .const import BGP_PATH_ATTR_COMMUNITIES
from .const import BGP_PATH_ATTR_LARGE_COMMUNITIES
from .const import BGP_PATH_ATTR_EXTENDED_COMMUNITIES
from .const import BGP_PATH_ATTR_MULTI_EXIT_DISC
from .const import BGP_PATH_ATTR_MP_REACH_NLRI
from .const import BGP_PATH_ATTR_MP_UNREACH_NLRI
from .const import BGP_PATH_ATTR_ATOMIC_AGGREGATE
from .const import BGP_PATH_ATTR_AGGREGATOR
from .const import BGP_PATH_ATTR_AS4_AGGREGATOR
from .const import BGP_PATH_ATTR_ONLY_TO_CUSTOMER
from .const import BGP_PATH_ATTR_ORIGINATOR_ID
from .const import BGP_PATH_ATTR_CLUSTER_LIST
from .const import BGP_PATH_ATTR_LOCAL_PREF
from .const import BGP_PATH_ATTR_ATTR_SET
from .const import BGP_PATH_ATTR_AS_PATHLIMIT
from .const import BGP_PATH_ATTR_AIGP
from .nlri import unpack_mrt_bgp_nlri
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
from ...const import STRUCT_8B
from ...const import STRUCT_2B2B
from ...const import STRUCT_8B8B
from ...const import STRUCT_2B2B2B
from ...const import STRUCT_4B4B4B
from ...const import struct_unpack
from ...const import socket_inet_ntop
from ....model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_IP
from ....model.attr import FTL_ATTR_BGP_ROUTE_ASPATH
from ....model.attr import FTL_ATTR_BGP_ROUTE_ORIGIN
from ....model.attr import FTL_ATTR_BGP_ROUTE_COMMUNITIES
from ....model.attr import FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES
from ....model.attr import FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES
from ....model.attr import FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC
from ....model.attr import FTL_ATTR_BGP_ROUTE_ATOMIC_AGGREGATE
from ....model.attr import FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL
from ....model.attr import FTL_ATTR_BGP_ROUTE_AGGREGATOR_AS
from ....model.attr import FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP
from ....model.attr import FTL_ATTR_BGP_ROUTE_ONLY_TO_CUSTOMER
from ....model.attr import FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID
from ....model.attr import FTL_ATTR_BGP_ROUTE_CLUSTER_LIST
from ....model.attr import FTL_ATTR_BGP_ROUTE_LOCAL_PREF
from ....model.attr import FTL_ATTR_BGP_ROUTE_ATTR_SET
from ....model.attr import FTL_ATTR_BGP_ROUTE_AS_PATHLIMIT
from ....model.attr import FTL_ATTR_BGP_ROUTE_AIGP
from ....model.attr import FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN
from ....model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_NEXTHOP_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_ORIGIN_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_COMMUNITIES_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_CLUSTER_LIST_HUMAN
from ....model.attr import FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_FIXES
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN
from ....model.attr import FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES_HUMAN
from ....model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_IGP
from ....model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_IGP_STR
from ....model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_EGP
from ....model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_EGP_STR
from ....model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE
from ....model.const import FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE_STR
from ....model.const import FTL_ATTR_BGP_STATS_BGP_PATH_ATTR_TO_STR
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH_STR
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH_STR
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_NLRI
from ....model.const import FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_NLRI_STR
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL
from ....model.const import FTL_ATTR_BGP_ERROR_REASON_INVALID_ASPATH
from ....model.record import FTL_RECORD_BGP_STATS
from ....model.error import FtlMrtDataError


def unpack_mrt_bgp_attr(caches, stats_record, route_init, route_emit, route_record, attr_bytes, aslen=4, addpath=False,
                        rib=False):
    """ Parse MRT attributes.
    """
    # Prepare AS byte length
    asbytelen = STRUCT_2B if aslen == 2 else STRUCT_4B

    # Initialize AS/AS4 path support
    aspath, aggr_as, aggr_ip = None, None, None
    as4path, aggr4_as, aggr4_ip = None, None, None

    # Initialize announced/withdrawn prefixes
    nlri, nlui = tuple(), tuple()

    #####################
    # ATTRIBUTE PARSING #
    #####################

    # Prepare byte offset
    offset = 0

    # ------------------------------------
    # [RFC4271] 4.3. UPDATE Message Format
    # ------------------------------------
    # 0                   1
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Attr. Flags  |Attr. Type Code|
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    # Parse attributes
    attrlen = len(attr_bytes)
    while offset < attrlen:

        # Parse attribute flags
        flags = attr_bytes[offset]
        offset += 1

        # Parse attribute type
        atype = attr_bytes[offset]
        offset += 1

        # Update stats record
        if FTL_RECORD_BGP_STATS:

            # Add attribute type
            if FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES >= 0:
                attrtype = atype
                if FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES_HUMAN:
                    attrtype = FTL_ATTR_BGP_STATS_BGP_PATH_ATTR_TO_STR.get(atype, atype)
                attrtype = str(attrtype)
                stats_record_mrt_bgp_attr = stats_record[FTL_ATTR_BGP_STATS_MRT_BGP_ATTRIBUTE_TYPES]
                stats_record_mrt_bgp_attr[attrtype] = stats_record_mrt_bgp_attr.get(attrtype, 0) + 1

        # ------------------------------------
        # [RFC4271] 4.3. UPDATE Message Format
        # ------------------------------------
        # The fourth high-order bit (bit 3) of the Attribute Flags octet
        # is the Extended Length bit. It defines whether the Attribute
        # Length is one octet (if set to 0) or two octets (if set to 1).
        #
        # If the Extended Length bit of the Attribute Flags octet is set
        # to 0, the third octet of the Path Attribute contains the length
        # of the attribute data in octets.
        #
        # If the Extended Length bit of the Attribute Flags octet is set
        # to 1, the third and fourth octets of the path attribute contain
        # the length of the attribute data in octets.

        # Parse attribute length
        alen = 0
        if flags & 0b00010000:
            alen = struct_unpack(STRUCT_2B, attr_bytes[offset:offset + 2])[0]
            offset += 2
        else:
            alen = attr_bytes[offset]
            offset += 1

        # Prepare attribute byte offsets (current/end)
        cur_offset, end_offset = offset, offset + alen
        offset = end_offset

        # Sanitize attribute
        if offset > attrlen:
            # NOTE: A few UPDATE messages (3-5) from RouteViews Oregon2 occasionally include incomplete BGP attributes
            raise FtlMrtDataError(f'Incomplete BGP attribute ({attrlen - cur_offset}B<{alen}B)',
                                  reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR, data=attr_bytes)

        ####################
        # ORIGIN ATTRIBUTE #
        ####################

        # --------------------------------------------------------------
        # [RFC4271] 4.3. UPDATE Message Format - a) ORIGIN (Type Code 1)
        # --------------------------------------------------------------
        # ORIGIN is a well-known mandatory attribute that defines the
        # origin of the path information. The data octet can assume
        # the following values:
        #
        #    Value      Meaning
        #
        #    0         IGP - Network Layer Reachability Information
        #                 is interior to the originating AS
        #
        #    1         EGP - Network Layer Reachability Information
        #                 learned via the EGP protocol [RFC904]
        #
        #    2         INCOMPLETE - Network Layer Reachability
        #                 Information learned by some other means

        # Parse origin attribute
        if atype == BGP_PATH_ATTR_ORIGIN:
            if FTL_ATTR_BGP_ROUTE_ORIGIN >= 0:
                origin = attr_bytes[cur_offset]
                if FTL_ATTR_BGP_ROUTE_ORIGIN_HUMAN:
                    if origin == FTL_ATTR_BGP_ROUTE_ORIGIN_IGP:
                        origin = FTL_ATTR_BGP_ROUTE_ORIGIN_IGP_STR
                    elif origin == FTL_ATTR_BGP_ROUTE_ORIGIN_EGP:
                        origin = FTL_ATTR_BGP_ROUTE_ORIGIN_EGP_STR
                    elif origin == FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE:
                        origin = FTL_ATTR_BGP_ROUTE_ORIGIN_INCOMPLETE_STR
                route_record[FTL_ATTR_BGP_ROUTE_ORIGIN] = origin

        #####################
        # AS_PATH ATTRIBUTE #
        #####################

        # ---------------------------------------------------------------
        # [RFC4271] 4.3. UPDATE Message Format - b) AS_PATH (Type Code 2)
        # ---------------------------------------------------------------
        # AS_PATH is a well-known mandatory attribute that is composed
        # of a sequence of AS path segments. Each AS path segment is
        # represented by a triple <path segment type, path segment
        # length, path segment value>.
        #
        # The path segment type is a 1-octet length field with the
        # following values defined:
        #
        #    Value      Segment Type
        #
        #    1         AS_SET: unordered set of ASes a route in the
        #                 UPDATE message has traversed
        #
        #    2         AS_SEQUENCE: ordered set of ASes a route in
        #                 the UPDATE message has traversed
        #
        # The path segment length is a 1-octet length field,
        # containing the number of ASes (not the number of octets) in
        # the path segment value field.
        #
        # The path segment value field contains one or more AS
        # numbers, each encoded as a 2-octet length field.

        # -----------------------------
        # [RFC6793] Protocol Extensions
        # -----------------------------
        # This document defines a new BGP path attribute called AS4_PATH.
        # This is an optional transitive attribute that contains the AS path
        # encoded with four-octet AS numbers. The AS4_PATH attribute has the
        # same semantics and the same encoding as the AS_PATH attribute,
        # except that it is "optional transitive", and it carries four-octet
        # AS numbers.

        # Parse AS/AS4 path attribute
        # pylint: disable-next=confusing-consecutive-elif,consider-using-in
        elif atype == BGP_PATH_ATTR_AS_PATH or atype == BGP_PATH_ATTR_AS4_PATH:
            if FTL_ATTR_BGP_ROUTE_ASPATH >= 0:

                # Sanitize AS path attribute
                # NOTE: Some MRT exporters fail to set correct AS/AS4 path type
                hoplen, hopbytelen = aslen, asbytelen
                c_offset2, c_offset4 = cur_offset, cur_offset
                do_continue = True
                while do_continue:
                    do_continue = False
                    if c_offset2 < end_offset:
                        c_offset2 += attr_bytes[c_offset2 + 1] * 2 + 2
                        do_continue = True
                    if c_offset4 < end_offset:
                        c_offset4 += attr_bytes[c_offset4 + 1] * 4 + 2
                        do_continue = True
                if c_offset2 == c_offset4 == end_offset:
                    hoplen, hopbytelen = aslen, asbytelen
                elif c_offset4 == end_offset:
                    hoplen, hopbytelen = 4, STRUCT_4B
                elif c_offset2 == end_offset:
                    hoplen, hopbytelen = 2, STRUCT_2B
                else:
                    hlen = end_offset - cur_offset
                    chlen = (c_offset4 if aslen == 4 else c_offset2) - cur_offset
                    raise FtlMrtDataError(f'Incomplete AS path attribute ({chlen}>{hlen}B)',
                                          reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_ASPATH, data=attr_bytes)

                # Check for AS length fixes
                if hoplen != aslen:

                    # Update stats record
                    if FTL_RECORD_BGP_STATS:

                        # Add AS length fix
                        if FTL_ATTR_BGP_STATS_MRT_FIXES >= 0:
                            fixtype = str(FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH if rib is False
                                          else FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH)
                            if FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN:
                                fixtype = (FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH_STR if rib is False
                                           else FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH_STR)
                            stats_record_fix = stats_record[FTL_ATTR_BGP_STATS_MRT_FIXES]
                            stats_record_fix[fixtype] = stats_record_fix.get(fixtype, 0) + 1

                # Parse AS path segments
                cur_aspath = list()
                while cur_offset < end_offset:

                    # Parse path segment type
                    stype = attr_bytes[cur_offset]
                    cur_offset += 1

                    # Parse path segment length
                    slen = attr_bytes[cur_offset]
                    cur_offset += 1

                    # Parse path segment or set
                    target, asset = cur_aspath, False
                    # pylint: disable-next=consider-using-in
                    if stype == BGP_PATH_ATTR_AS_PATH_SEGMENT_SET or stype == BGP_PATH_ATTR_AS_PATH_SEGMENT_CONFED_SET:
                        target, asset = list(), True

                    # Parse path segment/set value
                    for cur_offset in range(cur_offset + hoplen, cur_offset + hoplen * slen + hoplen, hoplen):
                        target.append(struct_unpack(hopbytelen, attr_bytes[cur_offset - hoplen:cur_offset])[0])

                    # Finalize path set
                    if asset is True:
                        cur_aspath.append(tuple(sorted(set(target))))

                # --------------------------------------------
                # [RFC6793] 4.2.3. Processing Received Updates
                # --------------------------------------------
                # When a NEW BGP speaker receives an update from an OLD BGP speaker, it
                # MUST be prepared to receive the AS4_PATH attribute along with the
                # existing AS_PATH attribute. If the AS4_PATH attribute is also
                # received, both of the attributes will be used to construct the exact
                # AS path information, and therefore the information carried by both of
                # the attributes will be considered for AS path loop detection.

                # Update AS path
                if atype == BGP_PATH_ATTR_AS_PATH:
                    aspath = cur_aspath
                elif atype == BGP_PATH_ATTR_AS4_PATH:
                    as4path = cur_aspath

        #########################
        # COMMUNITIES ATTRIBUTE #
        #########################

        # -------------------------------
        # [RFC1997] COMMUNITIES attribute
        # -------------------------------
        # This document creates the COMMUNITIES path attribute is an optional
        # transitive attribute of variable length. The attribute consists of a
        # set of four octet values, each of which specify a community. All
        # routes with this attribute belong to the communities listed in the
        # attribute.
        #
        # The community attribute values shall be encoded using an autonomous
        # system number in the first two octets. The semantics of the final
        # two octets may be defined by the autonomous system.

        # Parse communities attribute
        elif atype == BGP_PATH_ATTR_COMMUNITIES:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_COMMUNITIES >= 0:
                if FTL_ATTR_BGP_ROUTE_COMMUNITIES_HUMAN:
                    route_record[FTL_ATTR_BGP_ROUTE_COMMUNITIES] = tuple(
                        '{}:{}'.format(*struct_unpack(STRUCT_2B2B, attr_bytes[c_offset:c_offset + 4]))
                        for c_offset in range(cur_offset, end_offset, 4))
                else:
                    route_record[FTL_ATTR_BGP_ROUTE_COMMUNITIES] = tuple(
                        struct_unpack(STRUCT_4B, attr_bytes[c_offset:c_offset + 4])[0]
                        for c_offset in range(cur_offset, end_offset, 4))

        ######################
        # NEXT_HOP ATTRIBUTE #
        ######################

        # ----------------------------------------------------------------
        # [RFC4271] 4.3. UPDATE Message Format - c) NEXT_HOP (Type Code 3)
        # ----------------------------------------------------------------
        # This is a well-known mandatory attribute that defines the
        # (unicast) IP address of the router that SHOULD be used as
        # the next hop to the destinations listed in the Network Layer
        # Reachability Information field of the UPDATE message.

        # Parse nexthop IP attribute (IPv4 only)
        elif atype == BGP_PATH_ATTR_NEXT_HOP:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL >= 0:
                nexthop_proto = IPV4_STR if FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL_HUMAN else IPV4
                route_record[FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL] = nexthop_proto
            if FTL_ATTR_BGP_ROUTE_NEXTHOP_IP >= 0:
                nexthop_ip = attr_bytes[cur_offset:end_offset]
                if FTL_ATTR_BGP_ROUTE_NEXTHOP_IP_HUMAN:
                    route_record[FTL_ATTR_BGP_ROUTE_NEXTHOP_IP] = socket_inet_ntop(AF_INET, nexthop_ip)
                else:
                    route_record[FTL_ATTR_BGP_ROUTE_NEXTHOP_IP] = struct_unpack(STRUCT_4B, nexthop_ip)[0]

        ###########################
        # MP_REACH_NLRI ATTRIBUTE #
        ###########################

        # ------------------------------------------------------------------------
        # [RFC4760] 3. Multiprotocol Reachable NLRI - MP_REACH_NLRI (Type Code 14)
        # ------------------------------------------------------------------------
        # This is an optional non-transitive attribute that can be used for the
        # following purposes:
        #
        # (a) to advertise a feasible route to a peer
        #
        # (b) to permit a router to advertise the Network Layer address of the
        #     router that should be used as the next hop to the destinations
        #     listed in the Network Layer Reachability Information field of the
        #     MP_NLRI attribute.
        #
        # +---------------------------------------------------------+
        # | Address Family Identifier (2 octets)                    |
        # +---------------------------------------------------------+
        # | Subsequent Address Family Identifier (1 octet)          |
        # +---------------------------------------------------------+
        # | Length of Next Hop Network Address (1 octet)            |
        # +---------------------------------------------------------+
        # | Network Address of Next Hop (variable)                  |
        # +---------------------------------------------------------+
        # | Reserved (1 octet)                                      |
        # +---------------------------------------------------------+
        # | Network Layer Reachability Information (variable)       |
        # +---------------------------------------------------------+
        #
        # An UPDATE message that carries the MP_REACH_NLRI MUST also carry the
        # ORIGIN and the AS_PATH attributes (both in EBGP and in IBGP
        # exchanges). Moreover, in IBGP exchanges such a message MUST also
        # carry the LOCAL_PREF attribute.
        #
        # An UPDATE message that carries no NLRI, other than the one encoded in
        # the MP_REACH_NLRI attribute, SHOULD NOT carry the NEXT_HOP attribute.
        # If such a message contains the NEXT_HOP attribute, the BGP speaker
        # that receives the message SHOULD ignore this attribute.

        # Parse reachable prefix attribute
        elif atype == BGP_PATH_ATTR_MP_REACH_NLRI:  # pylint: disable=confusing-consecutive-elif
            afinet = None

            # Parse UPDATE message (including AFI/SAFI)
            if rib is False:

                # Parse AFI value
                afi = struct_unpack(STRUCT_2B, attr_bytes[cur_offset:cur_offset + 2])[0]
                cur_offset += 2

                # Parse SAFI value
                safi = attr_bytes[cur_offset]
                cur_offset += 1

                # Check AFI value
                if afi != AFI_IPV4 and afi != AFI_IPV6:  # pylint: disable=consider-using-in
                    raise FtlMrtDataError(f'Invalid AFI value ({afi}) in MP_REACH_NLRI attribute',
                                          reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=attr_bytes)

                # Check SAFI value
                if safi != BGP_SAFI_UNICAST and safi != BGP_SAFI_MULTICAST:  # pylint: disable=consider-using-in
                    raise FtlMrtDataError(f'Unsupported SAFI value ({safi}) in MP_REACH_NLRI attribute',
                                          reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=attr_bytes)

                # Parse protocol
                afinet = AF_INET6 if afi == AFI_IPV6 else AF_INET

            # ----------------------------
            # [RFC6396] 4.3.4. RIB Entries
            # ----------------------------
            # There is one exception to the encoding of BGP attributes for the BGP
            # MP_REACH_NLRI attribute (BGP Type Code 14) [RFC4760]. Since the AFI,
            # SAFI, and NLRI information is already encoded in the RIB Entry Header
            # or RIB_GENERIC Entry Header, only the Next Hop Address Length and
            # Next Hop Address fields are included. The Reserved field is omitted.
            # The attribute length is also adjusted to reflect only the length of
            # the Next Hop Address Length and Next Hop Address fields.

            # ----------------
            # [RFC6396] Errata
            # ----------------
            # The encoding of the MP_REACH_NLRI attribute is not in the form
            # according to Section 4.3.4. RIB Entries.
            #
            # NOTE: This seems to be an IPv6-related issue
            #
            # The example includes a full MP_REACH_NLRI attribute. This is a common
            # issue with TABLE_DUMP_V2 and parsers need to implement a workaround to
            # support the broken form.
            #
            # One way of solving this is to compare the attribute length of
            # MP_REACH_NLRI with the first byte of the attribute. If the value of the
            # first byte is equal to the attribute lenght - 1 then it is the RFC
            # encoding else assume that a full MP_REACH_NLRI attribute was dumped in
            # which case the parser needs to skip the first 3 bytes to get to the
            # nexthop.

            # Parse RIB entry (with or without AFI/SAFI)
            elif attr_bytes[cur_offset] != alen - 1:
                cur_offset += 3

                # Update stats record
                if FTL_RECORD_BGP_STATS:

                    # Add ADD-PATH fix
                    if FTL_ATTR_BGP_STATS_MRT_FIXES >= 0:
                        fixtype = str(FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_NLRI)
                        if FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN:
                            fixtype = FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_NLRI_STR
                        stats_record_fix = stats_record[FTL_ATTR_BGP_STATS_MRT_FIXES]
                        stats_record_fix[fixtype] = stats_record_fix.get(fixtype, 0) + 1

            # Parse nexthop length
            nhlen = attr_bytes[cur_offset]
            cur_offset += 1

            # --------------------------------------------
            # [RFC2545] 3. Constructing the Next Hop field
            # --------------------------------------------
            # A BGP speaker shall advertise to its peer in the Network Address of
            # Next Hop field the global IPv6 address of the next hop, potentially
            # followed by the link-local IPv6 address of the next hop.
            #
            # NOTE: We use global IPv6 addresses only, but skip link-local addresses
            #
            # The value of the Length of Next Hop Network Address field on a
            # MP_REACH_NLRI attribute shall be set to 16, when only a global
            # address is present, or 32 if a link-local address is also included in
            # the Next Hop field.

            # Skip link-local address
            nhiplen = nhlen if nhlen != 32 else 16
            mp_afinet = AF_INET6 if nhiplen == 16 else AF_INET

            # Parse nexthop protocol
            mp_nexthop_proto = None
            if FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL >= 0:
                if FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL_HUMAN:
                    mp_nexthop_proto = IPV6_STR if mp_afinet == AF_INET6 else IPV4_STR
                else:
                    mp_nexthop_proto = IPV6 if mp_afinet == AF_INET6 else IPV4
                if rib is True:
                    route_record[FTL_ATTR_BGP_ROUTE_NEXTHOP_PROTOCOL] = mp_nexthop_proto

            # Parse nexthop IP
            mp_nexthop_ip = None
            if FTL_ATTR_BGP_ROUTE_NEXTHOP_IP >= 0:
                nhiplen = nhlen if nhlen != 32 else 16
                mp_afinet = AF_INET6 if nhiplen == 16 else AF_INET
                mp_nexthop_ip = attr_bytes[cur_offset:cur_offset + nhiplen]
                if FTL_ATTR_BGP_ROUTE_NEXTHOP_IP_HUMAN:
                    mp_nexthop_ip = socket_inet_ntop(mp_afinet, mp_nexthop_ip)
                elif mp_afinet == AF_INET6:
                    net, host = struct_unpack(STRUCT_8B8B, mp_nexthop_ip)
                    mp_nexthop_ip = (net << 64) + host
                else:
                    mp_nexthop_ip = struct_unpack(STRUCT_4B, mp_nexthop_ip)[0]
                # NOTE: If there is an MP NEXT_HOP for RIB entries, we overwrite any existing pre-MP NEXT_HOP attribute,
                # NOTE: since there is only one prefix per attribute set (provided outside of MP_REACH_NLRI attributes)
                if rib is True:
                    route_record[FTL_ATTR_BGP_ROUTE_NEXTHOP_IP] = mp_nexthop_ip
            cur_offset += nhlen

            # Parse prefix
            if afinet is not None:

                # Skip reserved byte
                cur_offset += 1

                # Parse NLRI
                # NOTE: For UPDATE messages, we do not overwrite the pre-MP NEXT_HOP attribute, but hand over the MP
                # NOTE: NEXT_HOP to unpack_mrt_bgp_nlri() instead.
                if cur_offset < end_offset:
                    nlri += unpack_mrt_bgp_nlri(caches, stats_record, attr_bytes[cur_offset:end_offset], afinet,
                                                nexthop_proto=mp_nexthop_proto, nexthop_ip=mp_nexthop_ip,
                                                addpath=addpath)

        #############################
        # MULTI_EXIT_DISC ATTRIBUTE #
        #############################

        # -----------------------------------------------------------------------
        # [RFC4271] 4.3. UPDATE Message Format - d) MULTI_EXIT_DISC (Type Code 4)
        # -----------------------------------------------------------------------
        # This is an optional non-transitive attribute that is a
        # four-octet unsigned integer. The value of this attribute
        # MAY be used by a BGP speaker's Decision Process to
        # discriminate among multiple entry points to a neighboring
        # autonomous system.

        # Parse MED metric attribute
        elif atype == BGP_PATH_ATTR_MULTI_EXIT_DISC:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_MULTI_EXIT_DISC] = struct_unpack(STRUCT_4B,
                                                                                 attr_bytes[cur_offset:end_offset])[0]

        ###############################
        # LARGE COMMUNITIES ATTRIBUTE #
        ###############################

        # --------------------------------------------
        # [RFC8092} 3. BGP Large Communities Attribute
        # --------------------------------------------
        # This document defines the BGP Large Communities attribute as an
        # optional transitive path attribute of variable length. All routes
        # with the BGP Large Communities attribute belong to the communities
        # specified in the attribute.
        #
        # Each BGP Large Community value is encoded as a 12-octet quantity, as
        # follows:
        #
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                      Global Administrator                     |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                       Local Data Part 1                       |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                       Local Data Part 2                       |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        # Parse large communities attribute
        elif atype == BGP_PATH_ATTR_LARGE_COMMUNITIES:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES >= 0:
                if FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES_HUMAN:
                    route_record[FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES] = tuple(
                        '{}:{}:{}'.format(*struct_unpack(STRUCT_4B4B4B, attr_bytes[c_offset:c_offset + 12]))
                        for c_offset in range(cur_offset, end_offset, 12))
                else:
                    route_record[FTL_ATTR_BGP_ROUTE_LARGE_COMMUNITIES] = tuple(
                        ((struct_unpack(STRUCT_8B, attr_bytes[c_offset:c_offset + 8])[0] << 32)
                         + struct_unpack(STRUCT_4B, attr_bytes[c_offset + 8:c_offset + 12])[0])
                        for c_offset in range(cur_offset, end_offset, 12))

        #############################
        # MP_UNREACH_NLRI ATTRIBUTE #
        #############################

        # ----------------------------------------------------------------------------
        # [RFC4760] 4. Multiprotocol Unreachable NLRI - MP_UNREACH_NLRI (Type Code 15)
        # ----------------------------------------------------------------------------
        # This is an optional non-transitive attribute that can be used for the
        # purpose of withdrawing multiple unfeasible routes from service.
        #
        # +---------------------------------------------------------+
        # | Address Family Identifier (2 octets)                    |
        # +---------------------------------------------------------+
        # | Subsequent Address Family Identifier (1 octet)          |
        # +---------------------------------------------------------+
        # | Withdrawn Routes (variable)                             |
        # +---------------------------------------------------------+
        #
        # An UPDATE message that contains the MP_UNREACH_NLRI is not required
        # to carry any other path attributes.

        # Parse unreachable prefix attribute
        elif atype == BGP_PATH_ATTR_MP_UNREACH_NLRI:  # pylint: disable=confusing-consecutive-elif

            # Parse UPDATE message
            if rib is False:

                # Parse AFI value
                afi = struct_unpack(STRUCT_2B, attr_bytes[cur_offset:cur_offset + 2])[0]
                cur_offset += 2

                # Parse SAFI value
                safi = attr_bytes[cur_offset]
                cur_offset += 1

                # Check AFI value
                if afi != AFI_IPV4 and afi != AFI_IPV6:  # pylint: disable=consider-using-in
                    raise FtlMrtDataError(f'Invalid AFI value ({afi}) in MP_UNREACH_NLRI attribute',
                                          reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=attr_bytes)

                # Check SAFI value
                if safi != BGP_SAFI_UNICAST and safi != BGP_SAFI_MULTICAST:  # pylint: disable=consider-using-in
                    raise FtlMrtDataError(f'Unsupported SAFI value ({safi}) in MP_UNREACH_NLRI attribute',
                                          reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_PROTOCOL, data=attr_bytes)

                # Parse protocol
                afinet = AF_INET6 if afi == AFI_IPV6 else AF_INET

                # Parse NLRI
                if cur_offset < end_offset:
                    nlui += unpack_mrt_bgp_nlri(caches, stats_record, attr_bytes[cur_offset:end_offset], afinet,
                                                addpath=addpath)

        ########################
        # AGGREGATOR ATTRIBUTE #
        ########################

        # ------------------------------------------------------------------
        # [RFC4271] 4.3. UPDATE Message Format - g) AGGREGATOR (Type Code 7)
        # ------------------------------------------------------------------
        # AGGREGATOR is an optional transitive attribute of length 6.
        # The attribute contains the last AS number that formed the
        # aggregate route (encoded as 2 octets), followed by the IP
        # address of the BGP speaker that formed the aggregate route
        # (encoded as 4 octets). This SHOULD be the same address as
        # the one used for the BGP Identifier of the speaker.

        # -----------------------------
        # [RFC6793] Protocol Extensions
        # -----------------------------
        # This document defines a new BGP path attribute called
        # AS4_AGGREGATOR, which is optional transitive. The AS4_AGGREGATOR
        # attribute has the same semantics and the same encoding as the
        # AGGREGATOR attribute, except that it carries a four-octet AS number.

        # Parse AS/AS4 aggregator attribute (IPv4 only)
        # pylint: disable-next=consider-using-in,confusing-consecutive-elif
        elif atype == BGP_PATH_ATTR_AGGREGATOR or atype == BGP_PATH_ATTR_AS4_AGGREGATOR:
            if (FTL_ATTR_BGP_ROUTE_ASPATH >= 0 or FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL >= 0
                or FTL_ATTR_BGP_ROUTE_AGGREGATOR_AS >= 0 or FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP >= 0):

                # Sanitize aggregator
                # NOTE: Some MRT exporters fail to set correct AS/AS4 aggregator type
                aggasbytelen = STRUCT_2B
                if end_offset - cur_offset == 8:
                    aggasbytelen = STRUCT_4B
                elif end_offset - cur_offset != 6:
                    cagglen = end_offset - cur_offset
                    agglen = 8 if atype == BGP_PATH_ATTR_AS4_AGGREGATOR else 6
                    raise FtlMrtDataError(f'Incomplete aggregator attribute ({cagglen}!={agglen}B)',
                                          reason=FTL_ATTR_BGP_ERROR_REASON_INVALID_ATTR, data=attr_bytes)

                # Check for AS length fixes
                if aggasbytelen != asbytelen:

                    # Update stats record
                    if FTL_RECORD_BGP_STATS:

                        # Add AS length fix
                        if FTL_ATTR_BGP_STATS_MRT_FIXES >= 0:
                            fixtype = str(FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH if rib is False
                                          else FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH)
                            if FTL_ATTR_BGP_STATS_MRT_FIXES_HUMAN:
                                fixtype = (FTL_ATTR_BGP_STATS_MRT_FIXES_BGP4MP_ASLENGTH_STR if rib is False
                                           else FTL_ATTR_BGP_STATS_MRT_FIXES_TDV2_ASLENGTH_STR)
                            stats_record_fix = stats_record[FTL_ATTR_BGP_STATS_MRT_FIXES]
                            stats_record_fix[fixtype] = stats_record_fix.get(fixtype, 0) + 1

                # Parse aggregator
                aggas = struct_unpack(aggasbytelen, attr_bytes[cur_offset:end_offset - 4])[0]
                aggip = attr_bytes[end_offset - 4:end_offset]
                if atype == BGP_PATH_ATTR_AGGREGATOR:
                    aggr_as, aggr_ip = aggas, aggip
                else:
                    aggr4_as, aggr4_ip = aggas, aggip

        ##################################
        # EXTENDED COMMUNITIES ATTRIBUTE #
        ##################################

        # -----------------------------------------------
        # [RFC4360] 2. BGP Extended Communities Attribute
        # -----------------------------------------------
        # The Extended Communities Attribute is a transitive optional BGP
        # attribute, with the Type Code 16. The attribute consists of a set of
        # "extended communities". All routes with the Extended Communities
        # attribute belong to the communities listed in the attribute.
        #
        # Each Extended Community is encoded as an 8-octet quantity, as
        # follows:
        #
        #    - Type Field  : 1 or 2 octets
        #    - Value Field : Remaining octets
        #
        #     0                   1                   2                   3
        #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #    |  Type high    |  Type low(*)  |                               |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          Value                |
        #    |                                                               |
        #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #
        #    (*) Present for Extended types only, used for the Value field
        #        otherwise.

        # Parse extended communities attribute
        elif atype == BGP_PATH_ATTR_EXTENDED_COMMUNITIES:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES >= 0:
                if FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES_HUMAN:
                    route_record[FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES] = tuple(
                        '0x{:02x}:0x{:02x}:{}:{}:{}'.format(
                            attr_bytes[c_offset], attr_bytes[c_offset + 1],
                            *struct_unpack(STRUCT_2B2B2B, attr_bytes[c_offset + 2:c_offset + 8])
                        ) for c_offset in range(cur_offset, end_offset, 8)
                    )
                else:
                    route_record[FTL_ATTR_BGP_ROUTE_EXTENDED_COMMUNITIES] = tuple(
                        struct_unpack(STRUCT_8B, attr_bytes[c_offset:c_offset + 8])[0]
                        for c_offset in range(cur_offset, end_offset, 8)
                    )

        ##############################
        # ATOMIC_AGGREGATE ATTRIBUTE #
        ##############################

        # ------------------------------------------------------------------------
        # [RFC4271] 4.3. UPDATE Message Format - f) ATOMIC_AGGREGATE (Type Code 6)
        # ------------------------------------------------------------------------
        # ATOMIC_AGGREGATE is a well-known discretionary attribute of
        # length 0.

        # Parse atomic aggregate attribute
        elif atype == BGP_PATH_ATTR_ATOMIC_AGGREGATE:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_ATOMIC_AGGREGATE >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_ATOMIC_AGGREGATE] = True

        ##############################
        # ONLY_TO_CUSTOMER ATTRIBUTE #
        ##############################

        # ---------------------------------------------------------------------------
        # [DRAFT-IETF-IDR-BGP-OPEN-POLICY] 7. BGP Internal Only To Customer attribute
        # ---------------------------------------------------------------------------
        # The Internal Only To Customer (iOTC) attribute is a new optional,
        # non-transitive BGP Path attribute with the Type Code <TBD3>. This
        # attribute has zero length as it is used only as a flag.
        #
        # There are three rules of iOTC attribute usage:
        #
        # 1.  The iOTC attribute MUST be added to all incoming routes if the
        #     receiver's Role is Customer or Peer;
        #
        # 2.  Routes with the iOTC attribute set MUST NOT be announced by a
        #     sender whose Role is Customer or Peer;
        #
        # 3.  A sender MUST NOT include this attribute in UPDATE messages if
        #     its Role is Customer, Provider or Peer. If it is contained in an
        #     UPDATE message from eBGP speaker and receiver's Role is Customer,
        #     Provider, Peer or unspecified, then this attribute MUST be
        #     removed.
        #
        # These three rules provide mechanism that strongly prevents route leak
        # creation by an AS.

        # Parse only-to-customer attribute
        elif atype == BGP_PATH_ATTR_ONLY_TO_CUSTOMER:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_ONLY_TO_CUSTOMER >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_ONLY_TO_CUSTOMER] = True

        ###########################
        # ORIGINATOR_ID ATTRIBUTE #
        ###########################

        # -----------------------------------------------
        # [RFC4456] 8. Avoiding Routing Information Loops
        # -----------------------------------------------
        # ORIGINATOR_ID is a new optional, non-transitive BGP attribute of Type
        # code 9. This attribute is 4 bytes long and it will be created by an
        # RR in reflecting a route. This attribute will carry the BGP
        # Identifier of the originator of the route in the local AS. A BGP
        # speaker SHOULD NOT create an ORIGINATOR_ID attribute if one already
        # exists. A router that recognizes the ORIGINATOR_ID attribute SHOULD
        # ignore a route received with its BGP Identifier as the ORIGINATOR_ID.

        # Parse originator ID attribute (IPv4 only)
        elif atype == BGP_PATH_ATTR_ORIGINATOR_ID:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID >= 0:
                orig_bgp_id = attr_bytes[cur_offset:end_offset]
                if FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID_HUMAN:
                    route_record[FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID] = socket_inet_ntop(AF_INET, orig_bgp_id)
                else:
                    route_record[FTL_ATTR_BGP_ROUTE_ORIGINATOR_ID] = struct_unpack(STRUCT_4B, orig_bgp_id)[0]

        ##########################
        # CLUSTER_LIST ATTRIBUTE #
        ##########################

        # --------------------------
        # [RFC4456] 7. Redundant RRs
        # --------------------------
        # Usually, a cluster of clients will have a single RR. In that case,
        # the cluster will be identified by the BGP Identifier of the RR.
        # However, this represents a single point of failure so to make it
        # possible to have multiple RRs in the same cluster, all RRs in the
        # same cluster can be configured with a 4-byte CLUSTER_ID so that an RR
        # can discard routes from other RRs in the same cluster.

        # -----------------------------------------------
        # [RFC4456] 8. Avoiding Routing Information Loops
        # -----------------------------------------------
        # CLUSTER_LIST is a new, optional, non-transitive BGP attribute of Type
        # code 10. It is a sequence of CLUSTER_ID values representing the
        # reflection path that the route has passed.

        # Parse cluster list attribute (IPv4 only)
        elif atype == BGP_PATH_ATTR_CLUSTER_LIST:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_CLUSTER_LIST >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_CLUSTER_LIST] = tuple(
                    socket_inet_ntop(AF_INET, attr_bytes[c_offset:c_offset + 4])
                    if FTL_ATTR_BGP_ROUTE_CLUSTER_LIST_HUMAN
                    else struct_unpack(STRUCT_4B, attr_bytes[c_offset:c_offset + 4])[0]
                    for c_offset in range(cur_offset, end_offset, 4))

        ########################
        # LOCAL_PREF ATTRIBUTE #
        ########################

        # ------------------------------------------------------------------
        # [RFC4271] 4.3. UPDATE Message Format - e) LOCAL_PREF (Type Code 5)
        # ------------------------------------------------------------------
        # LOCAL_PREF is a well-known attribute that is a four-octet
        # unsigned integer.  A BGP speaker uses it to inform its other
        # internal peers of the advertising speaker's degree of
        # preference for an advertised route.

        # Parse local-pref attribute
        elif atype == BGP_PATH_ATTR_LOCAL_PREF:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_LOCAL_PREF >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_LOCAL_PREF] = struct_unpack(STRUCT_4B,
                                                                            attr_bytes[cur_offset:end_offset])[0]

        ##########################
        # AS_PATHLIMIT ATTRIBUTE #
        ##########################

        # -----------------------------------------------------------
        # [DRAFT-IETF-IDR-AS-PATHLIMIT] 5. The AS_PATHLIMIT Attribute
        # -----------------------------------------------------------
        # The AS_PATHLIMIT attribute is a transitive optional BGP path
        # attribute, with Type Code 21. The AS_PATHLIMIT attribute has a fixed
        # length of 5 octets. The first octet is an unsigned number that is
        # the upper bound on the number of ASes in the AS_PATH attribute of the
        # associated paths. One octet suffices because the TTL field of the IP
        # header ensures that only one octet's worth of ASes can ever be
        # traversed. The second thru fifth octets are the AS number of the AS
        # that attached the AS_PATHLIMIT attribute to the NLRI.

        # Parse AS path limit attribute
        elif atype == BGP_PATH_ATTR_AS_PATHLIMIT:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_AS_PATHLIMIT >= 0:
                pathlimit = attr_bytes[cur_offset]
                pathlimit_origin = struct_unpack(STRUCT_4B, attr_bytes[cur_offset + 1:cur_offset + 5])[0]
                route_record[FTL_ATTR_BGP_ROUTE_AS_PATHLIMIT] = (pathlimit_origin, pathlimit)

        ######################
        # ATTR_SET ATTRIBUTE #
        ######################

        # ------------------------------------------
        # [RFC6368] 5. BGP Customer Route Attributes
        # ------------------------------------------
        # ATTR_SET is an optional transitive attribute that carries a set of
        # BGP path attributes. An attribute set (ATTR_SET) can include any
        # BGP attribute that can occur in a BGP UPDATE message, except for
        # the MP_REACH and MP_UNREACH attributes.
        #
        # The ATTR_SET attribute is encoded as follows:
        #
        # +------------------------------+
        # | Attr Flags (O|T) Code = 128  |
        # +------------------------------+
        # | Attr. Length (1 or 2 octets) |
        # +------------------------------+
        # | Origin AS (4 octets)         |
        # +------------------------------+
        # | Path Attributes (variable)   |
        # +------------------------------+
        #
        # The Attribute Flags are encoded according to RFC 4271 [RFC4271]. The
        # Extended Length bit determines whether the Attribute Length is one or
        # two octets.

        # Parse attribute-set attribute
        elif atype == BGP_PATH_ATTR_ATTR_SET:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_ATTR_SET >= 0:
                route_record_attrset = list(route_init)
                attrset_origin = struct_unpack(STRUCT_4B, attr_bytes[cur_offset:cur_offset + 4])[0]
                unpack_mrt_bgp_attr(caches, stats_record, route_init, route_emit, route_record_attrset,
                                    attr_bytes[cur_offset + 4:end_offset], aslen=aslen)
                route_record[FTL_ATTR_BGP_ROUTE_ATTR_SET] = (attrset_origin, route_emit(route_record_attrset))

        ##################
        # AIGP ATTRIBUTE #
        ##################

        # ---------------------------
        # [RFC7311] 3. AIGP Attribute
        # ---------------------------
        # The AIGP attribute is an optional, non-transitive BGP path attribute.
        # The attribute type code for the AIGP attribute is 26.
        #
        # The value field of the AIGP attribute is defined here to be a set of
        # elements encoded as "Type/Length/Value" (i.e., a set of TLVs). Each
        # such TLV is encoded as shown in Figure 1.
        #
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #  |     Type      |         Length                |               |
        #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
        #  ~                                                               ~
        #  |                           Value                               |
        #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+..........................
        #
        #                         Figure 1: AIGP TLV
        #
        # -  Type: A single octet encoding the TLV Type. Only type 1, "AIGP
        #    TLV", is defined in this document. Use of other TLV types is
        #    outside the scope of this document.
        #
        # -  Length: Two octets encoding the length in octets of the TLV,
        #    including the Type and Length fields. The length is encoded as an
        #    unsigned binary integer. (Note that the minimum length is 3,
        #    indicating that no Value field is present.)
        #
        # -  Value: A field containing zero or more octets.
        #
        # This document defines only a single such TLV, the "AIGP TLV". The
        # AIGP TLV is encoded as follows:
        #
        # -  Type: 1
        #
        # -  Length: 11
        #
        # -  Value: Accumulated IGP Metric.
        #
        #    The value field of the AIGP TLV is always 8 octets long, and its
        #    value is interpreted as an unsigned 64-bit integer. IGP metrics
        #    are frequently expressed as 4-octet values. By using an 8-octet
        #    field, we ensure that the AIGP attribute can be used to hold the
        #    sum of an arbitrary number of 4-octet values.

        # Parse aigp attribute
        elif atype == BGP_PATH_ATTR_AIGP:  # pylint: disable=confusing-consecutive-elif
            if FTL_ATTR_BGP_ROUTE_AIGP >= 0:
                route_record[FTL_ATTR_BGP_ROUTE_AIGP] = tuple(
                    (attr_bytes[c_offset], struct_unpack(STRUCT_8B, attr_bytes[c_offset + 3: c_offset + 11])[0])
                    for c_offset in range(cur_offset, end_offset, 11))

        # Parse unsupported attributes
        elif FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN >= 0:  # pylint: disable=confusing-consecutive-elif
            aflags, adata = bin(flags) if FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN_HUMAN else flags, None
            if cur_offset < end_offset:
                adata = attr_bytes[cur_offset:end_offset]
                if FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN_HUMAN:
                    adata = ' '.join('{:02x}'.format(byte) for byte in adata)
                else:
                    adata = base64.b64encode(adata).decode('ascii')
            if route_record[FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN] is None:
                route_record[FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN] = tuple([(aflags, atype, adata)])
            else:
                route_record[FTL_ATTR_BGP_ROUTE_ATTRS_UNKNOWN] += tuple([(aflags, atype, adata)])

    #############################
    # ATTRIBUTE POST-PROCESSING #
    #############################

    # --------------------------------------------
    # [RFC6793] 4.2.3. Processing Received Updates
    # --------------------------------------------
    # A NEW BGP speaker MUST also be prepared to receive the AS4_AGGREGATOR
    # attribute along with the AGGREGATOR attribute from an OLD BGP
    # speaker. When both of the attributes are received, if the AS number
    # in the AGGREGATOR attribute is not AS_TRANS, then:
    #
    #    -  the AS4_AGGREGATOR attribute and the AS4_PATH attribute SHALL
    #       be ignored,
    #
    #    -  the AGGREGATOR attribute SHALL be taken as the information
    #       about the aggregating node, and
    #
    #    -  the AS_PATH attribute SHALL be taken as the AS path
    #       information.
    #
    # Otherwise,
    #
    #    -  the AGGREGATOR attribute SHALL be ignored,
    #
    #    -  the AS4_AGGREGATOR attribute SHALL be taken as the information
    #       about the aggregating node, and
    #
    #    -  the AS path information would need to be constructed, as in all
    #       other cases.

    # Merge AS/AS4 aggregator attributes
    if aggr_as is not None and aggr4_as is not None:
        if aggr_as != BGP_PATH_ATTR_AS4_PATH_AS_TRANS:
            aggr4_as, aggr4_ip, as4path = None, None, None
        else:
            aggr_as, aggr_ip = aggr4_as, aggr4_ip

    # Add final aggregator attributes
    if FTL_ATTR_BGP_ROUTE_AGGREGATOR_AS >= 0 and aggr_as is not None:
        route_record[FTL_ATTR_BGP_ROUTE_AGGREGATOR_AS] = aggr_as
    if aggr_ip is not None:
        if FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL >= 0:
            aggr_proto = IPV4_STR if FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL_HUMAN else IPV4
            route_record[FTL_ATTR_BGP_ROUTE_AGGREGATOR_PROTOCOL] = aggr_proto
        if FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP >= 0:
            if FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP_HUMAN:
                route_record[FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP] = socket_inet_ntop(AF_INET, aggr_ip)
            else:
                route_record[FTL_ATTR_BGP_ROUTE_AGGREGATOR_IP] = struct_unpack(STRUCT_4B, aggr_ip)[0]

    # --------------------------------------------
    # [RFC6793] 4.2.3. Processing Received Updates
    # --------------------------------------------
    # In order to construct the AS path information, it is necessary to
    # first calculate the number of AS numbers in the AS_PATH and AS4_PATH
    # attributes using the method specified in Section 9.1.2.2 of [RFC4271]
    # and in [RFC5065] for route selection.
    #
    # If the number of AS numbers in the AS_PATH attribute is less than the
    # number of AS numbers in the AS4_PATH attribute, then the AS4_PATH
    # attribute SHALL be ignored, and the AS_PATH attribute SHALL be taken
    # as the AS path information.
    #
    # If the number of AS numbers in the AS_PATH attribute is larger than
    # or equal to the number of AS numbers in the AS4_PATH attribute, then
    # the AS path information SHALL be constructed by taking as many AS
    # numbers and path segments as necessary from the leading part of the
    # AS_PATH attribute, and then prepending them to the AS4_PATH attribute
    # so that the AS path information has a number of AS numbers identical
    # to that of the AS_PATH attribute.
    #
    # NOTE: The following procedure is not implemented (would need a lot of state)
    #
    # Note that a valid AS_CONFED_SEQUENCE or AS_CONFED_SET path segment
    # SHALL be prepended if it is either the leading path segment or is
    # adjacent to a path segment that is prepended.

    # Merge AS/AS4 path attributes
    if FTL_ATTR_BGP_ROUTE_ASPATH >= 0:
        if aspath is not None:
            if as4path is not None:
                len_aspath, len_as4path = len(aspath), len(as4path)
                if len_aspath >= len_as4path:
                    aspath = aspath[:len_aspath - len_as4path] + as4path
            aspath = tuple(aspath)  # pylint: disable=redefined-variable-type

        # Add final AS path attribute
        # NOTE: RIB entries and announcements may include empty tuples, but should not include None (only for withdraws)
        # NOTE: -> this is NOT guaranteed, though (depends on correct usage of BGP attributes)
        route_record[FTL_ATTR_BGP_ROUTE_ASPATH] = aspath

    # Return announced/withdrawn prefixes
    return nlri, nlui
