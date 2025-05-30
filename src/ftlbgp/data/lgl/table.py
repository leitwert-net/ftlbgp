# -*- coding: utf-8 -*-
# pylint: disable=I0011,I0020,I0021,I0023
# pylint: disable=W0149,W0717,R0902,R0904,R0911,R0912,R0913,R0914,R0915,R1702,R1734,R1735,R2044,R6103,C0103,C0209,C2001
# pylint: enable=I0011
""" ftlbgp
Copyright (C) 2014-2025 Leitwert GmbH

This software is distributed under the terms of the MIT license.
It can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Author Johann SCHLAMP <schlamp@leitwert.net>
"""

# System imports
import re

# Routing table formats
TABLE_REGEX_STD = re.compile(r'^(\s+)(Network\s+)(Next Hop\s*)(\sMetric)(\s+LocPrf)(\s+Weight)(\s+)Path\s*$')
TABLE_REGEX_ALT = re.compile(r'^(\s+P)(\s+Pref)(\s+)(Time\s+)(Destination\s+)(Next Hop\s+)(If\s+)Path\s*$')


def check_lgl_table(header):
    """ Match looking glass header line against supported table formats.
    """
    # Check for standard table header (PCH)
    match = TABLE_REGEX_STD.match(header)
    if match is not None:
        return unpack_lgl_entry_std(*(len(g) for g in match.groups()))

    # Check for alternative table header (early RIPE RIS)
    match = TABLE_REGEX_ALT.match(header)
    if match is not None:
        return unpack_lgl_entry_alt(*(len(g) for g in match.groups()))

    # Table header not supported
    return None


def unpack_lgl_entry_std(status_skip, prefix_len, nexthop_len, med_len, locpref_len, weight_len, path_skip):
    """ Parse looking glass entry in standard table format (PCH).
    """
    # ------------------------
    # [PCH] % sh bgp ipv4 wide
    # ------------------------
    #    Network          Next Hop            Metric LocPrf Weight Path
    # *  1.0.0.0/24       206.126.236.19           0             0 3257 13335 i
    # *>                  206.126.237.30           0             0 13335 i
    # *> 1.0.16.0/24      206.126.236.23           0             0 2497 2519 i

    # Prepare table indexes
    prefix_start = status_skip
    prefix_end = prefix_start + prefix_len
    nexthop_start = prefix_end
    nexthop_end = nexthop_start + nexthop_len
    med_start = nexthop_end
    med_end = med_start + med_len
    locpref_start = med_end
    locpref_end = locpref_start + locpref_len
    aspath_start = locpref_end + weight_len + path_skip
    entry_len_min = aspath_start

    def unpack_lgl_entry(entry):
        """ Collector-specific entry parser.
        """
        # Check entry
        if len(entry) <= entry_len_min:
            return None

        # Parse prefix
        prefix = entry[prefix_start:prefix_end].rstrip()
        if len(prefix) == prefix_end - prefix_start:
            prefix, entry = entry[prefix_start:].split(None, 1)
            entry = '_' * prefix_end + entry.lstrip()
            if len(entry) <= entry_len_min:
                return None

        # Parse nexthop
        nexthop = entry[nexthop_start:nexthop_end].rstrip()
        if len(nexthop) == nexthop_end - nexthop_start:
            nexthop, entry = entry[nexthop_start:].split(None, 1)
            med, _ = entry.split(None, 1)
            entry = '.' * nexthop_end + ' ' * (med_len - len(med)) + entry
            # NOTE: If there is no MED metric, we are unable to parse 3-line entries
            if len(entry) <= entry_len_min:
                return None

        # Parse MED metric and local preference
        med = entry[med_start:med_end].strip()
        locpref = entry[locpref_start:locpref_end].lstrip()

        # Parse AS path
        aspath, origin = '', entry[aspath_start:].rstrip()
        if len(origin) > 1:
            aspath, origin = origin.rsplit(None, 1)

        # Return parsed entry
        return prefix, nexthop, med, locpref, aspath, origin

    # Return unpack function
    return unpack_lgl_entry


def unpack_lgl_entry_alt(status_skip, locpref_len, time_skip, time_len, prefix_len, nexthop_len, iface_len):
    """ Parse looking glass entry in alternative table format (early RIPE RIS).
    """
    # -------------------------
    # [RIPE] % sh bgp ipv4 wide
    # -------------------------
    #   P Pref Time     Destination                Next Hop                 If      Path
    # > B    0 11:53:59 3.0.0.0/8                  193.0.0.56               eth0    3333 286 701 80 i
    # * B    0 11:53:46 3.0.0.0/8                  193.0.0.59               eth0    3333 286 701 80 i

    # Prepare table indexes
    locpref_start = status_skip
    locpref_end = locpref_start + locpref_len
    prefix_start = locpref_end + time_skip + time_len
    prefix_end = prefix_start + prefix_len
    nexthop_start = prefix_end
    nexthop_end = nexthop_start + nexthop_len
    aspath_start = nexthop_end + iface_len
    entry_len_min = aspath_start

    def unpack_lgl_entry(entry):
        """ Collector-specific entry parser.
        """
        # Check entry
        if len(entry) <= entry_len_min:
            return None

        # Parse local preference
        locpref = entry[locpref_start:locpref_end].lstrip()

        # Parse prefix
        prefix = entry[prefix_start:prefix_end].rstrip()
        if len(prefix) == prefix_end - prefix_start:
            prefix, entry = entry[prefix_start:].split(None, 1)
            entry = '_' * prefix_end + entry.lstrip()
            if len(entry) <= entry_len_min:
                return None

        # Parse nexthop
        nexthop = entry[nexthop_start:nexthop_end].rstrip()
        if len(nexthop) == nexthop_end - nexthop_start:
            nexthop, entry = entry[nexthop_start:].split(None, 1)
            entry = '.' * nexthop_end + entry.lstrip()

        # Parse AS path
        aspath, origin = '', entry[aspath_start:].rstrip()
        if len(origin) > 1:
            aspath, origin = origin.rsplit(None, 1)

        # Return parsed entry
        return prefix, nexthop, '', locpref, aspath, origin

    # Return unpack function
    return unpack_lgl_entry
