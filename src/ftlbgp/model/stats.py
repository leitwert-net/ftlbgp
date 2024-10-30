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
from collections import namedtuple

# Local imports
from .attr import FtlAttrsBgp
from .util import FTL_ATTR_SHIFT_HUMAN


def filter_stats_spec(no_support):
    """ Remove unsupported stats fields from attributes spec.
    """
    # Update supported stats attributes
    stats, stats_fields, stats_human = FtlAttrsBgp.stats, dict(), None
    update_fields, unsupported_fields = list(), 0
    for attr_name, attr_value in stats._asdict().items():
        if attr_value != stats.human:
            if attr_value in {stats.ALL, stats.NONE, stats.DEFAULT}:
                update_fields.append(attr_name)
                stats_fields[attr_name] = attr_value
            elif attr_name in stats.internal or any(attr_name.startswith(skip) for skip in no_support) is False:
                stats_fields[attr_name] = attr_value
            else:
                unsupported_fields |= attr_value
        else:
            stats_fields[attr_name] = attr_value
            stats_human = attr_name

    # Update supported stats attributes (human-readable)
    stats_fields_human = {field: value << FTL_ATTR_SHIFT_HUMAN for field, value in stats_fields.items()
                          if field not in stats.internal or field in update_fields}
    for field in update_fields:
        stats_fields[field] &= ~unsupported_fields
        stats_fields_human[field] = stats_fields[field] << FTL_ATTR_SHIFT_HUMAN
    stats_fields[stats_human] = namedtuple(stats.human.__class__.__name__,
                                           stats_fields_human.keys())(*stats_fields_human.values())

    # Clone and return filtered attributes spec
    attrs = FtlAttrsBgp._asdict()
    attrs[stats.name] = namedtuple(stats.__class__.__name__, stats_fields.keys())(*stats_fields.values())
    return namedtuple(FtlAttrsBgp.__class__.__name__, attrs.keys())(*attrs.values())


def init_stats_record(attributes, attrindexes, spec_attributes, stats_record):
    """ Initialize default values for stats record.
    """
    # Initialize parser stats values
    try:
        if spec_attributes & (attributes.parser_lifetime | attributes.human.parser_lifetime):
            stats_record[attrindexes.parser_lifetime] = 0.0
        if spec_attributes & (attributes.parser_runtime | attributes.human.parser_runtime):
            stats_record[attrindexes.parser_runtime] = 0.0
        if spec_attributes & (attributes.parser_errors | attributes.human.parser_errors):
            stats_record[attrindexes.parser_errors] = dict()
    except AttributeError:
        pass

    # Initialize looking-glass stats values
    try:
        if spec_attributes & (attributes.lgl_runtime | attributes.human.lgl_runtime):
            stats_record[attrindexes.lgl_runtime] = 0.0
        if spec_attributes & (attributes.lgl_entries | attributes.human.lgl_entries):
            stats_record[attrindexes.lgl_entries] = 0
        if spec_attributes & (attributes.lgl_errors | attributes.human.lgl_errors):
            stats_record[attrindexes.lgl_errors] = dict()
    except AttributeError:
        pass

    # Initialize MRT stats values
    try:
        if spec_attributes & (attributes.mrt_runtime | attributes.human.mrt_runtime):
            stats_record[attrindexes.mrt_runtime] = 0.0
        if spec_attributes & (attributes.mrt_entries | attributes.human.mrt_entries):
            stats_record[attrindexes.mrt_entries] = 0
        if spec_attributes & (attributes.mrt_errors | attributes.human.mrt_errors):
            stats_record[attrindexes.mrt_errors] = dict()
        if spec_attributes & (attributes.mrt_fixes | attributes.human.mrt_fixes):
            stats_record[attrindexes.mrt_fixes] = dict()
        if spec_attributes & (attributes.mrt_bgp_entry_types | attributes.human.mrt_bgp_entry_types):
            stats_record[attrindexes.mrt_bgp_entry_types] = dict()
        if spec_attributes & (attributes.mrt_bgp_message_types | attributes.human.mrt_bgp_message_types):
            stats_record[attrindexes.mrt_bgp_message_types] = dict()
        if spec_attributes & (attributes.mrt_bgp_attribute_types | attributes.human.mrt_bgp_attribute_types):
            stats_record[attrindexes.mrt_bgp_attribute_types] = dict()
        if spec_attributes & (attributes.mrt_bgp_capability_types | attributes.human.mrt_bgp_capability_types):
            stats_record[attrindexes.mrt_bgp_capability_types] = dict()
    except AttributeError:
        pass

    # Initialize BGP stats values
    try:
        if spec_attributes & (attributes.bgp_routes_rib_ipv4 | attributes.human.bgp_routes_rib_ipv4):
            stats_record[attrindexes.bgp_routes_rib_ipv4] = 0
        if spec_attributes & (attributes.bgp_routes_rib_ipv6 | attributes.human.bgp_routes_rib_ipv6):
            stats_record[attrindexes.bgp_routes_rib_ipv6] = 0
        if spec_attributes & (attributes.bgp_routes_announce_ipv6 | attributes.human.bgp_routes_announce_ipv6):
            stats_record[attrindexes.bgp_routes_announce_ipv6] = 0
        if spec_attributes & (attributes.bgp_routes_announce_ipv4 | attributes.human.bgp_routes_announce_ipv4):
            stats_record[attrindexes.bgp_routes_announce_ipv4] = 0
        if spec_attributes & (attributes.bgp_routes_withdraw_ipv4 | attributes.human.bgp_routes_withdraw_ipv4):
            stats_record[attrindexes.bgp_routes_withdraw_ipv4] = 0
        if spec_attributes & (attributes.bgp_routes_withdraw_ipv6 | attributes.human.bgp_routes_withdraw_ipv6):
            stats_record[attrindexes.bgp_routes_withdraw_ipv6] = 0
    except AttributeError:
        pass
