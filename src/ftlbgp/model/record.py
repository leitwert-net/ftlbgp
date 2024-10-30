# -*- coding: utf-8 -*-
# pylint: disable=I0011,I0020,I0021,I0023
# pylint: disable=W0149,W0717,R0902,R0904,R0911,R0912,R0913,R0914,R0915,R1702,R1734,R1735,R2044,R6103,C0103,C0209,C2001
# pylint: enable=I0011
# flake8: noqa
""" ftlbgp
Copyright (C) 2014-2024 Leitwert GmbH

This software is distributed under the terms of the MIT license.
It can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Author Johann SCHLAMP <schlamp@leitwert.net>
"""

# Local imports
from .util import generate_spec_record

# Available BGP records
FTL_RECORD_BGP_PEER_TABLE    = 1 << 0
FTL_RECORD_BGP_STATE_CHANGE  = 1 << 1
FTL_RECORD_BGP_ROUTE         = 1 << 2
FTL_RECORD_BGP_KEEP_ALIVE    = 1 << 3
FTL_RECORD_BGP_ROUTE_REFRESH = 1 << 4
FTL_RECORD_BGP_NOTIFICATION  = 1 << 5
FTL_RECORD_BGP_OPEN          = 1 << 6
FTL_RECORD_BGP_STATS         = 1 << 7
FTL_RECORD_BGP_ERROR         = 1 << 8

# Availabe BGP record names
FTL_RECORD_BGP_PEER_TABLE_NAME    = 'peer_table'
FTL_RECORD_BGP_STATE_CHANGE_NAME  = 'state_change'
FTL_RECORD_BGP_ROUTE_NAME         = 'route'
FTL_RECORD_BGP_KEEP_ALIVE_NAME    = 'keep_alive'
FTL_RECORD_BGP_ROUTE_REFRESH_NAME = 'route_refresh'
FTL_RECORD_BGP_NOTIFICATION_NAME  = 'notification'
FTL_RECORD_BGP_OPEN_NAME          = 'open'
FTL_RECORD_BGP_STATS_NAME         = 'stats'
FTL_RECORD_BGP_ERROR_NAME         = 'error'

# BGP record specification
# [Format] spec := (field, value, default)
FtlRecordsBgp = generate_spec_record('FtlRecordsBgp', (
    (FTL_RECORD_BGP_PEER_TABLE_NAME,    FTL_RECORD_BGP_PEER_TABLE,    False),
    (FTL_RECORD_BGP_STATE_CHANGE_NAME,  FTL_RECORD_BGP_STATE_CHANGE,  False),
    (FTL_RECORD_BGP_ROUTE_NAME,         FTL_RECORD_BGP_ROUTE,         True),
    (FTL_RECORD_BGP_KEEP_ALIVE_NAME,    FTL_RECORD_BGP_KEEP_ALIVE,    False),
    (FTL_RECORD_BGP_ROUTE_REFRESH_NAME, FTL_RECORD_BGP_ROUTE_REFRESH, False),
    (FTL_RECORD_BGP_NOTIFICATION_NAME,  FTL_RECORD_BGP_NOTIFICATION,  False),
    (FTL_RECORD_BGP_OPEN_NAME,          FTL_RECORD_BGP_OPEN,          False),
    (FTL_RECORD_BGP_STATS_NAME,         FTL_RECORD_BGP_STATS,         True),
    (FTL_RECORD_BGP_ERROR_NAME,         FTL_RECORD_BGP_ERROR,         True),
), human=False)
