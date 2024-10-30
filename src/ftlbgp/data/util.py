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
import json

# Local imports
from ..model.attr import FTL_ATTR_BGP_STATS_MRT_ERRORS
from ..model.attr import FTL_ATTR_BGP_STATS_LGL_ERRORS
from ..model.attr import FTL_ATTR_BGP_STATS_PARSER_ERRORS
from ..model.attr import FTL_ATTR_BGP_ERROR_RECORD
from ..model.attr import FTL_ATTR_BGP_ERROR_SOURCE
from ..model.attr import FTL_ATTR_BGP_ERROR_SCOPE
from ..model.attr import FTL_ATTR_BGP_ERROR_REASON
from ..model.attr import FTL_ATTR_BGP_ERROR_MESSAGE
from ..model.attr import FTL_ATTR_BGP_ERROR_DATA
from ..model.attr import FTL_ATTR_BGP_ERROR_TRACE
from ..model.attr import FTL_ATTR_BGP_ERROR_SOURCE_HUMAN
from ..model.attr import FTL_ATTR_BGP_ERROR_SCOPE_HUMAN
from ..model.attr import FTL_ATTR_BGP_ERROR_REASON_HUMAN
from ..model.attr import FTL_ATTR_BGP_ERROR_DATA_HUMAN
from ..model.const import FTL_ATTR_BGP_ERROR_SOURCE_MRT
from ..model.const import FTL_ATTR_BGP_ERROR_SOURCE_LGL
from ..model.const import FTL_ATTR_BGP_ERROR_SOURCE_PARSER
from ..model.const import FTL_ATTR_BGP_ERROR_SOURCE_TO_STR
from ..model.const import FTL_ATTR_BGP_ERROR_SCOPE_TO_STR
from ..model.const import FTL_ATTR_BGP_ERROR_REASON_TO_STR
from ..model.record import FTL_RECORD_BGP_STATS
from ..model.record import FTL_RECORD_BGP_ERROR

# Cache keys
CACHE_TS = 0


def init_caches():
    """ Initialize data caches.
    """
    # Return data caches
    # NOTE: We currently support timestamp caches only
    return (dict(), )


def handle_bgp_error(raise_on_errors, error_init, error_emit, error_type, stats_emit, stats_record, error):
    """ Yield BGP error record or re-raise given exception.
    """
    # Extract error source
    error_source = error.source
    if FTL_ATTR_BGP_ERROR_SOURCE_HUMAN:
        error_source = FTL_ATTR_BGP_ERROR_SOURCE_TO_STR.get(error_source, str(error_source))

    # Extract error scope
    error_scope = error.scope
    if FTL_ATTR_BGP_ERROR_SCOPE_HUMAN:
        error_scope = FTL_ATTR_BGP_ERROR_SCOPE_TO_STR.get(error_scope, str(error_scope))

    # Extract error reason
    error_reason = error.reason
    if FTL_ATTR_BGP_ERROR_REASON_HUMAN:
        error_reason = FTL_ATTR_BGP_ERROR_REASON_TO_STR.get(error_reason, str(error_reason))

    # Update stats record
    if FTL_RECORD_BGP_STATS:

        # Identify error source
        source_errors = None
        if error.source == FTL_ATTR_BGP_ERROR_SOURCE_MRT:
            source_errors = FTL_ATTR_BGP_STATS_MRT_ERRORS
        elif error.source == FTL_ATTR_BGP_ERROR_SOURCE_LGL:
            source_errors = FTL_ATTR_BGP_STATS_LGL_ERRORS
        elif error.source == FTL_ATTR_BGP_ERROR_SOURCE_PARSER:
            source_errors = FTL_ATTR_BGP_STATS_PARSER_ERRORS

        # Add error scope/record/reason
        if source_errors:
            error_str = '|'.join((str(err) for err in (error_scope, error_reason, error_type)))
            stats_record[source_errors][error_str] = stats_record[source_errors].get(error_str, 0) + 1

        # Yield final stats record (if exception will be raised)
        if raise_on_errors:
            yield stats_emit(stats_record)

    # Yield error record if requested
    if FTL_RECORD_BGP_ERROR:

        # Initialize error record
        error_record = list(error_init)

        # Add error source to record
        if FTL_ATTR_BGP_ERROR_SOURCE >= 0:
            error_record[FTL_ATTR_BGP_ERROR_SOURCE] = error_source

        # Add error scope to record
        if FTL_ATTR_BGP_ERROR_SCOPE >= 0:
            error_record[FTL_ATTR_BGP_ERROR_SCOPE] = error_scope

        # Add error record type to record
        if FTL_ATTR_BGP_ERROR_RECORD >= 0:
            error_record[FTL_ATTR_BGP_ERROR_RECORD] = error_type

        # Add error reason to record
        if FTL_ATTR_BGP_ERROR_REASON >= 0:
            error_record[FTL_ATTR_BGP_ERROR_REASON] = error_reason

        # Add error message to record
        if FTL_ATTR_BGP_ERROR_MESSAGE >= 0:
            error_record[FTL_ATTR_BGP_ERROR_MESSAGE] = error.message

        # Add error data to record
        if FTL_ATTR_BGP_ERROR_DATA >= 0:
            data = error.data
            if data is not None:
                if isinstance(data, (bytes, bytearray, memoryview)) is True:
                    if FTL_ATTR_BGP_ERROR_DATA_HUMAN:
                        data = ' '.join('{:02x}'.format(byte) for byte in data)
                    else:
                        data = base64.b64encode(data).decode('ascii')
                elif FTL_ATTR_BGP_ERROR_DATA_HUMAN:
                    data = json.dumps(data)
            error_record[FTL_ATTR_BGP_ERROR_DATA] = data

        # Add error trace to record
        if FTL_ATTR_BGP_ERROR_TRACE >= 0:
            error_record[FTL_ATTR_BGP_ERROR_TRACE] = error.trace

        # Yield final error record
        yield error_emit(error_record)

    # Re-raise exception if requested
    if raise_on_errors:

        # Clone and raise error
        raise type(error)(record=error_type, error=error)
