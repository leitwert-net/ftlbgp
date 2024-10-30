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
import sys
import traceback

# Local imports
from .const import FTL_ATTR_BGP_ERROR_SOURCE_MRT
from .const import FTL_ATTR_BGP_ERROR_SOURCE_LGL
from .const import FTL_ATTR_BGP_ERROR_SOURCE_PARSER
from .const import FTL_ATTR_BGP_ERROR_SCOPE_BASE
from .const import FTL_ATTR_BGP_ERROR_SCOPE_FILE
from .const import FTL_ATTR_BGP_ERROR_SCOPE_HEADER
from .const import FTL_ATTR_BGP_ERROR_SCOPE_FORMAT
from .const import FTL_ATTR_BGP_ERROR_SCOPE_DATA
from .const import FTL_ATTR_BGP_ERROR_REASON_RUNTIME


##################
# GENERIC ERRORS #
##################

class FtlError(Exception):
    """ Generic exception.
    """
    # Prepare internals
    source = FTL_ATTR_BGP_ERROR_SOURCE_PARSER
    scope = FTL_ATTR_BGP_ERROR_SCOPE_BASE

    def __init__(self, message=None, reason=FTL_ATTR_BGP_ERROR_REASON_RUNTIME, record=None, data=None, trace=None,
                 error=None, exception=None, **_):
        """ Initialize exception instance.
        """
        # Prepare error details
        self.message = message
        self.reason = reason
        self.record = record
        self.data = data
        self.trace = trace

        # Extract stack trace
        if trace is True:
            tbline = 'Traceback (most recent call last):'
            self.trace, (cls, exc, tb) = list(), sys.exc_info()
            for line in [tbline] + traceback.format_tb(tb) + traceback.format_exception_only(cls, exc):
                for err in line.rstrip().split('\n'):
                    errline, indent = err.lstrip(), len(err)
                    self.trace.append((errline, indent - len(errline)))

        # Update with parent error
        if error is not None:
            self.__cause__ = None
            self.__traceback__ = error.__traceback__
            if self.source == FTL_ATTR_BGP_ERROR_SOURCE_PARSER:
                self.source = error.source
            if self.reason == FTL_ATTR_BGP_ERROR_SCOPE_BASE:
                self.scope = error.scope
            if self.reason == FTL_ATTR_BGP_ERROR_REASON_RUNTIME:
                self.reason = error.reason
            if self.message is None:
                self.message = error.message
            if self.record is None:
                self.record = record
            if self.data is None:
                self.data = error.data
            if self.trace is None:
                self.trace = error.trace

        # Update with parent exception
        if exception is not None:
            self.__cause__ = None
            self.__traceback__ = exception.__traceback__
            excmsg = f'[{exception.__class__.__name__}] {str(exception)}'
            self.message = f'{self.message}: {excmsg}' if self.message is not None else excmsg

        # Invoke super constructor
        errmsg = f'ERR|{self.source}.{self.scope}.{self.reason}'
        errmsg = f'[{errmsg}]' if self.record is None else f'[{errmsg}-{self.record}]'.upper()
        if self.message is not None:
            errmsg = f'{errmsg} {self.message}'
        super().__init__(errmsg)


class FtlFileError(FtlError):
    """ Generic file exception.
    """
    # Update internals
    scope = FTL_ATTR_BGP_ERROR_SCOPE_FILE


class FtlFormatError(FtlError):
    """ Generic file format exception.
    """
    # Update internals
    scope = FTL_ATTR_BGP_ERROR_SCOPE_FORMAT


class FtlDataError(FtlError):
    """ Generic file data exception.
    """
    # Update internals
    scope = FTL_ATTR_BGP_ERROR_SCOPE_DATA


##############
# MRT ERRORS #
##############

class FtlMrtError(FtlError):
    """ Base MRT exception.
    """
    # Update internals
    source = FTL_ATTR_BGP_ERROR_SOURCE_MRT


class FtlMrtHeaderError(FtlMrtError):
    """ Exception for invalid MRT header.
    """
    # Update internals
    scope = FTL_ATTR_BGP_ERROR_SCOPE_HEADER


class FtlMrtFormatError(FtlMrtError, FtlFormatError):
    """ Exception for invalid MRT format.
    """


class FtlMrtDataError(FtlMrtError, FtlDataError):
    """ Exception for invalid MRT data.
    """


##############
# LGL ERRORS #
##############

class FtlLglError(FtlError):
    """ Base looking glass exception.
    """
    # Update internals
    source = FTL_ATTR_BGP_ERROR_SOURCE_LGL


class FtlLglHeaderError(FtlLglError):
    """ Exception for invalid looking glass header.
    """
    # Update internals
    scope = FTL_ATTR_BGP_ERROR_SCOPE_HEADER


class FtlLglFormatError(FtlLglError, FtlFormatError):
    """ Exception for invalid looking glass format.
    """


class FtlLglDataError(FtlLglError, FtlDataError):
    """ Exception for invalid looking glass data.
    """
