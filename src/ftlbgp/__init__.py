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

__author__ = 'Johann SCHLAMP'
__copyright__ = 'Copyright (C) 2014-2024 Leitwert GmbH'
__license__ = 'MIT license'

__all__ = [
    'MrtParser',
    'LglParser',
    'BgpParser',
    'FtlError',
    'FtlFileError',
    'FtlFormatError',
    'FtlDataError'
]

# Local imports
from .version import __version__
from .parser import FtlParser
from .model.error import FtlError
from .model.error import FtlFileError
from .model.error import FtlFormatError
from .model.error import FtlDataError
from .data.mrt.unpack import unpack_mrt_data
from .data.lgl.unpack import unpack_lgl_data


@FtlParser(unpack_mrt_data)
def MrtParser():
    """ Parse BGP data in MRT format.
    """


@FtlParser(unpack_lgl_data)
def LglParser():
    """ Parse BGP data in looking glass format.
    """


@FtlParser(unpack_mrt_data, unpack_lgl_data)
def BgpParser():
    """ Parse BGP data in MRT or looking glass format.
    """
