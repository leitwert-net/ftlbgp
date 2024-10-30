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

# System imports
import socket
import struct
from datetime import datetime

# IP protocols
IPV4 = 4
IPV6 = 6

# IP protocol strings
IPV4_STR = 'ipv4'
IPV6_STR = 'ipv6'

# Address families
AF_INET = int(socket.AF_INET)
AF_INET6 = int(socket.AF_INET6)

# AFI values
AFI_IPV4 = 1  # Defined by IANA
AFI_IPV6 = 2  # Defined by IANA

# Socket/struct functions
socket_inet_pton = socket.inet_pton
socket_inet_ntop = socket.inet_ntop
struct_unpack = struct.unpack
struct_pack = struct.pack

# Struct bytes
STRUCT_2B = '!H'
STRUCT_4B = '!I'
STRUCT_8B = '!Q'
STRUCT_2B2B = '!HH'
STRUCT_8B8B = '!QQ'
STRUCT_2B2B2B = '!HHH'
STRUCT_4B4B4B = '!III'

# Strings
UTF8 = 'utf-8'

# Datetime functions
datetime_utcfromtimestamp = datetime.utcfromtimestamp

# Datetime formats
DATETIME_FORMAT_USEC = '%Y-%m-%d %H:%M:%S.%f'
DATETIME_FORMAT_MIN = '%Y-%m-%d %H:%M'
