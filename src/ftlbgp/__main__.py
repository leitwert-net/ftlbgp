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
import argparse
import sys

# Local imports
from . import __version__
from . import BgpParser
from . import FtlError
from . import FtlDataError


def main():
    """ Main routine.
    """
    # Prepare command line arguments
    description = f'ftlbgp [v{__version__}] - Parse BGP data in MRT or looking glass format'
    parser = argparse.ArgumentParser(prog='ftlbgp', description=description)
    argparse._VersionAction.__call__ = lambda *_: (help(BgpParser), parser.exit())  # pylint: disable=protected-access
    parser.add_argument('filelist', metavar='<FILE>', nargs='+', help='input file with BGP data (supports bz2/gz)')
    parser.add_argument('--pkg-help', action='version', help='show package help for BgpParser usage')
    parser.add_argument('--json', default=False, action='store_true', help='output BGP records in JSON format')
    parser.format_help = lambda: argparse.ArgumentParser.format_help(parser) + '\n'
    parser._get_formatter = lambda: parser.formatter_class(prog='python3 -m ftlbgp')  # pylint: disable=protected-access
    args = parser.parse_args()

    # Initialize BGP parser
    with BgpParser(named_records=args.json, serialize=True, raise_on_errors=False,
                   bgp_records=BgpParser.bgp.records.route,
                   bgp_route=(
                       BgpParser.bgp.route.human.DEFAULT
                       & ~BgpParser.bgp.route.human.type
                       & ~BgpParser.bgp.route.human.peer_bgp_id
                   )) as parse:

        # Parse input files
        for filename in args.filelist:
            try:
                # Iterate and print records
                for record in parse(filename):
                    print(record)

            # Ignore non-critical data errors
            except FtlDataError:
                continue

            # Abort on unknown errors
            except FtlError as error:
                print(str(error))
                sys.exit(1)

            # Handle command line induced errors
            except (BrokenPipeError, KeyboardInterrupt):
                return


# Main routine
if __name__ == '__main__':
    main()
