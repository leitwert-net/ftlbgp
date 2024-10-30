# ftlbgp

A Python parser for BGP data in MRT or looking glass format.

### Key features

- Support for all MRT entry types, BGP messages, and BGP attributes
- Customizable record and attribute types (no parsing of unneeded data)
- Programmatic data access with optional CSV and JSON serialization
- Raw values and human-readable output (e.g. integers vs. strings)
- Rapid prototyping (namedtuple) and high-performance mode (tuple)
- Context manager with built-in statistics and flexible error handling
- Zero-copy operations on all data items (as fast as it gets in Python)

## Compatibility

This package is compatible with `python3.6` and `pypy3.6-v7.0.0` or greater.

## Installation

Run `pip install ftlbgp` or

```
~$ git clone https://github.com/leitwert-net/ftlbgp.git`
~$ cd ftlbgp.git/src
```

to download and run the source code manually.

## Usage

### Parsing MRT files

```
~$ python3 -m ftlbgp -h
usage: python3 -m ftlbgp [-h] [--pkg-help] [--json] <FILE> [<FILE> ...]

ftlbgp [v1.0.3] - Parse BGP archives in MRT or looking glass format

positional arguments:
  <FILE>      input file with BGP data (supports bz2/gz)

optional arguments:
  -h, --help  show this help message and exit
  --pkg-help  show package help for BgpParser usage
  --json      output BGP records in JSON format

```

### Programmatic use

```python
# Import parser
from ftlbgp import BgpParser

# Prepare input file
filename = ...

# Parse default records and attributes
with BgpParser() as parse:
    for record in parse(filename):
        print(record)
```

## Customization

```python
# Parse all records
with BgpParser(bgp_records=BgpParser.bgp.records.ALL) as parse:
    for record in parse(filename):
        print(record)

# Parse specific records (route and error)
with BgpParser(bgp_records=BgpParser.bgp.records.route | BgpParser.bgp.records.error) as parse:
    for record in parse(filename):
        print(record)

# Parse all route attributes
with BgpParser(bgp_route=BgpParser.bgp.route.ALL) as parse:
    for record in parse(filename):
        print(record)

# Parse specific route attributes (default and local_pref)
with BgpParser(bgp_route=BgpParser.bgp.route.DEFAULT | BgpParser.bgp.route.local_pref) as parse:
    for record in parse(filename):
        print(record)
```

## Full specification

```
BgpParser()
      
This @FtlParser instance is used to read input files and generate a set of BGP records (Python tuples).
It must be used with a context manager (see sample usage below) and accepts the following arguments.

Keyword arguments:
  named_records     - Return named tuples instead of plain unnamed tuple records. [Default: True]
  serialize         - Convert output records to JSON (if named) or CSV (if unnamed). [Default: False]
  use_cache         - Cache expensive low-entropy values (memory consumption < 1MB). [Default: True]
  raise_on_errors   - Raise exceptions and stop parsing in case of data errors. [Default: False]
  bgp_records       - Select the types of BgpRecord entries to be returned by the parser.
                      Supports bitwise logical operators OR, AND, NOT to specify multiple records.
                      [Default:
                        BgpParser.bgp.records.route |
                        BgpParser.bgp.records.stats |
                        BgpParser.bgp.records.error
                       Available:
                        BgpParser.bgp.records.peer_table
                        BgpParser.bgp.records.state_change
                        BgpParser.bgp.records.keep_alive
                        BgpParser.bgp.records.route_refresh
                        BgpParser.bgp.records.notification
                        BgpParser.bgp.records.open
                        BgpParser.bgp.records.ALL
                        BgpParser.bgp.records.NONE
                        BgpParser.bgp.records.DEFAULT]
  bgp_peer_table    - Select [optionally human-readable] attribute to be included in BgpPeerTableRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.peer_table[.human].type |
                        BgpParser.bgp.peer_table[.human].peer_protocol |
                        BgpParser.bgp.peer_table[.human].peer_bgp_id |
                        BgpParser.bgp.peer_table[.human].peer_as |
                        BgpParser.bgp.peer_table[.human].peer_ip
                       Available:
                        BgpParser.bgp.peer_table[.human].collector_bgp_id
                        BgpParser.bgp.peer_table[.human].view_name
                        BgpParser.bgp.peer_table[.human].ALL
                        BgpParser.bgp.peer_table[.human].NONE
                        BgpParser.bgp.peer_table[.human].DEFAULT]
  bgp_state_change  - Select [optionally human-readable] attribute to be included in BgpStateChangeRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.state_change[.human].type |
                        BgpParser.bgp.state_change[.human].timestamp |
                        BgpParser.bgp.state_change[.human].peer_protocol |
                        BgpParser.bgp.state_change[.human].peer_as |
                        BgpParser.bgp.state_change[.human].peer_ip |
                        BgpParser.bgp.state_change[.human].old_state |
                        BgpParser.bgp.state_change[.human].new_state
                       Available:
                        BgpParser.bgp.state_change[.human].ALL
                        BgpParser.bgp.state_change[.human].NONE
                        BgpParser.bgp.state_change[.human].DEFAULT]
  bgp_route         - Select [optionally human-readable] attribute to be included in BgpRouteRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.route[.human].type |
                        BgpParser.bgp.route[.human].source |
                        BgpParser.bgp.route[.human].sequence |
                        BgpParser.bgp.route[.human].timestamp |
                        BgpParser.bgp.route[.human].peer_protocol |
                        BgpParser.bgp.route[.human].peer_bgp_id |
                        BgpParser.bgp.route[.human].peer_as |
                        BgpParser.bgp.route[.human].peer_ip |
                        BgpParser.bgp.route[.human].nexthop_protocol |
                        BgpParser.bgp.route[.human].nexthop_ip |
                        BgpParser.bgp.route[.human].prefix_protocol |
                        BgpParser.bgp.route[.human].prefix |
                        BgpParser.bgp.route[.human].path_id |
                        BgpParser.bgp.route[.human].aspath |
                        BgpParser.bgp.route[.human].origin |
                        BgpParser.bgp.route[.human].communities |
                        BgpParser.bgp.route[.human].large_communities
                       Available:
                        BgpParser.bgp.route[.human].extended_communities
                        BgpParser.bgp.route[.human].multi_exit_disc
                        BgpParser.bgp.route[.human].atomic_aggregate
                        BgpParser.bgp.route[.human].aggregator_protocol
                        BgpParser.bgp.route[.human].aggregator_as
                        BgpParser.bgp.route[.human].aggregator_ip
                        BgpParser.bgp.route[.human].only_to_customer
                        BgpParser.bgp.route[.human].originator_id
                        BgpParser.bgp.route[.human].cluster_list
                        BgpParser.bgp.route[.human].local_pref
                        BgpParser.bgp.route[.human].attr_set
                        BgpParser.bgp.route[.human].as_pathlimit
                        BgpParser.bgp.route[.human].aigp
                        BgpParser.bgp.route[.human].attrs_unknown
                        BgpParser.bgp.route[.human].ALL
                        BgpParser.bgp.route[.human].NONE
                        BgpParser.bgp.route[.human].DEFAULT]
  bgp_keep_alive    - Select [optionally human-readable] attribute to be included in BgpKeepAliveRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.keep_alive[.human].type |
                        BgpParser.bgp.keep_alive[.human].timestamp |
                        BgpParser.bgp.keep_alive[.human].peer_protocol |
                        BgpParser.bgp.keep_alive[.human].peer_as |
                        BgpParser.bgp.keep_alive[.human].peer_ip
                       Available:
                        BgpParser.bgp.keep_alive[.human].ALL
                        BgpParser.bgp.keep_alive[.human].NONE
                        BgpParser.bgp.keep_alive[.human].DEFAULT]
  bgp_route_refresh - Select [optionally human-readable] attribute to be included in BgpRouteRefreshRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.route_refresh[.human].type |
                        BgpParser.bgp.route_refresh[.human].timestamp |
                        BgpParser.bgp.route_refresh[.human].peer_protocol |
                        BgpParser.bgp.route_refresh[.human].peer_as |
                        BgpParser.bgp.route_refresh[.human].peer_ip |
                        BgpParser.bgp.route_refresh[.human].refresh_protocol
                       Available:
                        BgpParser.bgp.route_refresh[.human].ALL
                        BgpParser.bgp.route_refresh[.human].NONE
                        BgpParser.bgp.route_refresh[.human].DEFAULT]
  bgp_notification  - Select [optionally human-readable] attribute to be included in BgpNotificationRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.notification[.human].type |
                        BgpParser.bgp.notification[.human].timestamp |
                        BgpParser.bgp.notification[.human].peer_protocol |
                        BgpParser.bgp.notification[.human].peer_as |
                        BgpParser.bgp.notification[.human].peer_ip |
                        BgpParser.bgp.notification[.human].error_code |
                        BgpParser.bgp.notification[.human].error_subcode |
                        BgpParser.bgp.notification[.human].data
                       Available:
                        BgpParser.bgp.notification[.human].ALL
                        BgpParser.bgp.notification[.human].NONE
                        BgpParser.bgp.notification[.human].DEFAULT]
  bgp_open          - Select [optionally human-readable] attribute to be included in BgpOpenRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.open[.human].type |
                        BgpParser.bgp.open[.human].timestamp |
                        BgpParser.bgp.open[.human].peer_protocol |
                        BgpParser.bgp.open[.human].peer_as |
                        BgpParser.bgp.open[.human].peer_ip |
                        BgpParser.bgp.open[.human].version |
                        BgpParser.bgp.open[.human].my_as |
                        BgpParser.bgp.open[.human].hold_time |
                        BgpParser.bgp.open[.human].bgp_id |
                        BgpParser.bgp.open[.human].capabilities
                       Available:
                        BgpParser.bgp.open[.human].params_unknown
                        BgpParser.bgp.open[.human].ALL
                        BgpParser.bgp.open[.human].NONE
                        BgpParser.bgp.open[.human].DEFAULT]
  bgp_stats         - Select [optionally human-readable] attribute to be included in BgpStatsRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.stats[.human].type |
                        BgpParser.bgp.stats[.human].parser_lifetime |
                        BgpParser.bgp.stats[.human].parser_runtime |
                        BgpParser.bgp.stats[.human].parser_errors |
                        BgpParser.bgp.stats[.human].lgl_runtime |
                        BgpParser.bgp.stats[.human].lgl_entries |
                        BgpParser.bgp.stats[.human].lgl_errors |
                        BgpParser.bgp.stats[.human].mrt_runtime |
                        BgpParser.bgp.stats[.human].mrt_entries |
                        BgpParser.bgp.stats[.human].mrt_errors |
                        BgpParser.bgp.stats[.human].mrt_fixes |
                        BgpParser.bgp.stats[.human].mrt_bgp_entry_types |
                        BgpParser.bgp.stats[.human].mrt_bgp_message_types |
                        BgpParser.bgp.stats[.human].mrt_bgp_attribute_types |
                        BgpParser.bgp.stats[.human].mrt_bgp_capability_types |
                        BgpParser.bgp.stats[.human].bgp_routes_rib_ipv4 |
                        BgpParser.bgp.stats[.human].bgp_routes_rib_ipv6 |
                        BgpParser.bgp.stats[.human].bgp_routes_announce_ipv4 |
                        BgpParser.bgp.stats[.human].bgp_routes_announce_ipv6 |
                        BgpParser.bgp.stats[.human].bgp_routes_withdraw_ipv4 |
                        BgpParser.bgp.stats[.human].bgp_routes_withdraw_ipv6
                       Available:
                        BgpParser.bgp.stats[.human].ALL
                        BgpParser.bgp.stats[.human].NONE
                        BgpParser.bgp.stats[.human].DEFAULT]
  bgp_error         - Select [optionally human-readable] attribute to be included in BgpErrorRecord entries.
                      Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.
                      [Default:
                        BgpParser.bgp.error[.human].type |
                        BgpParser.bgp.error[.human].source |
                        BgpParser.bgp.error[.human].scope |
                        BgpParser.bgp.error[.human].record |
                        BgpParser.bgp.error[.human].reason |
                        BgpParser.bgp.error[.human].message |
                        BgpParser.bgp.error[.human].data |
                        BgpParser.bgp.error[.human].trace
                       Available:
                        BgpParser.bgp.error[.human].ALL
                        BgpParser.bgp.error[.human].NONE
                        BgpParser.bgp.error[.human].DEFAULT]

Returns:
  parse(<filename>) - Parse function that accepts a filename as single positional argument and generates
                      all specified BGP records on invocation. Input files can be provided in .bz2 or .gz
                      format. The parse function may be invoked multiple times within a single context.

Raises:
  FtlError          - Generic parser or runtime error.
  FtlFileError      - Failure during access of input file.
  FtlFormatError    - Unexpected format of input file.
  FtlDataError      - Invalid data entry in input file.
```

## Author

Johann SCHLAMP <[schlamp@leitwert.net](mailto:schlamp@leitwert.net)> 

## License

Copyright (C) 2014-2024 Leitwert GmbH

This software is distributed under the terms of the MIT license.    
It can be found in the LICENSE file or at [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT).
