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
import bz2
import contextlib
import functools
import gzip
import time
from collections import namedtuple

# Local imports
from .model.record import FtlRecordsBgp
from .model.error import FtlError
from .model.error import FtlFileError
from .model.error import FtlFormatError
from .model.const import FTL_MRT
from .model.const import FTL_LGL
from .model.const import FTL_BGP
from .model.const import FTL_PARSER
from .model.util import apply_spec_records
from .model.util import patch_spec_records
from .model.util import unpatch_spec_records
from .model.stats import filter_stats_spec
from .model.stats import init_stats_record
from .data.util import handle_bgp_error
from .data.util import init_caches

# Magic bytes
BZ2_MAGIC_BYTES = b'\x42\x5a\x68'
GZIP_MAGIC_BYTES = b'\x1f\x8b'


def FtlParser(*unpack_functions):
    """ BGP parser decorator for applying predefined arguments to given unpack functions.

        Positional arguments:
          unpack_functions  - One or more parsing functions decorated with @FtlParserFunc.
    """
    # Check setup of unpack functions
    for unpack_function in unpack_functions:
        if hasattr(unpack_function, 'ftl_parser_open_file') is False:
            raise FtlError(f'Parser function {unpack_function.__name__}() invalid (needs @FtlParserFunc decorator)')

    # Prepare supported data sources
    parser_support = {FTL_PARSER, FTL_BGP}
    parser_support |= {f.__name__.split('_')[1] for f in unpack_functions} & {FTL_MRT, FTL_LGL}
    parser_no_support = {FTL_MRT, FTL_LGL} - parser_support

    # Prepare supported stats fields
    FtlAttrsBgpSupport = filter_stats_spec(parser_no_support)

    # Initialize parser context
    def decorator(parser):
        """ Setup generic BGP parser.
        """
        @functools.wraps(parser, assigned=set(functools.WRAPPER_ASSIGNMENTS) - {'__doc__'})
        def ftl_parser(named_records=True, serialize=False, use_cache=True, raise_on_errors=False,
                       bgp_records=FtlRecordsBgp.DEFAULT, **bgp_attributes):
            """ This @FtlParser instance is used to read input files and generate a set of BGP records (Python tuples).
                It must be used with a context manager (see sample usage below) and accepts the following arguments.

                Keyword arguments:
                  named_records     - Return named tuples instead of plain unnamed tuple records. [Default: True]
                  serialize         - Convert output records to JSON (if named) or CSV (if unnamed). [Default: False]
                  use_cache         - Cache expensive low-entropy values (memory consumption < 1MB). [Default: True]
                  raise_on_errors   - Raise exceptions and stop parsing in case of data errors. [Default: False]
                  bgp_records       - Select the types of BgpRecord entries to be returned by the parser.
                                      Supports bitwise logical operators OR, AND, NOT to specify multiple records.
                                      {BGP_RECORDS_DOC}
                  {BGP_ATTRIBUTES_DOC}

                Returns:
                  parse(<filename>) - Parse function that accepts a filename as single positional argument and generates
                                      all specified BGP records on invocation. Input files can be provided in .bz2 or .gz
                                      format. The parse function may be invoked multiple times within a single context.

                Raises:
                  FtlError          - Generic parser or runtime error.
                  FtlFileError      - Failure during access of input file.
                  FtlFormatError    - Unexpected format of input file.
                  FtlDataError      - Invalid data entry in input file.

                Sample usage:

                  # Import parser
                  from ftlbgp import BgpParser

                  # Parse all records
                  filename = ...
                  with BgpParser(bgp_records=BgpParser.bgp.records.ALL) as parse:
                      for record in parse(filename):
                          ...

                  # Parse specific records (route and error)
                  filename = ...
                  with BgpParser(bgp_records=BgpParser.bgp.records.route | BgpParser.bgp.records.error) as parse:
                      for record in parse(filename):
                          ...

                  # Parse all route attributes
                  filename = ...
                  with BgpParser(bgp_route=BgpParser.bgp.route.ALL) as parse:
                      for record in parse(filename):
                          ...

                  # Parse specific route attributes (default and local_pref)
                  filename = ...
                  with BgpParser(bgp_route=BgpParser.bgp.route.DEFAULT | BgpParser.bgp.route.local_pref) as parse:
                      for record in parse(filename):
                          ...
            """
            # Prepare total runtime of context maanager
            parser_time_start = time.perf_counter()

            # Prepare record attributes and add default values
            bgp_attrs = {attrs.name: bgp_attributes.pop(attrs.argname, attrs.DEFAULT)
                         for attrs in FtlAttrsBgpSupport if bgp_records & getattr(FtlRecordsBgp, attrs.name)}

            # Set empty record attributes for other records
            bgp_attrs.update({attrs.name: attrs.NONE for attrs in FtlAttrsBgpSupport
                              if not bgp_records & getattr(FtlRecordsBgp, attrs.name)})

            # Check remaining keywords
            if len(bgp_attributes) > 0:
                bgp_attribute = next(iter(bgp_attributes))
                if any(attrs.argname == bgp_attribute for attrs in FtlAttrsBgpSupport) is True:
                    raise FtlError(f'Argument "{bgp_attribute}" not allowed for parser - enable via "bgp_records"'
                                   '(see @FtlParser decorator)')
                raise FtlError(f'Invalid argument "{bgp_attribute}" for parser (see @FtlParser decorator)')

            # Create record attributes instance
            bgp_attributes = namedtuple('FtlRecordAttrsBgp', bgp_attrs.keys())(**bgp_attrs)

            # Prepare BGP record templates
            (bgp_templates, bgp_error, records_fields, attrs_fields, attrs_human, stats_emit, stats_record,
             ) = apply_spec_records('Bgp', named_records, serialize, raise_on_errors, handle_bgp_error, FtlRecordsBgp,
                                    FtlAttrsBgpSupport, bgp_records, bgp_attributes)

            # Patch BGP record specs
            # NOTE: This call patches all spec-related constants that are imported
            # NOTE: by the unpack functions' modules (including any child function modules)
            for unpack_function in unpack_functions:
                patch_spec_records(unpack_function.__module__, FtlRecordsBgp, FtlAttrsBgpSupport, records_fields,
                                   attrs_fields, attrs_human)

            # Prepare record values and attr indexes
            records_name, records_cls = FtlRecordsBgp.spec, FtlRecordsBgp.__class__.__name__
            records_spec = namedtuple(records_cls, records_fields.keys())(*records_fields.values())
            attrs_specs = dict()
            for attrs_name, attrs in attrs_fields.items():
                attrs_cls = getattr(FtlAttrsBgpSupport, attrs_name).__class__.__name__
                attrs_specs[attrs_name] = namedtuple(attrs_cls, attrs.keys())(*attrs.values())
            unpack_bgp_spec = namedtuple('FtlBgp', (records_name, ) + tuple(attrs_specs))
            unpack_bgp_spec = unpack_bgp_spec(records_spec, *attrs_specs.values())

            # Prepare human-readable caches
            # NOTE: At the moment, there is only one simple timestamp cache (CACHE_TS)
            # NOTE: We could easily introduce additional cache types (e.g. for CACHE_IP)
            # NOTE: In that case, we should also add some cache fill stats below
            unpack_caches = [init_caches() if use_cache else None for _ in range(len(unpack_functions))]

            # Initialize stats record
            if bgp_records & FtlRecordsBgp.stats:
                init_stats_record(FtlAttrsBgpSupport.stats, unpack_bgp_spec.stats, bgp_attributes.stats, stats_record)

            @contextlib.contextmanager
            def parse():
                """ Context manager for BGP parsing.
                """
                def unpack(filename):
                    """ Try to parse input file with given unpack functions.
                    """
                    # Iterate unpack functions
                    idx, max_idx = 0, len(unpack_functions) - 1
                    for idx, (unpack_function, caches) in enumerate(zip(unpack_functions, unpack_caches)):
                        source_runtime = f'{unpack_function.__name__.split("_")[1]}_runtime'
                        unpack_time_start = time.perf_counter()

                        try:
                            # Invoke file opener
                            with unpack_function.ftl_parser_open_file(filename) as inputfile:

                                # Yield unpacked records
                                yield from unpack_function(inputfile, caches, stats_record, bgp_templates, bgp_error)

                            # Success
                            return

                        # Handle format errors
                        except FtlFormatError:

                            # Retry if unpack functions left
                            if idx < max_idx:
                                continue

                            # Raise generic error if multiple parsers failed
                            if max_idx > 0:
                                raise FtlFormatError('Unknown input file format')  # pylint: disable=raise-missing-from

                            # Reraise specific format error
                            raise

                        # Reraise already handled exceptions
                        except FtlError:
                            raise

                        # Raise unhandled exceptions
                        except Exception as exc:
                            raise FtlError('Unhandled parser error', exception=exc)  # pylint: disable=raise-missing-from

                        # Update and yield stats record
                        finally:

                            # Update stats record
                            if bgp_records & FtlRecordsBgp.stats:
                                now_time_end = time.perf_counter()
                                unpack_time = now_time_end - unpack_time_start
                                parser_time = now_time_end - parser_time_start
                                sattrs = FtlAttrsBgpSupport.stats

                                # Add runtimes
                                if (bgp_attributes.stats
                                    & (getattr(sattrs, source_runtime) | getattr(sattrs.human, source_runtime))):
                                    stats_record[getattr(unpack_bgp_spec.stats, source_runtime)] += unpack_time
                                if bgp_attributes.stats & (sattrs.parser_runtime | sattrs.human.parser_runtime):
                                    stats_record[unpack_bgp_spec.stats.parser_runtime] += unpack_time
                                if bgp_attributes.stats & (sattrs.parser_lifetime | sattrs.human.parser_lifetime):
                                    stats_record[unpack_bgp_spec.stats.parser_lifetime] = parser_time

                                # Yield final stats record
                                # NOTE: This record is cumulatively updated when parsing multiple files
                                yield stats_emit(stats_record)

                # Add record values and attr indexes
                unpack.bgp = unpack_bgp_spec

                # Yield record generator
                yield unpack

                # Unpatch BGP record specs
                for unpack_function in unpack_functions:
                    unpatch_spec_records(unpack_function.__module__)

            # Return parser context
            return parse()

        # Prepare parser documentation
        line_indent = ''.join(('\n', ftl_parser.__doc__.split('\n')[-1], ' ' * 6))
        arg_indent = ' ' * (len(next(line for line in ftl_parser.__doc__.split('\n')
                                     if FtlRecordsBgp.argname in line).split('-', 1)[0].lstrip()))

        def generate_doc(model, records=False):
            """ Generate docstring for given record/attributes model.
            """
            # Extract model defaults and available entries
            model_doc_default, model_doc_available, model_doc_internal = list(), list(), list()
            for field, value in model._asdict().items():
                if field not in model.internal or any(v is value for v in (model.ALL, model.NONE, model.DEFAULT)):
                    model_doc = model_doc_available
                    if value in {model.ALL, model.NONE, model.DEFAULT}:
                        model_doc = model_doc_internal
                    elif value & model.DEFAULT:
                        model_doc = model_doc_default
                    field_name = f'{parser.__name__}{".bgp" if records is False else ""}.{model.name}'
                    field_name += f'{".records" if records is True else "[.human]"}.{field}'
                    field_doc = ''.join((line_indent, arg_indent, ' ' * 4, field_name))
                    model_doc.append(field_doc)

            # Generate and return model documentation
            return ''.join(['[Default:', ' |'.join(model_doc_default), line_indent, arg_indent, ' ' * 2, ' Available:',
                            ''.join(model_doc_available + model_doc_internal).rstrip('|'), ']'])

        # Prepare records documentation
        records_doc = generate_doc(FtlRecordsBgp, records=True).rstrip()

        # Prepare attributes documentation
        attributes_doc = [line_indent[1:]]
        for name, attrs in FtlAttrsBgpSupport._asdict().items():
            record_name = f'Bgp{"".join((p.capitalize() for p in name.split("_")))}Record'
            attributes_doc.append(''.join((
                line_indent, attrs.argname, ' ' * (len(arg_indent) - len(attrs.argname)),
                f'- Select [optionally human-readable] attribute to be included in {record_name} entries.',
                line_indent, ' ' * (len(attrs.argname) + 2 + len(arg_indent) - len(attrs.argname)),
                'Supports bitwise logical operators (OR/AND/NOT) to specify multiple attributes.', line_indent,
                ' ' * len(attrs.argname), ' ' * (len(arg_indent) - len(attrs.argname)), ' ' * 2, generate_doc(attrs)
            )))

        # Update parser documentation
        attributes_doc_str = ''.join(attributes_doc).lstrip()
        ftl_parser.__doc__ = ftl_parser.__doc__.format(BGP_RECORDS_DOC=records_doc, BGP_ATTRIBUTES_DOC=attributes_doc_str)
        ftl_parser.__doc__ = ''.join((parser.__doc__.strip(), line_indent, line_indent[:-2], ftl_parser.__doc__.strip()))

        # Prepare spec filtering (generate key/value spec lists without internal fields)
        # pylint: disable-next=unnecessary-lambda-assignment
        filter_spec_record = lambda s: list(zip(*((k, v) for k, v in s._asdict().items() if k not in s.internal
                                                  or any(vs is v for vs in (s.ALL, s.NONE, s.DEFAULT)))))
        # pylint: disable-next=unnecessary-lambda-assignment
        filter_spec_attrs = lambda s: list(zip(*((k, v) for k, v in s._asdict().items() if k not in s.internal
                                                 or any(vs is v for vs in (s.ALL, s.NONE, s.DEFAULT, s.human)))))

        # Add record/attr specs (without internal fields)
        records_name, (records_fields, records_values) = FtlRecordsBgp.spec, filter_spec_record(FtlRecordsBgp)
        records_spec = namedtuple(FtlRecordsBgp.__class__.__name__, records_fields)(*records_values)
        attrs_specs = dict()
        for attrs_name, attrs in FtlAttrsBgpSupport._asdict().items():
            attrs_fields, attrs_values = filter_spec_attrs(attrs)
            attrs_specs[attrs_name] = namedtuple(attrs.__class__.__name__, attrs_fields)(*attrs_values)
        ftl_parser.bgp = namedtuple('FtlBgp', (records_name, ) + tuple(attrs_specs))(records_spec, *attrs_specs.values())

        # Return parser
        return ftl_parser

    # Return decorator for parser
    return decorator


def FtlParserFunc(method=None, text_input=None):
    """ Decorate BGP parsing function.

        Keyword arguments:
          text_input  - If given, open input file as text with specified encoding (e.g. UTF-8).
    """
    def decorator(unpack):
        """ Setup generic BGP parsing function.
        """
        @functools.wraps(unpack)
        def ftl_parser_open_file(filename):
            """ Open BGP file for reading.
            """
            try:
                # Read magic bytes
                ftype = ''
                with open(filename, 'rb') as fh:
                    ftype = fh.read(max(len(BZ2_MAGIC_BYTES), len(GZIP_MAGIC_BYTES)))

                # Prepare access mode
                mode = 'rb' if text_input is None else 'rt'

                # Support bzip2, gzip, and uncompressed files
                if ftype.startswith(BZ2_MAGIC_BYTES):
                    return bz2.open(filename, mode=mode, encoding=text_input)
                if ftype.startswith(GZIP_MAGIC_BYTES):
                    return gzip.open(filename, mode=mode, encoding=text_input)
                return open(filename, mode=mode, encoding=text_input)

            # Invalid input file
            except Exception as exc:
                raise FtlFileError(exception=exc)  # pylint: disable=raise-missing-from

            # Failure
            return None

        # Add file opener to parser function
        unpack.ftl_parser_open_file = ftl_parser_open_file

        # Return parser function
        return unpack

    # Return decorator for parser function
    if method is None:
        return decorator
    return decorator(method)
