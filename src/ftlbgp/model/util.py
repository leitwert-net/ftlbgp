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
import functools
import json
import re
import sys
import threading
from collections import namedtuple

# Local imports
from .const import FTL_ATTR
from .const import FTL_RECORD
from .error import FtlError

# Module patching
FTL_PATCH_THREAD_LOCK = threading.Lock()
FTL_PATCH_LOCKED = '__patchlock__'
FTL_PATCH_HASH = '__patchhash__'

# Bit shift for human-readable attributes
FTL_ATTR_SHIFT_HUMAN = 32


def generate_spec_attributes(cls, spec):
    """ Generate generic attributes specification instance.
    """
    # Prepare spec fields
    fields = dict(**{attr.name: attr for attr in spec})

    # Return spec instance
    return namedtuple(cls, fields.keys())(**fields)


def generate_spec_record(cls, spec, human=True, typed=None):
    """ Generate generic record specification instance.
    """
    # Extract name from class
    parts = re.sub('([A-Z]+)', r' \1', cls).split()
    parts = parts[2:] if len(parts) > 3 else parts[1:]
    spectype, name = parts[0].lower(), '_'.join(p.lower() for p in parts[1:])
    argname = '_'.join((spectype, name) if typed is not None else (name, spectype))
    istyped = typed is not None

    # Prepare base record spec
    # [Format] spec := (field, value, default)
    base_spec = (
        ('internal',   set(),      None),
        ('spec',       spectype,   None),
        ('name',       name,       None),
        ('argname',    argname,    None),
        ('typed',      istyped,    None),
        ('ALL',        0,          None),
        ('NONE',       0,          None),
        ('DEFAULT',    0,          None),
    )

    # Prepare human-readable record spec
    # [Format] spec := (field, value, default)
    if human is True:
        base_spec += (
            ('human', None, None),
        )

    # Prepare typed record spec
    # [Format] spec := (field, value, default)
    if istyped is True:
        base_spec += (
            ('type', typed, True),
        )

    # Prepare record spec data
    fields, values, internal = dict(), set(), {field for field, _, _ in base_spec}

    # Iterate record spec fields
    for field, value, default in base_spec + spec:

        # Check values for duplicates
        if default is not None:
            if field in fields:
                field_error = 'Internal' if field in internal else 'Existing'
                raise FtlError(f'{field_error} field "{field}" redefined in model specification {cls}')
            if value in values:
                field_error = value.bit_length() - 1
                raise FtlError(f'Existing value "1 << {field_error}" redefined in model specification {cls}')
            values.add(value)

            # Add value to all/default-type
            fields['ALL'] |= value
            if default is True:
                fields['DEFAULT'] |= value

        # Update value fields
        fields[field] = value

        # Update internal fields
        if default is None:
            fields['internal'].add(field)

    # Add human-readable record spec
    if human is True:
        fields_human = {field: value << FTL_ATTR_SHIFT_HUMAN for field, value in fields.items()
                        if field not in fields['internal'] or field in {'ALL', 'NONE', 'DEFAULT'}}
        fields['human'] = namedtuple(f'{cls}Human', fields_human.keys())(**fields_human)

    # Return record spec instance
    return namedtuple(cls, fields.keys())(**fields)


def apply_spec_records(cls, named_records, serialize, raise_on_errors, handle_error, records, attributes, spec_records,
                       spec_attributes):
    """ Setup generic record templates based on given record/attributes spec.
    """
    # Prepare attribute-to-index mapping
    records_field_to_value = dict()
    attrs_field_to_idx = dict()
    attrs_field_to_human = dict()

    # Prepare template fields
    template_fields = dict()
    for record_name, record_value in records._asdict().items():
        if record_name not in records.internal:
            record_attrs = getattr(attributes, record_name)
            spec_attrs = getattr(spec_attributes, record_name)

            # Skip unrequested records
            if not spec_records & record_value:
                template_fields[record_name] = (tuple(), tuple, None)
                continue

            # Prepare record type and template
            record_attrs_field_to_idx = attrs_field_to_idx.setdefault(record_name, dict())
            record_attrs_field_to_human = attrs_field_to_human.setdefault(record_name, dict())
            record_type = record_name if (spec_attrs >> FTL_ATTR_SHIFT_HUMAN) & record_attrs.type else record_value
            records_field_to_value[record_name] = record_type
            record_init = list()

            # Map attributes to tuple fields/indexes
            attr_fields, attr_index = list(), 0
            for attr_field, attr_value in record_attrs._asdict().items():
                if attr_field not in record_attrs.internal:
                    if spec_attrs & attr_value or (spec_attrs >> FTL_ATTR_SHIFT_HUMAN) & attr_value:

                        # Prepare initial record value (None or auto-typed)
                        record_init_value = None
                        if record_attrs.typed is True:
                            if record_attrs.type == attr_value:
                                record_init_value = record_type

                        # Update record template and index mapping
                        record_init.append(record_init_value)
                        record_attrs_field_to_idx[attr_field] = attr_index
                        record_attrs_field_to_human[attr_field] = (spec_attrs >> FTL_ATTR_SHIFT_HUMAN) & attr_value != 0

                        # Update record fields
                        attr_fields.append(attr_field)
                        attr_index += 1

            # Prepare emit method
            record = ''.join((part.capitalize() for part in record_name.split('_')))
            record_emit = namedtuple(f'{cls}{record}Record', attr_fields)._make if named_records else tuple
            if serialize:
                if named_records:
                    # pylint: disable-next=unnecessary-lambda-assignment
                    record_emit = lambda record, attr_fields=attr_fields: json.dumps(dict(zip(attr_fields, record)))
                else:
                    # pylint: disable-next=unnecessary-lambda-assignment
                    record_emit = lambda record: ','.join(str(e)[1:-1].replace(',', '').replace('\'', '')
                                                          if isinstance(e, tuple) else str(e)
                                                          if e is not None else '' for e in record)

            # Register initialized record template
            template_fields[record_name] = (tuple(record_init), record_emit, record_type)

    # Access stats record template
    stats_init, stats_emit, stats_record = tuple(), tuple, None
    try:
        stats_init, stats_emit, _ = template_fields[attributes.stats.name]
        stats_record = list(stats_init)
    except AttributeError:
        pass

    # Access error record template
    error_init, error_emit, error_type = tuple(), tuple, None
    try:
        error_init, error_emit, error_type = template_fields[attributes.error.name]
    except AttributeError:
        pass

    # Finalize record templates
    for record_name, (record_init, record_emit, record_type) in template_fields.items():

        # Parametrize record error function
        record_error = functools.partial(handle_error, raise_on_errors, error_init, error_emit, record_type, stats_emit,
                                         stats_record)

        # Add record error function to record template
        template_fields[record_name] = (record_init, record_emit, record_error)

    # Finalize record templates and generic record error function
    record_templates = namedtuple(f'FtlRecordTemplates{cls}', template_fields.keys())(**template_fields)
    record_error = functools.partial(handle_error, raise_on_errors, error_init, error_emit, error_type, stats_emit,
                                     stats_record)

    # Return finalized record spec
    return (record_templates, record_error, records_field_to_value, attrs_field_to_idx, attrs_field_to_human, stats_emit,
            stats_record)


def patch_spec_records(module, records, attributes, records_field_to_value, attrs_field_to_idx, attrs_field_to_human):
    """ Patch modules with given record/attributes spec.
    """
    # Prepare record flags
    const_to_record_flag = dict()
    records_name = records.name.upper()
    for record_field in records._fields:
        if record_field not in records.internal:
            record_flag = record_field in records_field_to_value
            const_to_record_flag['_'.join((FTL_RECORD, records_name, record_field.upper()))] = record_flag

    # Prepare attribute indexes
    const_to_attrs_idx = dict()
    for attrs in attributes:
        attrs_name = attrs.argname.upper()
        field_to_idx = attrs_field_to_idx.get(attrs.name, dict())
        for attr_field in attrs._fields:
            if attr_field not in attrs.internal:
                attr_idx = field_to_idx.get(attr_field, -1)
                const_to_attrs_idx['_'.join((FTL_ATTR, attrs_name, attr_field.upper()))] = attr_idx

    # Prepare human-readable attribute flags
    const_to_human_attrs_flag = dict()
    for attrs in attributes:
        attrs_name = attrs.argname.upper()
        field_to_human = attrs_field_to_human.get(attrs.name, dict())
        for attr_field in attrs._fields:
            if attr_field not in attrs.internal:
                attr_flag = field_to_human.get(attr_field, False)
                const_to_human_attrs_flag['_'.join((FTL_ATTR, attrs_name, attr_field.upper(), 'HUMAN'))] = attr_flag

    # Prepare module
    module_path = module.split('.', 1)[0]
    modules_patched = set()

    # Prepare patch hash value
    patch_hash = hash(tuple(hash(tuple(sorted(c.items())))
                            for c in (const_to_record_flag, const_to_attrs_idx, const_to_human_attrs_flag)))

    # Prepare module patcher
    def patch_module(module_name):
        """ Recursively patch spec-related constants in parser (sub-)modules.
        """
        # Prevent patching the same module multiple times
        modules_patched.add(module_name)

        # Access module instance
        module = sys.modules[module_name]

        # Patch module members
        for member in sorted(dir(module)):

            # Patch record flags
            if member in const_to_record_flag:
                setattr(module, member, const_to_record_flag[member])

            # Patch attribute indexes
            elif member in const_to_attrs_idx:
                setattr(module, member, const_to_attrs_idx[member])

            # Patch human-readable attribute flags
            elif member in const_to_human_attrs_flag:
                setattr(module, member, const_to_human_attrs_flag[member])

            # Recurse down
            sub_module = getattr(getattr(module, member), '__module__', None)
            if sub_module is not None and sub_module.startswith(f'{module_path}.'):
                if sub_module not in modules_patched:
                    patch_module(sub_module)
                    continue

    # Lock module access based on patch hash value
    with FTL_PATCH_THREAD_LOCK:
        if getattr(sys.modules[module], FTL_PATCH_HASH, patch_hash) != patch_hash:
            raise FtlError(f'Unable to lock parser module "{module}" - parallel use not allowed')
        setattr(sys.modules[module], FTL_PATCH_LOCKED, getattr(sys.modules[module], FTL_PATCH_LOCKED, 0) + 1)
        setattr(sys.modules[module], FTL_PATCH_HASH, patch_hash)

        # Patch all modules
        patch_module(module)


def unpatch_spec_records(module):
    """ Undo module patch (remove lock).
    """
    # Unlock module access
    with FTL_PATCH_THREAD_LOCK:
        setattr(sys.modules[module], FTL_PATCH_LOCKED, getattr(sys.modules[module], FTL_PATCH_LOCKED, 0) - 1)
        if getattr(sys.modules[module], FTL_PATCH_LOCKED, 0) == 0:
            delattr(sys.modules[module], FTL_PATCH_LOCKED)
            delattr(sys.modules[module], FTL_PATCH_HASH)
