# Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import uuid

import ovs.db.data
import ovs.db.parser
import ovs.ovsuuid
from ovs.db import error


class AtomicType(object):
    def __init__(self, name, default, python_types):
        self.name = name
        self.default = default
        self.python_types = python_types

    @staticmethod
    def from_string(s):
        if s != "void":
            for atomic_type in ATOMIC_TYPES:
                if s == atomic_type.name:
                    return atomic_type
        raise error.Error('"%s" is not an atomic-type' % s, s)

    @staticmethod
    def from_json(json):
        if not isinstance(json, str):
            raise error.Error("atomic-type expected", json)
        else:
            return AtomicType.from_string(json)

    def __str__(self):
        return self.name

    def to_string(self):
        return self.name

    def to_json(self):
        return self.name

    def default_atom(self):
        return ovs.db.data.Atom(self, self.default)


REAL_PYTHON_TYPES = [int]
REAL_PYTHON_TYPES.extend([float])
REAL_PYTHON_TYPES = tuple(REAL_PYTHON_TYPES)

VoidType = AtomicType("void", None, ())
IntegerType = AtomicType("integer", 0, (int,))
RealType = AtomicType("real", 0.0, REAL_PYTHON_TYPES)
BooleanType = AtomicType("boolean", False, (bool,))
StringType = AtomicType("string", "", (str,))
UuidType = AtomicType("uuid", ovs.ovsuuid.zero(), (uuid.UUID,))

ATOMIC_TYPES = [VoidType, IntegerType, RealType, BooleanType, StringType,
                UuidType]


def escapeCString(src):
    dst = ""
    for c in src:
        if c in "\\\"":
            dst += "\\" + c
        elif ord(c) < 32:
            if c == '\n':
                dst += '\\n'
            elif c == '\r':
                dst += '\\r'
            elif c == '\a':
                dst += '\\a'
            elif c == '\b':
                dst += '\\b'
            elif c == '\f':
                dst += '\\f'
            elif c == '\t':
                dst += '\\t'
            elif c == '\v':
                dst += '\\v'
            else:
                dst += '\\%03o' % ord(c)
        else:
            dst += c
    return dst


def commafy(x):
    """Returns integer x formatted in decimal with thousands set off by
    commas."""
    return _commafy("%d" % x)


def _commafy(s):
    if s.startswith('-'):
        return '-' + _commafy(s[1:])
    elif len(s) <= 3:
        return s
    else:
        return _commafy(s[:-3]) + ',' + _commafy(s[-3:])


def returnUnchanged(x):
    return x


class BaseType(object):
    def __init__(self, type_, enum=None, min=None, max=None,
                 min_length=0, max_length=sys.maxsize, ref_table_name=None):
        assert isinstance(type_, AtomicType)
        self.type = type_
        self.enum = enum
        self.min = min
        self.max = max
        self.min_length = min_length
        self.max_length = max_length
        self.ref_table_name = ref_table_name
        if ref_table_name:
            self.ref_type = 'strong'
        else:
            self.ref_type = None
        self.ref_table = None

    def default(self):
        return ovs.db.data.Atom.default(self.type)

    def __eq__(self, other):
        if not isinstance(other, BaseType):
            return NotImplemented
        return (self.type == other.type and self.enum == other.enum and
                self.min == other.min and self.max == other.max and
                self.min_length == other.min_length and
                self.max_length == other.max_length and
                self.ref_table_name == other.ref_table_name)

    def __ne__(self, other):
        if not isinstance(other, BaseType):
            return NotImplemented
        else:
            return not (self == other)

    @staticmethod
    def __parse_uint(parser, name, default):
        value = parser.get_optional(name, (int,))
        if value is None:
            value = default
        else:
            max_value = 2 ** 32 - 1
            if not (0 <= value <= max_value):
                raise error.Error("%s out of valid range 0 to %d"
                                  % (name, max_value), value)
        return value

    @staticmethod
    def from_json(json):
        if isinstance(json, str):
            return BaseType(AtomicType.from_json(json))

        parser = ovs.db.parser.Parser(json, "ovsdb type")
        atomic_type = AtomicType.from_json(parser.get("type", (str,)))

        base = BaseType(atomic_type)

        enum = parser.get_optional("enum", [])
        if enum is not None:
            base.enum = ovs.db.data.Datum.from_json(
                    BaseType.get_enum_type(base.type), enum)
        elif base.type == IntegerType:
            base.min = parser.get_optional("minInteger", (int,))
            base.max = parser.get_optional("maxInteger", (int,))
            if (base.min is not None and base.max is not None
                    and base.min > base.max):
                raise error.Error("minInteger exceeds maxInteger", json)
        elif base.type == RealType:
            base.min = parser.get_optional("minReal", REAL_PYTHON_TYPES)
            base.max = parser.get_optional("maxReal", REAL_PYTHON_TYPES)
            if (base.min is not None and base.max is not None
                    and base.min > base.max):
                raise error.Error("minReal exceeds maxReal", json)
        elif base.type == StringType:
            base.min_length = BaseType.__parse_uint(parser, "minLength", 0)
            base.max_length = BaseType.__parse_uint(parser, "maxLength",
                                                    sys.maxsize)
            if base.min_length > base.max_length:
                raise error.Error("minLength exceeds maxLength", json)
        elif base.type == UuidType:
            base.ref_table_name = parser.get_optional("refTable", ['id'])
            if base.ref_table_name:
                base.ref_type = parser.get_optional("refType",
                                                    (str,),
                                                   "strong")
                if base.ref_type not in ['strong', 'weak']:
                    raise error.Error('refType must be "strong" or "weak" '
                                      '(not "%s")' % base.ref_type)
        parser.finish()

        return base

    def to_json(self):
        if not self.has_constraints():
            return self.type.to_json()

        json = {'type': self.type.to_json()}

        if self.enum:
            json['enum'] = self.enum.to_json()

        if self.type == IntegerType:
            if self.min is not None:
                json['minInteger'] = self.min
            if self.max is not None:
                json['maxInteger'] = self.max
        elif self.type == RealType:
            if self.min is not None:
                json['minReal'] = self.min
            if self.max is not None:
                json['maxReal'] = self.max
        elif self.type == StringType:
            if self.min_length != 0:
                json['minLength'] = self.min_length
            if self.max_length != sys.maxsize:
                json['maxLength'] = self.max_length
        elif self.type == UuidType:
            if self.ref_table_name:
                json['refTable'] = self.ref_table_name
                if self.ref_type != 'strong':
                    json['refType'] = self.ref_type
        return json

    def copy(self):
        base = BaseType(self.type, self.enum.copy(), self.min, self.max,
                        self.min_length, self.max_length, self.ref_table_name)
        base.ref_table = self.ref_table
        return base

    def is_valid(self):
        if self.type in (VoidType, BooleanType, UuidType):
            return True
        elif self.type in (IntegerType, RealType):
            return self.min is None or self.max is None or self.min <= self.max
        elif self.type == StringType:
            return self.min_length <= self.max_length
        else:
            return False

    def has_constraints(self):
        return (self.enum is not None or self.min is not None or
                self.max is not None or
                self.min_length != 0 or self.max_length != sys.maxsize or
                self.ref_table_name is not None)

    def without_constraints(self):
        return BaseType(self.type)

    @staticmethod
    def get_enum_type(atomic_type):
        """Returns the type of the 'enum' member for a BaseType whose
        'type' is 'atomic_type'."""
        return Type(BaseType(atomic_type), None, 1, sys.maxsize)

    def is_ref(self):
        return self.type == UuidType and self.ref_table_name is not None

    def is_strong_ref(self):
        return self.is_ref() and self.ref_type == 'strong'

    def is_weak_ref(self):
        return self.is_ref() and self.ref_type == 'weak'

    def toEnglish(self, escapeLiteral=returnUnchanged):
        if self.type == UuidType and self.ref_table_name:
            s = escapeLiteral(self.ref_table_name)
            if self.ref_type == 'weak':
                s = "weak reference to " + s
            return s
        else:
            return self.type.to_string()

    def constraintsToEnglish(self, escapeLiteral=returnUnchanged,
                             escapeNumber=returnUnchanged):
        if self.enum:
            literals = [value.toEnglish(escapeLiteral)
                        for value in self.enum.values]
            literals.sort()
            if len(literals) == 1:
                english = 'must be %s' % (literals[0])
            elif len(literals) == 2:
                english = 'either %s or %s' % (literals[0], literals[1])
            else:
                english = 'one of %s, %s, or %s' % (literals[0],
                                                    ', '.join(literals[1:-1]),
                                                    literals[-1])
        elif self.min is not None and self.max is not None:
            if self.type == IntegerType:
                english = 'in range %s to %s' % (
                    escapeNumber(commafy(self.min)),
                    escapeNumber(commafy(self.max)))
            else:
                english = 'in range %s to %s' % (
                    escapeNumber("%g" % self.min),
                    escapeNumber("%g" % self.max))
        elif self.min is not None:
            if self.type == IntegerType:
                english = 'at least %s' % escapeNumber(commafy(self.min))
            else:
                english = 'at least %s' % escapeNumber("%g" % self.min)
        elif self.max is not None:
            if self.type == IntegerType:
                english = 'at most %s' % escapeNumber(commafy(self.max))
            else:
                english = 'at most %s' % escapeNumber("%g" % self.max)
        elif self.min_length != 0 and self.max_length != sys.maxsize:
            if self.min_length == self.max_length:
                english = ('exactly %s characters long'
                           % commafy(self.min_length))
            else:
                english = ('between %s and %s characters long'
                        % (commafy(self.min_length),
                           commafy(self.max_length)))
        elif self.min_length != 0:
            return 'at least %s characters long' % commafy(self.min_length)
        elif self.max_length != sys.maxsize:
            english = 'at most %s characters long' % commafy(self.max_length)
        else:
            english = ''

        return english

    def toCType(self, prefix, refTable=True):
        if self.ref_table_name:
            if not refTable:
                assert self.type == UuidType
                return 'struct uuid *'
            return "struct %s%s *" % (prefix, self.ref_table_name.lower())
        else:
            return {IntegerType: 'int64_t ',
                    RealType: 'double ',
                    UuidType: 'struct uuid ',
                    BooleanType: 'bool ',
                    StringType: 'char *'}[self.type]

    def to_const_c_type(self, prefix, refTable=True):
        nonconst = self.toCType(prefix, refTable)

        # A "const" prefix works OK for the types we use, but it's a little
        # weird to write "const bool" as, e.g., a function parameter since
        # there's no real "const"ness there.  So, omit the "const" except
        # when a pointer is involved.
        if '*' in nonconst:
            return 'const ' + nonconst
        else:
            return nonconst

    def toAtomicType(self):
        return "OVSDB_TYPE_%s" % self.type.to_string().upper()

    def copyCValue(self, dst, src, refTable=True):
        args = {'dst': dst, 'src': src}
        if self.ref_table_name:
            if not refTable:
                return "%(dst)s = *%(src)s;" % args
            return ("%(dst)s = %(src)s->header_.uuid;") % args
        elif self.type == StringType:
            return "%(dst)s = xstrdup(%(src)s);" % args
        else:
            return "%(dst)s = %(src)s;" % args

    def assign_c_value_casting_away_const(self, dst, src, refTable=True):
        args = {'dst': dst, 'src': src}
        if self.ref_table_name:
            if not refTable:
                return "%(dst)s = *%(src)s;" % args
            return ("%(dst)s = %(src)s->header_.uuid;") % args
        elif self.type == StringType:
            return "%(dst)s = CONST_CAST(char *, %(src)s);" % args
        else:
            return "%(dst)s = %(src)s;" % args

    def initCDefault(self, var, is_optional):
        if self.ref_table_name:
            return "%s = NULL;" % var
        elif self.type == StringType and not is_optional:
            return '%s = "";' % var
        else:
            pattern = {IntegerType: '%s = 0;',
                       RealType: '%s = 0.0;',
                       UuidType: 'uuid_zero(&%s);',
                       BooleanType: '%s = false;',
                       StringType: '%s = NULL;'}[self.type]
            return pattern % var

    def cInitBaseType(self, prefix, prereqs):
        init = [".type = %s," % self.toAtomicType()]
        if self.enum:
            datum_name = "%s_enum" % prefix
            init += [".enum_ = &%s," % datum_name]
            prereqs += self.enum.cDeclareDatum(datum_name)
        if self.type == IntegerType:
            if self.min is None:
                low = "INT64_MIN"
            else:
                low = "INT64_C(%d)" % self.min
            if self.max is None:
                high = "INT64_MAX"
            else:
                high = "INT64_C(%d)" % self.max
            init.append(".integer = { .min = %s, .max = %s }," % (low, high))
        elif self.type == RealType:
            if self.min is None:
                low = "-DBL_MAX"
            else:
                low = self.min
            if self.max is None:
                high = "DBL_MAX"
            else:
                high = self.max
            init.append(".real = { .min = %s, .max = %s }," % (low, high))
        elif self.type == StringType:
            if self.min is None:
                low = 0
            else:
                low = self.min_length
            if self.max is None:
                high = "UINT_MAX"
            else:
                high = self.max_length
            init.append(".string = { .minLen = %s, .maxLen = %s }," % (
                low, high))
        elif self.type == UuidType:
            if self.ref_table_name is not None:
                init.append(".uuid = { .refTableName = \"%s\", "
                            ".refType = OVSDB_REF_%s }," % (
                                escapeCString(self.ref_table_name),
                                self.ref_type.upper()))
        return init


class Type(object):
    DEFAULT_MIN = 1
    DEFAULT_MAX = 1

    def __init__(self, key, value=None, n_min=DEFAULT_MIN, n_max=DEFAULT_MAX):
        self.key = key
        self.value = value
        self.n_min = n_min
        self.n_max = n_max

    def copy(self):
        if self.value is None:
            value = None
        else:
            value = self.value.copy()
        return Type(self.key.copy(), value, self.n_min, self.n_max)

    def __eq__(self, other):
        if not isinstance(other, Type):
            return NotImplemented
        return (self.key == other.key and self.value == other.value and
                self.n_min == other.n_min and self.n_max == other.n_max)

    def __ne__(self, other):
        if not isinstance(other, Type):
            return NotImplemented
        else:
            return not (self == other)

    def is_valid(self):
        return (self.key.type != VoidType and self.key.is_valid() and
                (self.value is None or
                 (self.value.type != VoidType and self.value.is_valid())) and
                self.n_min <= 1 <= self.n_max)

    def is_scalar(self):
        return self.n_min == 1 and self.n_max == 1 and not self.value

    def is_optional(self):
        return self.n_min == 0 and self.n_max == 1

    def is_composite(self):
        return self.n_max > 1

    def is_set(self):
        return self.value is None and (self.n_min != 1 or self.n_max != 1)

    def is_map(self):
        return self.value is not None

    def is_smap(self):
        return (self.is_map()
                and self.key.type == StringType
                and self.value.type == StringType)

    def is_optional_pointer(self):
        return (self.is_optional() and not self.value
                and (self.key.type == StringType or self.key.ref_table_name))

    @staticmethod
    def __n_from_json(json, default):
        if json is None:
            return default
        elif isinstance(json, int) and 0 <= json <= sys.maxsize:
            return json
        else:
            raise error.Error("bad min or max value", json)

    @staticmethod
    def from_json(json):
        if isinstance(json, str):
            return Type(BaseType.from_json(json))

        parser = ovs.db.parser.Parser(json, "ovsdb type")
        _types = [str]
        _types.extend([dict])
        key_json = parser.get("key", _types)
        value_json = parser.get_optional("value", _types)
        min_json = parser.get_optional("min", [int])
        _types = [str]
        _types.extend([int])
        max_json = parser.get_optional("max", _types)
        parser.finish()

        key = BaseType.from_json(key_json)
        if value_json:
            value = BaseType.from_json(value_json)
        else:
            value = None

        n_min = Type.__n_from_json(min_json, Type.DEFAULT_MIN)

        if max_json == 'unlimited':
            n_max = sys.maxsize
        else:
            n_max = Type.__n_from_json(max_json, Type.DEFAULT_MAX)

        type_ = Type(key, value, n_min, n_max)
        if not type_.is_valid():
            raise error.Error("ovsdb type fails constraint checks", json)
        return type_

    def to_json(self):
        if self.is_scalar() and not self.key.has_constraints():
            return self.key.to_json()

        json = {"key": self.key.to_json()}
        if self.value is not None:
            json["value"] = self.value.to_json()
        if self.n_min != Type.DEFAULT_MIN:
            json["min"] = self.n_min
        if self.n_max == sys.maxsize:
            json["max"] = "unlimited"
        elif self.n_max != Type.DEFAULT_MAX:
            json["max"] = self.n_max
        return json

    def toEnglish(self, escapeLiteral=returnUnchanged):
        keyName = self.key.toEnglish(escapeLiteral)
        if self.value:
            valueName = self.value.toEnglish(escapeLiteral)

        if self.is_scalar():
            return keyName
        elif self.is_optional():
            if self.value:
                return "optional %s-%s pair" % (keyName, valueName)
            else:
                return "optional %s" % keyName
        else:
            if self.n_max == sys.maxsize:
                if self.n_min:
                    quantity = "%s or more " % commafy(self.n_min)
                else:
                    quantity = ""
            elif self.n_min:
                quantity = "%s to %s " % (commafy(self.n_min),
                                          commafy(self.n_max))
            else:
                quantity = "up to %s " % commafy(self.n_max)

            if self.value:
                return "map of %s%s-%s pairs" % (quantity, keyName, valueName)
            else:
                # Extract the last word from 'keyName' so we can make it
                # plural.  For linguistic analysis, turn it into English
                # without formatting so that we don't consider any prefix or
                # suffix added by escapeLiteral.
                plainKeyName = (self.key.toEnglish(returnUnchanged)
                                .rpartition(' ')[2].lower())

                if plainKeyName == 'chassis':
                    plural = keyName
                elif plainKeyName.endswith('s'):
                    plural = keyName + "es"
                else:
                    plural = keyName + "s"
                return "set of %s%s" % (quantity, plural)

    def constraintsToEnglish(self, escapeLiteral=returnUnchanged,
                             escapeNumber=returnUnchanged):
        constraints = []
        keyConstraints = self.key.constraintsToEnglish(escapeLiteral,
                                                       escapeNumber)
        if keyConstraints:
            if self.value:
                constraints.append('key %s' % keyConstraints)
            else:
                constraints.append(keyConstraints)

        if self.value:
            valueConstraints = self.value.constraintsToEnglish(escapeLiteral,
                                                               escapeNumber)
            if valueConstraints:
                constraints.append('value %s' % valueConstraints)

        return ', '.join(constraints)

    def cDeclComment(self):
        if self.n_min == 1 and self.n_max == 1 and self.key.type == StringType:
            return "\t/* Always nonnull. */"
        else:
            return ""

    def cInitType(self, prefix, prereqs):
        init = [".key = {"]
        init += ["   " + x for x in self.key.cInitBaseType(prefix + "_key",
                                                           prereqs)]
        init += ["},"]
        if self.value:
            init += [".value = {"]
            init += ["    " + x
                     for x in self.value.cInitBaseType(prefix + "_value",
                                                       prereqs)]
            init += ["},"]
        else:
            init.append(".value = OVSDB_BASE_VOID_INIT,")
        init.append(".n_min = %s," % self.n_min)
        if self.n_max == sys.maxsize:
            n_max = "UINT_MAX"
        else:
            n_max = self.n_max
        init.append(".n_max = %s," % n_max)
        return init
