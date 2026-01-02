# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
cut command
"""

from __future__ import annotations

import getopt
import re

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}


class Command_cut(HoneyPotCommand):
    """
    cut command - extract fields from input
    """

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(self.args, "b:c:d:f:s", ["help", "version"])
        except getopt.GetoptError as err:
            self.errorWrite(f"cut: invalid option -- '{err.opt}'\nTry 'cut --help' for more information.\n")
            self.exit()
            return

        # Parse options
        delimiter = "\t"  # default delimiter is TAB
        fields: list[int | str] = []
        complement = False
        only_delimited = False

        for o, a in optlist:
            if o in ("-d", "--delimiter"):
                if len(a) != 1:
                    self.errorWrite("cut: the delimiter must be a single character\n")
                    self.exit()
                    return
                delimiter = a
            elif o in ("-f", "--fields"):
                # Parse field specifications (e.g., "1,3-5,7")
                try:
                    fields.extend(self._parse_fields(a))
                except ValueError as e:
                    self.errorWrite(f"cut: {e}\n")
                    self.exit()
                    return
            elif o == "-s":
                only_delimited = True
            elif o == "--complement":
                complement = True
            elif o == "--help":
                self.help()
                self.exit()
                return
            elif o == "--version":
                self.version()
                self.exit()
                return

        if not fields and not complement:
            self.help()
            self.exit()
            return

        # Process input
        if args:
            # Process files
            for arg in args:
                if arg == "-":
                    self._process_input(self.input_data, delimiter, fields, complement, only_delimited)
                    continue

                pname = self.fs.resolve_path(arg, self.protocol.cwd)

                if self.fs.isdir(pname):
                    self.errorWrite(f"cut: {arg}: Is a directory\n")
                    continue

                try:
                    contents = self.fs.file_contents(pname)
                    self._process_input(contents, delimiter, fields, complement, only_delimited)
                except FileNotFound:
                    self.errorWrite(f"cut: {arg}: No such file or directory\n")
        else:
            # Process stdin
            self._process_input(self.input_data, delimiter, fields, complement, only_delimited)

        self.exit()

    def _parse_fields(self, field_spec: str) -> list[int | str]:
        """
        Parse field specification like "1,3-5,7" into a list of field numbers and range markers
        """
        fields = []
        parts = field_spec.split(",")

        for part in parts:
            part = part.strip()
            if "-" in part:
                # Range like "3-5" or "3-"
                try:
                    range_parts = part.split("-", 1)
                    start_str = range_parts[0]
                    end_str = range_parts[1] if len(range_parts) > 1 else ""

                    if not start_str and not end_str:
                        raise ValueError(f"invalid field value: {part}")

                    if start_str:
                        start = int(start_str)
                        if start < 1:
                            raise ValueError(f"fields are numbered from 1: {part}")
                    else:
                        start = 1

                    if end_str:
                        end = int(end_str)
                        if end < start:
                            raise ValueError(f"invalid range with no endpoint: {part}")
                        fields.extend(range(start, end + 1))
                    else:
                        # Open-ended range like "3-"
                        fields.append(f"{start}-")  # Special marker for open-ended range
                except ValueError as e:
                    if "invalid literal" in str(e):
                        raise ValueError(f"invalid field value: {part}")
                    raise
            else:
                # Single field like "7"
                try:
                    field_num = int(part)
                    if field_num < 1:
                        raise ValueError(f"fields are numbered from 1: {part}")
                    fields.append(field_num)
                except ValueError:
                    raise ValueError(f"invalid field value: {part}")

        return sorted(list(set(fields)), key=lambda x: (isinstance(x, str), x))  # Sort with strings after numbers

    def _process_input(
        self, input_data: bytes | None, delimiter: str, fields: list[int | str], complement: bool, only_delimited: bool
    ) -> None:
        """
        Process input data according to cut parameters
        """
        if not input_data:
            return

        try:
            text = input_data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            # If we can't decode, treat as binary and split by delimiter directly
            lines = input_data.split(b"\n")
            for line in lines:
                if line:  # Skip empty lines
                    parts = line.split(delimiter.encode())
                    # Convert bytes to strings for processing
                    str_parts = [part.decode("utf-8", errors="ignore") for part in parts]
                    self._process_line(str_parts, fields, complement, only_delimited)
            return

        lines = text.split("\n")
        for line in lines:
            if not line and lines.index(line) == len(lines) - 1:  # Skip trailing empty line
                continue

            # Split line by delimiter
            if delimiter == "\t":
                parts = line.split("\t")
            else:
                parts = line.split(delimiter)

            self._process_line(parts, fields, complement, only_delimited)

    def _process_line(self, parts: list[str], fields: list[int | str], complement: bool, only_delimited: bool) -> None:
        """
        Process a single line according to cut parameters
        """
        # Skip lines without delimiter if -s option is used
        if only_delimited and len(parts) == 1:
            return

        if complement:
            # Select fields that are NOT in the specified fields list
            selected_parts = []
            for i, part in enumerate(parts, 1):
                if not any(self._field_matches(i, field) for field in fields):
                    selected_parts.append(part)
        else:
            # Select specified fields
            selected_parts = []
            for field in fields:
                if isinstance(field, int):
                    if 1 <= field <= len(parts):
                        selected_parts.append(parts[field - 1])
                elif isinstance(field, str) and field.endswith("-"):
                    # Open-ended range like "3-"
                    start = int(field[:-1])
                    selected_parts.extend(parts[start - 1 :])

        # Output the selected parts joined by space (standard cut behavior)
        if selected_parts:
            self.write(f"{' '.join(selected_parts)}\n")

    def _field_matches(self, position: int, field: int | str) -> bool:
        """
        Check if a field specification matches a position
        """
        if isinstance(field, int):
            return position == field
        elif isinstance(field, str) and field.endswith("-"):
            start = int(field[:-1])
            return position >= start
        return False

    def help(self) -> None:
        self.write("""Usage: cut OPTION... [FILE]...
Print selected parts of lines from each FILE to standard output.

With no FILE, or when FILE is -, read standard input.

Mandatory arguments to long options are mandatory for short options too.
  -b, --bytes=LIST        select only these bytes
  -c, --characters=LIST   select only these characters
  -d, --delimiter=DELIM   use DELIM instead of TAB for field delimiter
  -f, --fields=LIST       select only these fields;  also print any line
                            that contains no delimiter character, unless
                            the -s option is specified
      --complement        complement the set of selected bytes, characters
                            or fields
  -s, --only-delimited    do not print lines not containing delimiters
      --output-delimiter=STRING  use STRING as the output delimiter
                            the default is to use the input delimiter
      --help     display this help and exit
      --version  output version information and exit

Use one, and only one of -b, -c or -f.  Each LIST is made up of one
range, or many ranges separated by commas.  Selected input is written
in the same order that it is read, and is written exactly once.
Each range is one of:

  N     N'th byte, character or field, counted from 1
  N-    from N'th byte, character or field, to end of line
  N-M   from N'th to M'th (included) byte, character or field
  -M    from first to M'th (included) byte, character or field

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/cut>
or available locally via: info '(coreutils) cut invocation'
""")

    def version(self) -> None:
        self.write("""cut (GNU coreutils) 8.32
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by David M. Ihnat, David MacKenzie, and Jim Meyering.
""")


commands["/usr/bin/cut"] = Command_cut
commands["cut"] = Command_cut
