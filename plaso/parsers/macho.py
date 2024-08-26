# -*- coding: utf-8 -*-
"""Parser for Mach-O files."""

import lief
import os

from dfvfs.helpers import data_slice as dfvfs_data_slice

from plaso.lib import dtfabric_helper
from plaso.lib import specification
from plaso.parsers import interface
from plaso.parsers import manager


class MachoParser(interface.FileObjectParser, dtfabric_helper.DtFabricHelper):
  """Parser for Macho files."""

  NAME = 'macho'
  DATA_FORMAT = 'Mach-O file'

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'macho.yaml')

  def ParseFileObject(self, parser_mediator, file_object, **kwargs):
    """Parses a Macho-O file.

    Args:
      parser_mediator (ParserMediator): parser mediator.
      file_object (dfvfs.FileIO): file-like object to be parsed.

    Raises:
      WrongParser: when the format is not supported by the parser, this will
          signal the event extractor to apply other parsers.
    """

  @classmethod
  def GetFormatSpecification(cls):
    """Retrieves the format specification."""
    format_specification = specification.FormatSpecification(cls.NAME)
    format_specification.AddNewSignature(b'\xca\xfe\xba\xbe', offset=0)
    format_specification.AddNewSignature(b'\xce\xfa\xed\xfe', offset=0)
    format_specification.AddNewSignature(b'\xcf\xfa\xed\xfe', offset=0)
    return format_specification
  
  def ParseFileObject(self, parser_mediator, file_object):
    """Parses a Mach-O file-like object.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfVFS.
      file_object (dfvfs.FileIO): a file-like object.

    Raises:
      WrongParser: when the file cannot be parsed.
    """
    macho_data_slice = dfvfs_data_slice.DataSlice(file_object)
    print(macho_data_slice.__len__())
    try:
      macho_binary = lief.MachO.parse(raw=macho_data_slice, config=lief.MachO.ParserConfig.deep)
    except Exception as exception:
      raise errors.WrongParser(
          'Unable to read Mach-O file with error: {0!s}'.format(exception))
    print('++++++++++++++++++')

manager.ParsersManager.RegisterParser(MachoParser)
