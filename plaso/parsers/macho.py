# -*- coding: utf-8 -*-
"""Parser for Mach-O files."""

import lief
import os

from dfvfs.helpers import data_slice as dfvfs_data_slice

from plaso.containers import events
from plaso.lib import dtfabric_helper
from plaso.lib import specification
from plaso.parsers import interface
from plaso.parsers import manager

class MachoFileEventData(events.EventData):
  """Mach-O file event data.
  Attributes:
    name (str): name of the binary.
    num_binary (int): amount of binaries.
    size (int): size of the binary.
    cpu_type (int): cpu type of the binary.
    cpu_subtype (int): cpu subtype of the binary.
    signature (int): signature of the binary.
  """

  DATA_TYPE = 'macos:macho:file'

  def __init__(self):
    """Initializes event data."""
    super(MachoFileEventData, self).__init__(data_type=self.DATA_TYPE)
    self.name = None
    self.num_binaries = None
    self.size = None
    self.cpu_type = None
    self.cpu_subtype = None
    self.signature = None

class MachoParser(interface.FileEntryParser, dtfabric_helper.DtFabricHelper):
  """Parser for Macho files."""
  NAME = 'macho'
  DATA_FORMAT = 'Mach-O file'

  _MAGIC_MULTI_SIGNATURE = b'\xca\xfe\xba\xbe'
  _MAGIC_32_SIGNATURE = b'\xce\xfa\xed\xfe'
  _MAGIC_64_SIGNATURE = b'\xcf\xfa\xed\xfe'

  #_DEFINITION_FILE = os.path.join(
  #    os.path.dirname(__file__), 'macho.yaml')

  def _ParseFatMachoBinary(self, parser_mediator, fat_binary, file_name, file_size):
    """Parses a Mach-O fat binary.
    Args:
      parser_mediator (ParserMediator): parser mediator.
      fat_binary (lief.FatBinary): fat binary to be parsed.
      file_name (str): file name of the fat binary.
      file_size (int): file size of the fat binary.
    """
    event_data = MachoFileEventData()    
    event_data.name = file_name
    event_data.num_binaries = fat_binary.size
    event_data.size = file_size
    parser_mediator.ProduceEventData(event_data)

    for binary in fat_binary:
      self._ParseMachoBinary(parser_mediator, binary, file_name)

  def _ParseMachoBinary(self, parser_mediator, binary, file_name):
    """Parses a Mach-O binary.
    Args:
      parser_mediator (ParserMediator): parser mediator.
      binary (lief.Binary): binary to be parsed.
      filename (str): file name
    """
    print(binary.header.cpu_type)
    event_data = MachoFileEventData()    
    event_data.name = file_name
    event_data.num_binaries = 1
    event_data.cpu_type = binary.header.cpu_type.value
    event_data.cpu_subtype = binary.header.cpu_subtype
    if binary.has_code_signature:
      # TODO: Do something useful with the signarure
      # print(binary.code_signature.content.tobytes())
      print(binary.code_signature.data_size)
    parser_mediator.ProduceEventData(event_data)

  @classmethod
  def GetFormatSpecification(cls):
    """Retrieves the format specification."""
    format_specification = specification.FormatSpecification(cls.NAME)
    format_specification.AddNewSignature(cls._MAGIC_MULTI_SIGNATURE, offset=0)
    format_specification.AddNewSignature(cls._MAGIC_32_SIGNATURE, offset=0)
    format_specification.AddNewSignature(cls._MAGIC_64_SIGNATURE, offset=0)
    return format_specification

  def ParseFileEntry(self, parser_mediator, file_entry):
    """Parses a Mach-O file entry.
    Args:
      parser_mediator (ParserMediator): parser mediator.
      file_entry (dfvfs.FileEntry): file entry to be parsed.
    """    
    file_name = parser_mediator.GetFilename()
    relative_path = parser_mediator.GetRelativePath()
    print(file_name)
    print(relative_path)

    macho_binary = lief.MachO.parse(relative_path, config=lief.MachO.ParserConfig.quick)
    #print(macho_binary)

    if isinstance(macho_binary, lief.MachO.FatBinary):
      self._ParseFatMachoBinary(parser_mediator, macho_binary, file_name, file_entry.size)
    elif isinstance(macho_binary, lief.MachO.Binary):
      self._ParseMachoBinary(parser_mediator, macho_binary, file_name)

manager.ParsersManager.RegisterParser(MachoParser)