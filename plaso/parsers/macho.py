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
    name (str): name of the file.
    size (int): size of the file.
  """

  DATA_TYPE = 'macos:macho:file'

  def __init__(self):
    """Initializes event data."""
    super(MachoFileEventData, self).__init__(data_type=self.DATA_TYPE)
    self.name = None
    self.size = None

class MachoParser(interface.FileEntryParser, dtfabric_helper.DtFabricHelper):
  """Parser for Macho files."""

  NAME = 'macho'
  DATA_FORMAT = 'Mach-O file'

  #_DEFINITION_FILE = os.path.join(
  #    os.path.dirname(__file__), 'macho.yaml')

  @classmethod
  def GetFormatSpecification(cls):
    """Retrieves the format specification."""
    format_specification = specification.FormatSpecification(cls.NAME)
    format_specification.AddNewSignature(b'\xca\xfe\xba\xbe', offset=0)
    format_specification.AddNewSignature(b'\xce\xfa\xed\xfe', offset=0)
    format_specification.AddNewSignature(b'\xcf\xfa\xed\xfe', offset=0)
    return format_specification

  def ParseFileEntry(self, parser_mediator, file_entry):
    """Parses a Mach-O file entry.

    Args:
      parser_mediator (ParserMediator): parser mediator.
      file_entry (dfvfs.FileEntry): file entry to be parsed.
    """    
    filename = parser_mediator.GetFilename()
    relative_path = parser_mediator.GetRelativePath()
    print(filename)
    print(relative_path)

    macho_binary = lief.MachO.parse(relative_path, config=lief.MachO.ParserConfig.quick)
    #print(macho_binary)

    event_data = MachoFileEventData()    
    event_data.name = filename
    event_data.size = file_entry.size
    parser_mediator.ProduceEventData(event_data)

manager.ParsersManager.RegisterParser(MachoParser)
