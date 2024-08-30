# -*- coding: utf-8 -*-
"""Parser for Mach-O files."""

import lief
import os

from dfvfs.helpers import data_slice as dfvfs_data_slice

from plaso.analyzers.hashers import entropy
from plaso.analyzers.hashers import md5
from plaso.analyzers.hashers import sha256
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
    entropy (str): entropy of the binary.
    md5 (str): md5 of the binary.
    sha256 (str): sha256 of the binary.
    segment_names (list[str]): names of the sections in the Mach-O file.
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
    self.entropy = None
    self.md5 = None
    self.sha256 = None
    self.segment_names = None

class MachoParser(interface.FileEntryParser, dtfabric_helper.DtFabricHelper):
  """Parser for Macho files."""
  NAME = 'macho'
  DATA_FORMAT = 'Mach-O file'

  _DEFAULT_READ_SIZE = 512

  _MAGIC_MULTI_SIGNATURE = b'\xca\xfe\xba\xbe'
  _MAGIC_32_SIGNATURE = b'\xce\xfa\xed\xfe'
  _MAGIC_64_SIGNATURE = b'\xcf\xfa\xed\xfe'

  #_DEFINITION_FILE = os.path.join(
  #    os.path.dirname(__file__), 'macho.yaml')

  def _GetDigest(self, hasher, file_entry, offset, size):
    """Executes a hasher and returns the digest.
    Args:
      hasher (BaseHasher): hasher to execute.
      file_entry (dfvfs.file_entry): file entry to be hashed.
      offset (int): offset in file entry from where to read.
      size (int): amount of bytes to read.

     Returns:
      digest (str): digest returned by hasher.
    """
    file_object = file_entry.GetFileObject()

    # Make sure we are starting from the beginning of the file.
    file_object.seek(offset, os.SEEK_SET)

    data = file_object.read(size)
    hasher.Update(data)

    return hasher.GetStringDigest()

  def _GetSectionNames(self, segment):
    """Retrieves Mach-O segment section names.
    Args:
      segment (lief.MachO.SegmentCommand): binary to be parsed.

    Returns:
      list[str]: names of the segments.
    """
    section_names = []
    for section in segment.sections:
      #print('  ' + str(section.name))
      section_names.append(section.name)
    return section_names

  def _GetSegmentNames(self, binary):
    """Retrieves Mach-O segment names.
    Args:
      binary (lief.MachO.Binary): binary to be parsed.

    Returns:
      list[str]: names of the segments.
    """
    segment_names = []
    for segment in binary.segments:
      section_names = []
      print(segment.name)
      segment_names.append(segment.name)
      section_names = self._GetSectionNames(binary)
      # TODO: How do we want to surface the section names
    return segment_names

  def _ParseFatMachoBinary(self, parser_mediator, fat_binary, file_name, file_entry):
    """Parses a Mach-O fat binary.
    Args:
      parser_mediator (ParserMediator): parser mediator.
      fat_binary (lief.MachO.FatBinary): fat binary to be parsed.
      file_name (str): file name of the fat binary.
      file_entry (dfvfs.FileEntry): file entry to be parsed.
    """
    print('---------- start fat binary ------------')
    print('size: ' + str (file_entry.size))
    ent = self._GetDigest(entropy.EntropyHasher(), file_entry, 0, file_entry.size)
    md5_hash = self._GetDigest(md5.MD5Hasher(), file_entry, 0, file_entry.size)
    sha256_hash = self._GetDigest(sha256.SHA256Hasher(), file_entry, 0, file_entry.size)
    print('entropy: ' + str(ent))
    print('md5: ' + str(md5_hash))
    print('sha256: ' + str(sha256_hash))

    event_data = MachoFileEventData()    
    event_data.name = file_name
    event_data.num_binaries = fat_binary.size
    event_data.size = file_entry.size
    event_data.entropy = ent
    event_data.md5 = md5_hash
    event_data.sha256 = sha256_hash
    parser_mediator.ProduceEventData(event_data)
    print('----------- end fat binary -------------')

    for binary in fat_binary:
      self._ParseMachoBinary(parser_mediator, binary, file_name, file_entry)

  def _ParseMachoBinary(self, parser_mediator, binary, file_name, file_entry):
    """Parses a Mach-O binary.
    Args:
      parser_mediator (ParserMediator): parser mediator.
      binary (lief.MachO.Binary): binary to be parsed.
      filename (str): file name of the binary.
      file_entry (dfvfs.FileEntry): file entry to be parsed.
    """
    print('------------ start binary --------------')
    print(binary.header.cpu_type)
    fat_offset = binary.fat_offset
    original_size = binary.original_size
    print('fat offset: ' + str(fat_offset))
    print('size: ' + str (original_size))
    ent = self._GetDigest(entropy.EntropyHasher(), file_entry, fat_offset, original_size)
    md5_hash = self._GetDigest(md5.MD5Hasher(), file_entry, fat_offset, original_size)
    sha256_hash = self._GetDigest(sha256.SHA256Hasher(), file_entry, fat_offset, original_size)
    print('entropy: ' + str(ent))
    print('md5: ' + str(md5_hash))
    print('sha256: ' + str(sha256_hash))

    event_data = MachoFileEventData()    
    event_data.name = file_name
    event_data.num_binaries = 1
    event_data.cpu_type = binary.header.cpu_type.value
    event_data.cpu_subtype = binary.header.cpu_subtype
    event_data.entropy = ent
    event_data.md5 = md5_hash
    event_data.sha256 = sha256_hash
    if binary.has_code_signature:
      # TODO: Do something useful with the signarure
      # print(binary.code_signature.content.tobytes())
      print('signature size: ' + str(binary.code_signature.data_size))
    event_data.segment_names = self._GetSegmentNames(binary)
    parser_mediator.ProduceEventData(event_data)
    print('------------- end binary ---------------')


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
    #print(file_name)
    print(relative_path)

    macho_binary = lief.MachO.parse(relative_path, config=lief.MachO.ParserConfig.quick)
    #print(macho_binary)

    if isinstance(macho_binary, lief.MachO.FatBinary):
      self._ParseFatMachoBinary(parser_mediator, macho_binary, file_name, file_entry)
    elif isinstance(macho_binary, lief.MachO.Binary):
      self._ParseMachoBinary(parser_mediator, macho_binary, file_name, file_entry)

manager.ParsersManager.RegisterParser(MachoParser)