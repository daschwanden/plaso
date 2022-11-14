#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This file contains the tests for the generic text parser."""

import codecs
import unittest

import pyparsing

from dfvfs.file_io import fake_file_io
from dfvfs.path import fake_path_spec
from dfvfs.resolver import context as dfvfs_context

from plaso.lib import errors
from plaso.parsers import text_parser

from tests.parsers import test_lib


class TestPyparsingMultiLineTextParser(
    text_parser.PyparsingMultiLineTextParser):
  """Multi-line PyParsing-based text parser for testing purposes."""

  NAME = 'test'

  _ENCODING = 'utf-8'

  _LINE = pyparsing.Regex('.*') + pyparsing.lineEnd()

  _LINE_STRUCTURES = [('line', _LINE)]

  def _ParseRecord(self, parser_mediator, key, structure):
    """Parses a pyparsing structure.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfVFS.
      key (str): name of the parsed structure.
      structure (pyparsing.ParseResults): tokens from a parsed log line.

    Raises:
      ParseError: when the structure type is unknown.
    """
    return

  def CheckRequiredFormat(self, parser_mediator, text_reader):
    """Check if the log record has the minimal structure required by the parser.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfVFS.
      text_reader (EncodedTextReader): text reader.

    Returns:
      bool: True if this is the correct parser, False otherwise.
    """
    return True


class EncodedTextReaderTest(test_lib.ParserTestCase):
  """Tests for encoded text reader."""

  _TEST_LINES ='\n'.join([
      'Multiple lines',
      'of text',
      'in a single',
      'file.'])

  _TEST_DATA = _TEST_LINES.encode('utf-8')

  def _EncodingErrorHandler(self, exception):
    """Encoding error handler.

    Args:
      exception [UnicodeDecodeError]: exception.

    Returns:
      tuple[str, int]: replacement string and number of bytes to skip.

    Raises:
      TypeError: if exception is not of type UnicodeDecodeError.
    """
    if not isinstance(exception, UnicodeDecodeError):
      raise TypeError('Unsupported exception type.')

    # pylint: disable=attribute-defined-outside-init
    self._encoding_errors.append(
        (exception.start, exception.object[exception.start]))
    escaped = '\\x{0:2x}'.format(exception.object[exception.start])
    return (escaped, exception.start + 1)

  def testReadLine(self):
    """Tests the ReadLine function."""
    resolver_context = dfvfs_context.Context()

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    file_object = fake_file_io.FakeFile(
        resolver_context, test_path_spec, self._TEST_DATA)
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object)

    line = text_reader.ReadLine()
    self.assertEqual(line, 'Multiple lines')

    line = text_reader.ReadLine()
    self.assertEqual(line, 'of text')

  def testReadLines(self):
    """Tests the ReadLines function."""
    resolver_context = dfvfs_context.Context()

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    file_object = fake_file_io.FakeFile(
        resolver_context, test_path_spec, self._TEST_DATA)
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object)

    text_reader.ReadLines()
    self.assertEqual(text_reader.lines, self._TEST_LINES)

  def testReadLineOfText(self):
    """Tests the _ReadLineOfText function."""
    resolver_context = dfvfs_context.Context()

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    data = b'This is another file.'
    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, data)
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object, encoding='utf-8')

    line = text_reader.ReadLineOfText()
    self.assertEqual(line, 'This is another file.')

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    data = b'This is an\xbather file.'
    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, data)
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object, encoding='utf8')

    with self.assertRaises(UnicodeDecodeError):
      text_reader.ReadLineOfText()

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    data = b'This is an\xbather file.'
    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, data)
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(
        file_object, encoding='utf8', encoding_errors='replace')

    line = text_reader.ReadLineOfText()
    self.assertEqual(line, 'This is an\ufffdther file.')

    # pylint: disable=attribute-defined-outside-init
    self._encoding_errors = []
    codecs.register_error('test_handler', self._EncodingErrorHandler)

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    data = b'This is an\xbather file.'
    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, data)
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(
        file_object, encoding='utf8', encoding_errors='test_handler')

    line = text_reader.ReadLineOfText()
    self.assertEqual(line, 'This is an\\xbather file.')

    self.assertEqual(len(self._encoding_errors), 1)
    self.assertEqual(self._encoding_errors[0], (10, 0xba))

  def testSkipAhead(self):
    """Tests the SkipAhead function."""
    resolver_context = dfvfs_context.Context()

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    file_object = fake_file_io.FakeFile(
        resolver_context, test_path_spec, self._TEST_DATA)
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object)

    text_reader.SkipAhead(10)
    self.assertEqual(text_reader.lines, self._TEST_LINES[10:])


class SingleLineTextParserTest(test_lib.ParserTestCase):
  """Tests for the single-line text parser."""

  # TODO: add tests for ParseFileObject


class PyparsingMultiLineTextParserTest(test_lib.ParserTestCase):
  """Tests for the multi-line PyParsing-based text parser."""

  # pylint: disable=protected-access

  # TODO: add tests for _GetValueFromStructure

  # TODO: add tests for _ParseLineStructure

  def testParseFileObject(self):
    """Tests the ParseFileObject function."""
    storage_writer = self._CreateStorageWriter()
    parser_mediator = self._CreateParserMediator(storage_writer)
    resolver_context = dfvfs_context.Context()

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    data = b'This is another file.\nWith two lines.\n'
    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, data)
    file_object.Open()

    test_parser = TestPyparsingMultiLineTextParser()
    test_parser.ParseFileObject(parser_mediator, file_object)

    # The test parser does not generate events.
    number_of_events = storage_writer.GetNumberOfAttributeContainers('event')
    self.assertEqual(number_of_events, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    storage_writer = self._CreateStorageWriter()
    parser_mediator = self._CreateParserMediator(storage_writer)

    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')
    data = b'This is another file.\nWith tw\xba lines.\n'
    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, data)
    file_object.Open()

    test_parser = TestPyparsingMultiLineTextParser()

    with self.assertRaises(errors.WrongParser):
      test_parser.ParseFileObject(parser_mediator, file_object)


if __name__ == '__main__':
  unittest.main()
