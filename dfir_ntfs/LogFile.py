# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with the $LogFile journal.

import struct
import io
import shutil
import binascii

UPDATE_SEQUENCE_STRIDE = 512
PAGE_SIZE = 4096 # This is the size of a single memory page.

CLUSTER_SIZE_DEFAULT = 4096
FILE_RECORD_SEGMENT_SIZE_DEFAULT = 1024

# Values for the restart area:
LFS_NO_CLIENT = 0xFFFF # No index in the array of client records.

# Flags for the restart area:
RESTART_SINGLE_PAGE_IO = 0x1 # Log entries are written one by one.
RESTART_UNKNOWN_NAME_2 = 0x2 # The new restart area has been written to the log file.

# Flags for the log record page:
LOG_PAGE_LOG_RECORD_END = 0x1 # This page contains the end of a log record.
LOG_PAGE_UNKNOWN_2 = 0x2 # This page contains a client restart area (set when the log file version is 2.0 or higher).

# Flags for the log record header:
LOG_RECORD_MULTI_PAGE = 0x1 # This record was written to multiple pages.
LOG_RECORD_UNKNOWN_NAME_2 = 0x2 # This record contains no redo buffer.
LOG_RECORD_UNKNOWN_NAME_4 = 0x4 # This record contains no undo buffer.

# Values for the log record types:
LfsClientRecord = 0x1
LfsClientRestart = 0x2

# Operations for the NTFS client:
Noop = 0x00
CompensationLogRecord = 0x01
InitializeFileRecordSegment = 0x02 # [1]
DeallocateFileRecordSegment = 0x03 # [1]
WriteEndOfFileRecordSegment = 0x04 # [1]
CreateAttribute = 0x05 # [1]
DeleteAttribute = 0x06 # [1]
UpdateResidentValue = 0x07 # [1]
UpdateNonresidentValue = 0x08 # [2]
UpdateMappingPairs = 0x09 # [1]
DeleteDirtyClusters = 0x0A
SetNewAttributeSizes = 0x0B # [1]
AddIndexEntryRoot = 0x0C # [1]
DeleteIndexEntryRoot = 0x0D # [1]
AddIndexEntryAllocation = 0x0E # [2]
DeleteIndexEntryAllocation = 0x0F # [2]
WriteEndOfIndexBuffer = 0x10 # [2]
SetIndexEntryVcnRoot = 0x11 # [1]
SetIndexEntryVcnAllocation = 0x12 # [2]
UpdateFileNameRoot = 0x13 # [1]
UpdateFileNameAllocation = 0x14 # [2]
SetBitsInNonresidentBitMap = 0x15 # [2]
ClearBitsInNonresidentBitMap = 0x16 # [2]
HotFix = 0x17
EndTopLevelAction = 0x18
PrepareTransaction = 0x19
CommitTransaction = 0x1A
ForgetTransaction = 0x1B
OpenNonresidentAttribute = 0x1C
OpenAttributeTableDump = 0x1D
AttributeNamesDump = 0x1E
DirtyPageTableDump = 0x1F
TransactionTableDump = 0x20
UpdateRecordDataRoot = 0x21 # [1]
UpdateRecordDataAllocation = 0x22 # [2]
UpdateRelativeDataIndex = 0x23 # [1]
UpdateRelativeDataAllocation = 0x24 # [2]
ZeroEndOfFileRecord = 0x25 # [1]

# [1]: this is an update to the resident ($MFT) data.

LOGGED_RESIDENT_UPDATES = [ InitializeFileRecordSegment, DeallocateFileRecordSegment, WriteEndOfFileRecordSegment, CreateAttribute, DeleteAttribute, UpdateResidentValue, UpdateMappingPairs, SetNewAttributeSizes, AddIndexEntryRoot, DeleteIndexEntryRoot, SetIndexEntryVcnRoot, UpdateFileNameRoot, UpdateRecordDataRoot, UpdateRelativeDataIndex, ZeroEndOfFileRecord ]

# [2]: this is an update to the nonresident data (which is referenced by an entry in the open attribute table).

LOGGED_NONRESIDENT_UPDATES = [ UpdateNonresidentValue, AddIndexEntryAllocation, DeleteIndexEntryAllocation, WriteEndOfIndexBuffer, SetIndexEntryVcnAllocation, UpdateFileNameAllocation, SetBitsInNonresidentBitMap, ClearBitsInNonresidentBitMap, UpdateRecordDataAllocation, UpdateRelativeDataAllocation ]

NTFSOperations = {
	Noop: 'Noop',
	CompensationLogRecord: 'CompensationLogRecord',
	InitializeFileRecordSegment: 'InitializeFileRecordSegment',
	DeallocateFileRecordSegment: 'DeallocateFileRecordSegment',
	WriteEndOfFileRecordSegment: 'WriteEndOfFileRecordSegment',
	CreateAttribute: 'CreateAttribute',
	DeleteAttribute: 'DeleteAttribute',
	UpdateResidentValue: 'UpdateResidentValue',
	UpdateNonresidentValue: 'UpdateNonresidentValue',
	UpdateMappingPairs: 'UpdateMappingPairs',
	DeleteDirtyClusters: 'DeleteDirtyClusters',
	SetNewAttributeSizes: 'SetNewAttributeSizes',
	AddIndexEntryRoot: 'AddIndexEntryRoot',
	DeleteIndexEntryRoot: 'DeleteIndexEntryRoot',
	AddIndexEntryAllocation: 'AddIndexEntryAllocation',
	DeleteIndexEntryAllocation: 'DeleteIndexEntryAllocation',
	WriteEndOfIndexBuffer: 'WriteEndOfIndexBuffer',
	SetIndexEntryVcnRoot: 'SetIndexEntryVcnRoot',
	SetIndexEntryVcnAllocation: 'SetIndexEntryVcnAllocation',
	UpdateFileNameRoot: 'UpdateFileNameRoot',
	UpdateFileNameAllocation: 'UpdateFileNameAllocation',
	SetBitsInNonresidentBitMap: 'SetBitsInNonresidentBitMap',
	ClearBitsInNonresidentBitMap: 'ClearBitsInNonresidentBitMap',
	HotFix: 'HotFix',
	EndTopLevelAction: 'EndTopLevelAction',
	PrepareTransaction: 'PrepareTransaction',
	CommitTransaction: 'CommitTransaction',
	ForgetTransaction: 'ForgetTransaction',
	OpenNonresidentAttribute: 'OpenNonresidentAttribute',
	OpenAttributeTableDump: 'OpenAttributeTableDump',
	AttributeNamesDump: 'AttributeNamesDump',
	DirtyPageTableDump: 'DirtyPageTableDump',
	TransactionTableDump: 'TransactionTableDump',
	UpdateRecordDataRoot: 'UpdateRecordDataRoot',
	UpdateRecordDataAllocation: 'UpdateRecordDataAllocation',
	UpdateRelativeDataIndex: 'UpdateRelativeDataIndex',
	UpdateRelativeDataAllocation: 'UpdateRelativeDataAllocation',
	ZeroEndOfFileRecord: 'ZeroEndOfFileRecord'
}

def ResolveNTFSOperation(NTFSOperationCode):
	"""Convert an NTFS operation code to a string."""

	if NTFSOperationCode in NTFSOperations.keys():
		return NTFSOperations[NTFSOperationCode]

	return hex(NTFSOperationCode)

def UnprotectSectors(Buffer):
	"""Apply an update sequence array (USA) to multiple sectors (as a bytearray object) and return the (resulting buffer, end_of_usa_offset) tuple."""

	if len(Buffer) < 2 * UPDATE_SEQUENCE_STRIDE or len(Buffer) % UPDATE_SEQUENCE_STRIDE != 0:
		raise UpdateSequenceArrayException('Invalid input (not two or more sectors)')

	usa_offset, usa_size = struct.unpack('<HH', Buffer[4 : 8])

	if usa_offset < 8 or usa_offset > UPDATE_SEQUENCE_STRIDE - 6:
		raise UpdateSequenceArrayException('Invalid update sequence array offset: {}'.format(usa_offset))

	if usa_size < 2 or (usa_size - 1) * UPDATE_SEQUENCE_STRIDE != len(Buffer):
		raise UpdateSequenceArrayException('Invalid update sequence array size: {}'.format(usa_size))

	if usa_offset + usa_size * 2 >= len(Buffer):
		raise UpdateSequenceArrayException('Invalid update sequence array offset and size: {}, {}'.format(usa_offset, usa_size))

	if Buffer[usa_offset + 4 : usa_offset + 8] == b'CRC4': # Check if integrity of data in this block is protected using the CRC32 value (for DAX volumes).
		crc32_recorded_raw = Buffer[usa_offset : usa_offset + 4]
		crc32_recorded = struct.unpack('<L', crc32_recorded_raw)[0]

		buffer_modified = Buffer[:]
		buffer_modified[usa_offset : usa_offset + usa_size * 2] = b'\x00' * (usa_size * 2)

		crc32_calculated = binascii.crc32(buffer_modified)

		if crc32_recorded == crc32_calculated:
			end_of_usa_offset = usa_offset + usa_size * 2
			return (Buffer, end_of_usa_offset)

		# If the checksum value is invalid, treat this block as a usual one.

	sequence_number_in_usa_bytes = Buffer[usa_offset : usa_offset + 2]

	i = 1 # Skip the first element (sequence_number_in_usa_bytes).
	while i < usa_size:
		offset_in_usa = i * 2
		update_bytes = Buffer[usa_offset + offset_in_usa : usa_offset + offset_in_usa + 2]

		offset_in_buf = i * UPDATE_SEQUENCE_STRIDE - 2
		sequence_number_in_sector_bytes = Buffer[offset_in_buf : offset_in_buf + 2]

		if sequence_number_in_usa_bytes != sequence_number_in_sector_bytes:
			raise UpdateSequenceArrayException('Invalid sequence number in the buffer, relative offset: {}'.format(offset_in_buf))

		Buffer[offset_in_buf] = update_bytes[0]
		Buffer[offset_in_buf + 1] = update_bytes[1]

		i += 1

	end_of_usa_offset = usa_offset + usa_size * 2
	return (Buffer, end_of_usa_offset)

class LogFileException(Exception):
	"""This is a top-level exception for this module."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class UpdateSequenceArrayException(LogFileException):
	"""This exception is raised when something is wrong with an update sequence array."""

	pass

class RestartPageException(LogFileException):
	"""This exception is raised when something is wrong with a restart page."""

	pass

class EmptyLogFileException(RestartPageException):
	"""This exception is raised when the log file is empty."""

	pass

class RestartAreaException(LogFileException):
	"""This exception is raised when something is wrong with a restart area."""

	pass

class ClientRecordException(LogFileException):
	"""This exception is raised when something is wrong with a client record."""

	pass

class LogRecordPageException(LogFileException):
	"""This exception is raised when something is wrong with a log record page."""

	pass

class ClientException(LogFileException):
	"""This exception is raised when something is wrong with client data."""

	pass

class RestartPage(object):
	"""This class is used to work with a restart page."""

	buf = None
	"""Data of this restart page with updates from an update sequence array (USA) applied."""

	def __init__(self, restart_page_raw):
		self.buf, __ = UnprotectSectors(bytearray(restart_page_raw))

		signature = self.buf[: 4]
		if signature not in [ b'RSTR', b'CHKD', b'BAAD' ]:
			raise RestartPageException('Invalid signature: {}'.format(signature))

		major_version = self.get_major_version()
		minor_version = self.get_minor_version()

		if (major_version, minor_version) not in [ (1, 1), (2, 0), (3, 0) ]:
			version_str = '{}.{}'.format(major_version, minor_version)
			raise NotImplementedError('Version not supported: {}'.format(version_str))

		system_page_size = self.get_system_page_size()
		if system_page_size < 1024 or system_page_size % 512 != 0:
			raise RestartPageException('Invalid system page size: {}'.format(system_page_size))

		if system_page_size != PAGE_SIZE:
			raise NotImplementedError('The following system page size is not supported: {}'.format(system_page_size))

		log_page_size = self.get_log_page_size()
		if log_page_size < 1024 or log_page_size % 512 != 0:
			raise RestartPageException('Invalid log page size: {}'.format(log_page_size))

		if log_page_size != PAGE_SIZE:
			raise NotImplementedError('The following log page size is not supported: {}'.format(log_page_size))

		restart_offset = self.get_restart_offset()
		if restart_offset == 0 or restart_offset % 8 != 0 or restart_offset >= len(self.buf) or restart_offset >= system_page_size:
			raise RestartPageException('Invalid restart offset: {}'.format(restart_offset))

	def get_chkdsk_lsn(self):
		"""Get and return the last log sequence number (LSN) found during the chkdsk scan."""

		return struct.unpack('<Q', self.buf[8 : 16])[0]

	def get_system_page_size(self):
		"""Get and return the system page size. This is the size of a restart page."""

		return struct.unpack('<L', self.buf[16 : 20])[0]

	def get_log_page_size(self):
		"""Get and return the log page size. This is the size of a log record page."""

		return struct.unpack('<L', self.buf[20 : 24])[0]

	def get_restart_offset(self):
		"""Get and return the restart area offset (relative from the start of this structure)."""

		return struct.unpack('<H', self.buf[24 : 26])[0]

	def get_restart_area(self):
		"""Get, parse and return the restart area (as a RestartArea object)."""

		return RestartArea(self.buf[self.get_restart_offset() : ], self.get_system_page_size())

	def get_major_version(self):
		"""Get and return the major version of the log file."""

		return struct.unpack('<H', self.buf[28 : 30])[0]

	def get_minor_version(self):
		"""Get and return the minor version of the log file."""

		return struct.unpack('<H', self.buf[26 : 28])[0]

	def __str__(self):
		return 'RestartPage, version: {}.{}, system page size: {}, log page size: {}'.format(self.get_major_version(), self.get_minor_version(), self.get_system_page_size(), self.get_log_page_size())

class RestartArea(object):
	"""This class is used to work with a restart area."""

	buf = None
	"""Data of this restart area."""

	def __init__(self, restart_area_raw, system_page_size):
		self.buf = restart_area_raw

		client_array_offset = self.get_client_array_offset()
		if client_array_offset == 0 or client_array_offset % 8 != 0 or client_array_offset >= len(self.buf) or client_array_offset >= system_page_size:
			raise RestartAreaException('Invalid client array offset: {}'.format(client_array_offset))

		log_clients = self.get_log_clients()
		client_free_index = self.get_client_free_list()
		client_in_use_index = self.get_client_in_use_list()

		if client_free_index != LFS_NO_CLIENT and client_free_index >= log_clients:
			raise RestartAreaException('Invalid client index (free): {}'.format(client_free_index))

		if client_in_use_index != LFS_NO_CLIENT and client_in_use_index >= log_clients:
			raise RestartAreaException('Invalid client index (in-use): {}'.format(client_in_use_index))

	def get_current_lsn(self):
		"""Get and return the current log sequence number (LSN)."""

		return struct.unpack('<Q', self.buf[0 : 8])[0]

	def get_log_clients(self):
		"""Get and return the number of log clients."""

		return struct.unpack('<H', self.buf[8 : 10])[0]

	def get_client_free_list(self):
		"""Get and return the index of the free list of client records."""

		return struct.unpack('<H', self.buf[10 : 12])[0]

	def get_client_in_use_list(self):
		"""Get and return the index of the in-use list of client records."""

		return struct.unpack('<H', self.buf[12 : 14])[0]

	def get_flags(self):
		"""Get and return the flags (as an integer)."""

		return struct.unpack('<H', self.buf[14 : 16])[0]

	def get_sequence_number_bits(self):
		"""Get and return the number of bits to use for the sequence number."""

		return struct.unpack('<L', self.buf[16 : 20])[0]

	def get_restart_area_length(self):
		"""Get and return the size of this restart area."""

		return struct.unpack('<H', self.buf[20 : 22])[0]

	def get_client_array_offset(self):
		"""Get and return the offset to the array of client records (relative from the start of this structure)."""

		return struct.unpack('<H', self.buf[22 : 24])[0]

	def get_file_size(self):
		"""Get and return the log file size."""

		return struct.unpack('<q', self.buf[24 : 32])[0]

	def get_last_lsn_data_length(self):
		"""Get and return the size of data from the last log sequence number (LSN), excluding the header."""

		return struct.unpack('<L', self.buf[32 : 36])[0]

	def get_record_header_length(self):
		"""Get and return the size of the log page header."""

		return struct.unpack('<H', self.buf[36 : 38])[0]

	def get_log_page_data_offset(self):
		"""Get and return the log page data offset."""

		return struct.unpack('<H', self.buf[38 : 40])[0]

	def get_revision_number(self):
		"""Get and return the revision number for this area."""

		return struct.unpack('<L', self.buf[40 : 44])[0]

	def clients(self):
		"""This method yields client records (ClientRecord objects)."""

		i = 0
		while i < self.get_log_clients():
			curr_pos = i * ClientRecord.sizeof
			buf = self.buf[curr_pos + self.get_client_array_offset() : ]

			yield ClientRecord(buf)

			i += 1

	def __str__(self):
		return 'RestartArea, clients: {} (free index: {}, in-use index: {}), flags: {}, current LSN: {}, sequence number bits: {}'.format(self.get_log_clients(), hex(self.get_client_free_list()), hex(self.get_client_in_use_list()), hex(self.get_flags()), self.get_current_lsn(), self.get_sequence_number_bits())

class ClientRecord(object):
	"""This class is used to work with a client record."""

	buf = None
	"""Data of this client record."""

	sizeof = 160
	"""An allocated size of this record."""

	def __init__(self, client_record_raw):
		self.buf = client_record_raw

		client_name_length = self.get_client_name_length()
		if client_name_length > 128: # Do not cross the 'sizeof' boundary.
			raise ClientRecordException('Invalid name length: {}'.format(client_name_length))

	def get_oldest_lsn(self):
		"""Get and return the oldest log sequence number (LSN) required by this client."""

		return struct.unpack('<Q', self.buf[0 : 8])[0]

	def get_client_restart_lsn(self):
		"""Get and return the log sequence number (LSN) of the latest client restart area."""

		return struct.unpack('<Q', self.buf[8 : 16])[0]

	def get_prev_client(self):
		"""Get and return the index of the previous client record."""

		return struct.unpack('<H', self.buf[16 : 18])[0]

	def get_next_client(self):
		"""Get and return the index of the next client record."""

		return struct.unpack('<H', self.buf[18 : 20])[0]

	def get_sequence_number(self):
		"""Get and return the sequence number."""

		return struct.unpack('<H', self.buf[20 : 22])[0]

	def get_client_name_length(self):
		"""Get and return the name length for this client."""

		return struct.unpack('<L', self.buf[28 : 32])[0]

	def get_client_name(self):
		"""Get, decode and return the name of this client."""

		name_raw = self.buf[32 : 32 + self.get_client_name_length()]
		return name_raw.decode('utf-16le')

	def __str__(self):
		return 'ClientRecord, name: {}, oldest LSN: {}, client restart LSN: {}, sequence number: {}'.format(self.get_client_name(), self.get_oldest_lsn(), self.get_client_restart_lsn(), self.get_sequence_number())

class LogRecordPage(object):
	"""This class is used to work with a log record page."""

	buf = None
	"""Data of this log record page with updates from an update sequence array (USA) applied."""

	buf_protected = None
	"""Data of this log record page without updates from an update sequence array (USA) applied."""

	end_of_usa_offset = None
	"""Offset to the end of an update sequence array (USA) in the data."""

	data_offset = None
	"""Offset to the start of the log data."""

	page_number = None
	"""Number of this page in the log file."""

	def __init__(self, log_record_page_raw, log_page_number, data_offset):
		self.buf, self.end_of_usa_offset = UnprotectSectors(bytearray(log_record_page_raw))
		self.buf_protected = log_record_page_raw

		signature = self.buf[: 4]
		if signature not in [ b'RCRD', b'CHKD', b'BAAD' ]:
			raise LogRecordPageException('Invalid signature: {}'.format(signature))

		self.page_number = log_page_number

		if data_offset < 8 or data_offset < self.end_of_usa_offset or data_offset % 8 != 0:
			raise NotImplementedError('The following log data offset is invalid or not supported: {}'.format(data_offset))

		self.data_offset = data_offset

	def get_last_lsn(self):
		"""Get and return the highest log sequence number (LSN) in this page."""

		return struct.unpack('<Q', self.buf[8 : 16])[0]

	def get_file_offset_11(self):
		"""Get and return the log file offset for a tail copy. The log file version should be 1.1. This field is not valid for regular log record pages."""

		return struct.unpack('<q', self.buf[8 : 16])[0] # The same offset as above!

	def get_file_offset_2x(self):
		"""Get and return the log file offset for a fast copy. The log file version should be 2.0 (or higher). This field is not valid for regular log record pages."""

		if self.end_of_usa_offset <= 60:
			return struct.unpack('<L', self.buf[60 : 64])[0]

	def get_flags(self):
		"""Get and return the flags (as an integer)."""

		return struct.unpack('<L', self.buf[16 : 20])[0]

	def get_page_count(self):
		"""Get and return the page count."""

		return struct.unpack('<H', self.buf[20 : 22])[0]

	def get_page_position(self):
		"""Get and return the page position."""

		return struct.unpack('<H', self.buf[22 : 24])[0]

	def get_next_record_offset(self):
		"""Get and return the offset of the free space in this page."""

		return struct.unpack('<H', self.buf[24 : 26])[0]

	def get_last_end_lsn(self):
		"""Get and return the log sequence number (LSN) for the last record in this page."""

		return struct.unpack('<Q', self.buf[32 : 40])[0]

	def get_log_record_at_offset(self, offset, header_length = None):
		"""Get, parse and return a log record header (LogRecordHeader) by its offset in this log record page."""

		if offset < self.data_offset:
			raise LogFileException('Invalid log data offset: {} < {}'.format(offset, self.data_offset))

		return LogRecordHeader(self.buf[offset : ], header_length)

	def __str__(self):
		return 'LogRecordPage #{}, USA end: {}, last LSN: {} (or file offset 1.1/2.x: {}/{}), flags: {}, page count: {}, page position: {}, last end LSN: {}'.format(self.page_number, self.end_of_usa_offset, self.get_last_lsn(), self.get_file_offset_11(), self.get_file_offset_2x(), hex(self.get_flags()), self.get_page_count(), self.get_page_position(), self.get_last_end_lsn())

class LogRecordHeader(object):
	"""This class is used to work with a log record header."""

	buf = None
	"""Data of this log record (including client data)."""

	sizeof = 48
	"""A size of this header (aligned to 8 bytes)."""

	def __init__(self, log_record_raw, header_length = None):
		self.buf = log_record_raw

		if header_length is not None and header_length < 48:
			raise NotImplementedError('The following log record header length is not supported: {}'.format(header_length))

		if header_length is not None:
			self.sizeof = header_length

		if self.sizeof < 8 or self.sizeof % 8 != 0:
			raise LogFileException('Invalid log header length: {}'.format(self.sizeof))

		if len(self.buf) < self.sizeof:
			raise LogFileException('Truncated log record header')

	def get_this_lsn(self):
		"""Get and return the log sequence number (LSN) for this record."""

		return struct.unpack('<Q', self.buf[0 : 8])[0]

	def get_client_previous_lsn(self):
		"""Get and return the previous log sequence number (LSN) for this client."""

		return struct.unpack('<Q', self.buf[8 : 16])[0]

	def get_client_undo_next_lsn(self):
		"""Get and return the next undo log sequence number (LSN) for this client."""

		return struct.unpack('<Q', self.buf[16 : 24])[0]

	def get_client_data_length(self):
		"""Get and return the client data length for this record."""

		return struct.unpack('<L', self.buf[24 : 28])[0]

	def get_client_id(self):
		"""Get and return the client ID for this record."""

		return struct.unpack('<L', self.buf[28 : 32])[0]

	def get_record_type(self):
		"""Get and return the record type."""

		return struct.unpack('<L', self.buf[32 : 36])[0]

	def get_transaction_id(self):
		"""Get and return the transaction ID."""

		return struct.unpack('<L', self.buf[36 : 40])[0]

	def get_flags(self):
		"""Get and return the flags (as an integer)."""

		return struct.unpack('<H', self.buf[40 : 42])[0]

	def __str__(self):
		return 'LogRecordHeader, this LSN: {}, client ID: {}, record type: {}, client data length: {}, transaction ID: {}, flags: {}'.format(self.get_this_lsn(), self.get_client_id(), self.get_record_type(), self.get_client_data_length(), self.get_transaction_id(), hex(self.get_flags()))

class LogFileParser(object):
	"""This class is used to read and parse a $LogFile file."""

	file_object = None
	"""A file object for a $LogFile file."""

	file_size = None
	"""A size of this $LogFile file."""

	restart_page_1 = None
	"""The first restart page (a RestartPage object)."""

	restart_page_2 = None
	"""The second restart page (a RestartPage object)."""

	log_page_size = None
	"""A size of a single log record page."""

	log_version = None
	"""A tuple (major_version, minor_version) for this log file."""

	lsns = None
	"""A sorted list of log sequence numbers (LSNs) seen in this file."""

	lsns_sorted = None
	"""A dictionary with a sorted list of log sequence numbers (LSNs) grouped by client IDs (each client ID is a key in this dictionary)."""

	cluster_size = None
	"""A number of bytes per cluster. (It will be adjusted later.)"""

	oat_version = None
	"""A version of the open attribute table to use. (It will be adjusted later.)"""

	def __init__(self, file_object):
		self.file_object = file_object
		self.writable = False

		self.file_object.seek(0, 2)
		self.file_size = self.file_object.tell()

		self.file_object.seek(0)
		restart_page_1_raw = self.file_object.read(PAGE_SIZE)
		restart_page_2_raw = self.file_object.read(PAGE_SIZE)

		if len(restart_page_1_raw) != PAGE_SIZE or len(restart_page_2_raw) != PAGE_SIZE:
			raise LogFileException('Truncated log file')

		if restart_page_1_raw == restart_page_2_raw == b'\xFF' * PAGE_SIZE:
			raise EmptyLogFileException('Empty log file')

		try:
			self.restart_page_1 = RestartPage(restart_page_1_raw)
		except LogFileException:
			self.restart_page_1 = None

		try:
			self.restart_page_2 = RestartPage(restart_page_2_raw)
		except LogFileException:
			self.restart_page_2 = None

		if self.restart_page_1 is None and self.restart_page_2 is None: # Both restart pages are corrupt.
			raise LogFileException('No valid restart pages found')

		log_page_size = None
		log_version = None

		if self.restart_page_1 is None: # The first restart page is corrupt, use the second one.
			log_page_size = self.restart_page_2.get_log_page_size()
			log_version = (self.restart_page_2.get_major_version(), self.restart_page_2.get_minor_version())
			restart_area = self.restart_page_2.get_restart_area()

		if self.restart_page_2 is None: # The second restart page is corrupt, use the first one.
			log_page_size = self.restart_page_1.get_log_page_size()
			log_version = (self.restart_page_1.get_major_version(), self.restart_page_1.get_minor_version())
			restart_area = self.restart_page_1.get_restart_area()

		if log_page_size is None: # Both restart pages are valid.
			log_page_size = self.restart_page_1.get_log_page_size()
			restart_area = self.restart_page_1.get_restart_area()

			if log_page_size != self.restart_page_2.get_log_page_size():
				raise LogFileException('Invalid log page size in the second restart page')

			log_version = (self.restart_page_1.get_major_version(), self.restart_page_1.get_minor_version())
			if log_version != (self.restart_page_2.get_major_version(), self.restart_page_2.get_minor_version()):
				raise LogFileException('Invalid log version the second restart page')

		self.log_page_size = log_page_size
		self.log_version = log_version

		self.record_header_length = restart_area.get_record_header_length()
		if self.record_header_length < LogRecordHeader.sizeof:
			raise LogFileException('Invalid record header length: {} < {}'.format(self.record_header_length, LogRecordHeader.sizeof))

		self.log_page_data_offset = restart_area.get_log_page_data_offset()

		self.sequence_number_bits = restart_area.get_sequence_number_bits()
		if self.sequence_number_bits >= 64 or self.sequence_number_bits < 3:
			raise LogFileException('Invalid count of sequence number bits: {}'.format(self.sequence_number_bits))

		self.cluster_size = CLUSTER_SIZE_DEFAULT # Adjusted in the 'collect_lsns' method.
		self.oat_version = 1 # Adjusted in the 'collect_lsns' method.

	def lsn_to_offset(self, lsn):
		"""Convert a log sequence number (LSN) to a file offset, return a (log_page_number, offset_in_page) tuple."""

		absolute_offset = ((lsn << self.sequence_number_bits) & 0xFFFFFFFFFFFFFFFF) >> (self.sequence_number_bits - 3)

		log_page_number = absolute_offset // self.log_page_size
		offset_in_page = absolute_offset % self.log_page_size

		return (log_page_number, offset_in_page)

	def lsn_to_seqnum(self, lsn):
		"""Convert a log sequence number (LSN) to a sequence number and return it."""

		return lsn >> (64 - self.sequence_number_bits)

	def offset_to_lsn(self, log_page_number, offset_in_page, sequence_number):
		"""Convert a log page number, an offset within that page, and a sequence number to a log sequence number (LSN) and return it."""

		absolute_offset = log_page_number * self.log_page_size + offset_in_page

		return (absolute_offset >> 3) | (sequence_number << (64 - self.sequence_number_bits))

	def get_log_record_page_by_number(self, log_page_number):
		"""Get, parse and return a log record page (LogRecordPage) by its number (or None, if not found)."""

		self.file_object.seek(log_page_number * self.log_page_size)
		buf = self.file_object.read(self.log_page_size)

		if len(buf) != self.log_page_size: # Truncated data.
			return

		try:
			log_page = LogRecordPage(buf, log_page_number, self.log_page_data_offset)
		except (LogFileException, NotImplementedError):
			log_page = None

		return log_page

	def get_wrapped_log_record_page_number(self):
		"""Return the first log record page number to be used after the log file is wrapped."""

		if self.log_version[0] == 1 and self.log_version[1] == 1:
			start_page = 4 # 2 restart pages and 2 tail log record pages.
		elif self.log_version[0] >= 2:
			start_page = 34 # 2 restart pages and 32 fast pages.
		else:
			raise NotImplementedError('Unknown location of the "infinite" area')

		return start_page

	def collect_lsns(self):
		"""Collect valid log sequence numbers (LSNs) found in this log file."""

		self.lsns = set()

		if self.restart_page_1 is not None:
			lsn = self.restart_page_1.get_chkdsk_lsn()
			self.lsns.add(lsn)

			lsn = self.restart_page_1.get_restart_area().get_current_lsn()
			self.lsns.add(lsn)

			for client in self.restart_page_1.get_restart_area().clients():
				lsn = client.get_oldest_lsn()
				self.lsns.add(lsn)

				lsn = client.get_client_restart_lsn()
				self.lsns.add(lsn)

		if self.restart_page_2 is not None:
			lsn = self.restart_page_2.get_chkdsk_lsn()
			self.lsns.add(lsn)

			lsn = self.restart_page_2.get_restart_area().get_current_lsn()
			self.lsns.add(lsn)

			for client in self.restart_page_2.get_restart_area().clients():
				lsn = client.get_oldest_lsn()
				self.lsns.add(lsn)

				lsn = client.get_client_restart_lsn()
				self.lsns.add(lsn)

		for log_record_page in self.log_record_pages(1):
			lsn = log_record_page.get_last_lsn()
			self.lsns.add(lsn)

			lsn = log_record_page.get_last_end_lsn()
			self.lsns.add(lsn)

		# Validate every LSN found, collect new LSNs.
		new_lsns = set()
		for lsn in self.lsns.copy():
			log_page_number, offset = self.lsn_to_offset(lsn)

			if log_page_number == 0:
				self.lsns.remove(lsn)
				continue

			log_record_page = self.get_log_record_page_by_number(log_page_number)
			if log_record_page is None:
				self.lsns.remove(lsn)
				continue

			try:
				log_record_header = log_record_page.get_log_record_at_offset(offset, self.record_header_length)
			except LogFileException:
				self.lsns.remove(lsn)
				continue

			if lsn != log_record_header.get_this_lsn():
				self.lsns.remove(lsn)

			new_lsn = log_record_header.get_client_previous_lsn()
			new_lsns.add(new_lsn)

			new_lsn = log_record_header.get_client_undo_next_lsn()
			new_lsns.add(new_lsn)

		# Validate these new LSNs.
		for lsn in new_lsns.copy():
			log_page_number, offset = self.lsn_to_offset(lsn)

			if log_page_number == 0:
				new_lsns.remove(lsn)
				continue

			log_record_page = self.get_log_record_page_by_number(log_page_number)
			if log_record_page is None:
				new_lsns.remove(lsn)
				continue

			try:
				log_record_header = log_record_page.get_log_record_at_offset(offset, self.record_header_length)
			except LogFileException:
				new_lsns.remove(lsn)
				continue

			if lsn != log_record_header.get_this_lsn():
				new_lsns.remove(lsn)

		# Extend the list of LSNs found using new data.
		self.lsns.update(new_lsns)

		# Now, walk through all LSNs found before and locate new LSNs.

		def find_next_lsn(current_lsn):
			"""Given a current LSN, find, validate and return the next LSN. If there is none or something is invalid, return None."""

			log_page_number, offset_in_page = self.lsn_to_offset(current_lsn)
			if log_page_number == 0:
				return

			log_record_page = self.get_log_record_page_by_number(log_page_number)
			if log_record_page is None:
				return

			try:
				log_record_header = log_record_page.get_log_record_at_offset(offset_in_page, self.record_header_length)
			except LogFileException:
				return

			client_data_length = log_record_header.get_client_data_length()
			if client_data_length < 8 or client_data_length % 8 != 0:
				return

			seqnum_expected = self.lsn_to_seqnum(lsn)

			if client_data_length <= self.log_page_size - offset_in_page - self.record_header_length: # Client data is in the current log record page only.
				# Try the current log record page.
				candidate_offset_in_page = offset_in_page + self.record_header_length + client_data_length
				candidate_lsn = self.offset_to_lsn(log_page_number, candidate_offset_in_page, seqnum_expected)

				try:
					candidate_log_record_header = log_record_page.get_log_record_at_offset(candidate_offset_in_page, self.record_header_length)
				except LogFileException:
					pass
				else:
					if candidate_log_record_header.get_this_lsn() == candidate_lsn:
						return candidate_lsn

				# Try the next log record page.
				candidate_log_page_number = log_page_number + 1
				candidate_offset_in_page = self.log_page_data_offset
				candidate_lsn = self.offset_to_lsn(candidate_log_page_number, candidate_offset_in_page, seqnum_expected)

				# Handle the wrap.
				if candidate_log_page_number * self.log_page_size >= self.file_size:
					candidate_log_page_number = self.get_wrapped_log_record_page_number()
					seqnum_expected += 1
					candidate_lsn = self.offset_to_lsn(candidate_log_page_number, candidate_offset_in_page, seqnum_expected)

				candidate_log_record_page = self.get_log_record_page_by_number(candidate_log_page_number)
				if candidate_log_record_page is not None:
					try:
						candidate_log_record_header = candidate_log_record_page.get_log_record_at_offset(candidate_offset_in_page, self.record_header_length)
					except LogFileException:
						pass
					else:
						if candidate_log_record_header.get_this_lsn() == candidate_lsn:
							return candidate_lsn

			else: # Client data is in two or more log record pages.
				client_data_length_left = client_data_length - (self.log_page_size - offset_in_page - self.record_header_length) # Client data length in the next pages (without the first one).

				pages_to_skip = 1 + client_data_length_left // (self.log_page_size - self.log_page_data_offset) # The number of pages to skip (including the first one with client data).

				candidate_log_page_number = log_page_number + pages_to_skip

				candidate_offset_in_page = self.log_page_data_offset + client_data_length_left - (pages_to_skip - 1) * (self.log_page_size - self.log_page_data_offset)
				candidate_lsn = self.offset_to_lsn(candidate_log_page_number, candidate_offset_in_page, seqnum_expected)

				# Handle the wrap.
				if candidate_log_page_number * self.log_page_size >= self.file_size:
					pages_left_in_file = (self.file_size // self.log_page_size) - (log_page_number + 1) # Pages left after the first one with client data.

					candidate_log_page_number = self.get_wrapped_log_record_page_number() + (pages_to_skip - 1) - pages_left_in_file
					seqnum_expected += 1
					candidate_lsn = self.offset_to_lsn(candidate_log_page_number, candidate_offset_in_page, seqnum_expected)

				candidate_log_record_page = self.get_log_record_page_by_number(candidate_log_page_number)
				if candidate_log_record_page is not None:
					try:
						candidate_log_record_header = candidate_log_record_page.get_log_record_at_offset(candidate_offset_in_page, self.record_header_length)
					except LogFileException:
						pass
					else:
						if candidate_log_record_header.get_this_lsn() == candidate_lsn:
							return candidate_lsn

				# Try the next log record page.
				candidate_log_page_number += 1
				candidate_offset_in_page = self.log_page_data_offset
				candidate_lsn = self.offset_to_lsn(candidate_log_page_number, candidate_offset_in_page, seqnum_expected)

				candidate_log_record_page = self.get_log_record_page_by_number(candidate_log_page_number)
				if candidate_log_record_page is not None:
					try:
						candidate_log_record_header = candidate_log_record_page.get_log_record_at_offset(candidate_offset_in_page, self.record_header_length)
					except LogFileException:
						pass
					else:
						if candidate_log_record_header.get_this_lsn() == candidate_lsn:
							return candidate_lsn

		def find_previous_lsn(current_lsn):
			"""Give a current LSN, find, validate and return the previous LSN for the same client. If there is none or something is invalid, return None."""

			log_page_number, offset_in_page = self.lsn_to_offset(current_lsn)
			if log_page_number == 0:
				return

			log_record_page = self.get_log_record_page_by_number(log_page_number)
			if log_record_page is None:
				return

			try:
				log_record_header = log_record_page.get_log_record_at_offset(offset_in_page, self.record_header_length)
			except LogFileException:
				return

			client_previous_lsn = log_record_header.get_client_previous_lsn()
			candidate_log_page_number, candidate_offset_in_page = self.lsn_to_offset(client_previous_lsn)

			if candidate_log_page_number == 0:
				return
			
			candidate_log_record_page = self.get_log_record_page_by_number(candidate_log_page_number)
			if candidate_log_record_page is not None:
				try:
					candidate_log_record_header = candidate_log_record_page.get_log_record_at_offset(candidate_offset_in_page, self.record_header_length)
				except LogFileException:
					pass
				else:
					if candidate_log_record_header.get_this_lsn() == client_previous_lsn:
						return client_previous_lsn

		def find_undo_next_lsn(current_lsn):
			"""Give a current LSN, find, validate and return the undo next LSN for the same client. If there is none or something is invalid, return None."""

			log_page_number, offset_in_page = self.lsn_to_offset(current_lsn)
			if log_page_number == 0:
				return

			log_record_page = self.get_log_record_page_by_number(log_page_number)
			if log_record_page is None:
				return

			try:
				log_record_header = log_record_page.get_log_record_at_offset(offset_in_page, self.record_header_length)
			except LogFileException:
				return

			client_undo_next_lsn = log_record_header.get_client_undo_next_lsn()
			candidate_log_page_number, candidate_offset_in_page = self.lsn_to_offset(client_undo_next_lsn)

			if candidate_log_page_number == 0:
				return
			
			candidate_log_record_page = self.get_log_record_page_by_number(candidate_log_page_number)
			if candidate_log_record_page is not None:
				try:
					candidate_log_record_header = candidate_log_record_page.get_log_record_at_offset(candidate_offset_in_page, self.record_header_length)
				except LogFileException:
					pass
				else:
					if candidate_log_record_header.get_this_lsn() == client_undo_next_lsn:
						return client_undo_next_lsn


		# Find new LSNs by walking over client data.
		for lsn in self.lsns.copy():
			current_lsn = lsn

			while True:
				current_lsn = find_next_lsn(current_lsn)

				if current_lsn is None or current_lsn in self.lsns: # Loop until a known LSN is encountered or something invalid is found.
					break
				else:
					self.lsns.add(current_lsn)

		# Find new LSNs by looking for previous LSNs recorded for the same client.
		for lsn in self.lsns.copy():
			current_lsn = lsn

			while True:
				current_lsn = find_previous_lsn(current_lsn)

				if current_lsn is None or current_lsn in self.lsns: # Loop until a known LSN is encountered or something invalid is found.
					break
				else:
					self.lsns.add(current_lsn)

		# Find new LSNs by looking for undo next LSNs for the same client.
		for lsn in self.lsns.copy():
			current_lsn = lsn

			while True:
				current_lsn = find_undo_next_lsn(current_lsn)

				if current_lsn is None or current_lsn in self.lsns: # Loop until a known LSN is encountered or something invalid is found.
					break
				else:
					self.lsns.add(current_lsn)

		# Find new LSNs by looking in NTFS restart areas.
		new_lsns = set()

		for lsn in self.lsns.copy():
			client_data = self.get_client_data(lsn)
			if client_data.record_type == LfsClientRestart:
				try:
					ntfs_restart_area = client_data.data_decoded()
				except ClientException:
					continue

				# Adjust the cluster size.
				cluster_size = ntfs_restart_area.get_bytes_per_cluster()
				if cluster_size is not None and cluster_size > 0 and cluster_size % 512 == 0:
					self.cluster_size = cluster_size

				# Adjust the version-specific configuration.
				self.use_dumps = True
				major_version = ntfs_restart_area.get_major_version()
				if major_version >= 1:
					if major_version >= 2:
						self.use_dumps = False

					self.oat_version = 1
				else:
					self.oat_version = 0

				new_lsns.add(ntfs_restart_area.get_start_of_checkpoint_lsn())
				new_lsns.add(ntfs_restart_area.get_open_attribute_table_lsn())
				new_lsns.add(ntfs_restart_area.get_attribute_names_lsn())
				new_lsns.add(ntfs_restart_area.get_dirty_page_table_lsn())
				new_lsns.add(ntfs_restart_area.get_transaction_table_lsn())

		for lsn in new_lsns:
			# Validate a new LSN.
			log_page_number, offset = self.lsn_to_offset(lsn)
			if log_page_number == 0:
				continue

			log_record_page = self.get_log_record_page_by_number(log_page_number)
			if log_record_page is None:
				continue

			try:
				log_record_header = log_record_page.get_log_record_at_offset(offset, self.record_header_length)
			except LogFileException:
				continue

			if lsn == log_record_header.get_this_lsn():
				self.lsns.add(lsn)
			else:
				continue

			# Search for new LSNs.
			current_lsn = lsn
			while True:
				current_lsn = find_next_lsn(current_lsn)

				if current_lsn is None or current_lsn in self.lsns: # Loop until a known LSN is encountered or something invalid is found.
					break
				else:
					self.lsns.add(current_lsn)

			current_lsn = lsn
			while True:
				current_lsn = find_previous_lsn(current_lsn)

				if current_lsn is None or current_lsn in self.lsns: # Loop until a known LSN is encountered or something invalid is found.
					break
				else:
					self.lsns.add(current_lsn)

			current_lsn = lsn
			while True:
				current_lsn = find_undo_next_lsn(current_lsn)

				if current_lsn is None or current_lsn in self.lsns: # Loop until a known LSN is encountered or something invalid is found.
					break
				else:
					self.lsns.add(current_lsn)

		self.lsns = sorted(self.lsns) # Finally, store a sorted list of LSNs.

	def sort_lsns(self):
		"""Group log sequence numbers (LSNs) by their client IDs."""

		self.lsns_sorted = dict()

		for current_lsn in self.lsns:
			log_page_number, offset_in_page = self.lsn_to_offset(current_lsn)
			log_record_page = self.get_log_record_page_by_number(log_page_number)
			log_record_header = log_record_page.get_log_record_at_offset(offset_in_page, self.record_header_length)

			client_id = log_record_header.get_client_id()
			if client_id not in self.lsns_sorted.keys():
				self.lsns_sorted[client_id] = [ current_lsn ]
			else:
				self.lsns_sorted[client_id].append(current_lsn)

		for client_id in self.lsns_sorted.keys():
			self.lsns_sorted[client_id] = sorted(self.lsns_sorted[client_id])

	def prepare_for_writes(self):
		"""Make a writable file object in memory (which is a copy of the original one) and use it for further operations."""

		if self.writable:
			return

		self.file_object.seek(0)

		new_file_object = io.BytesIO()
		shutil.copyfileobj(self.file_object, new_file_object)

		self.old_file_object = self.file_object
		self.file_object = new_file_object
		self.writable = True

	def discard_changes(self):
		"""Discard all changes made to a writable file object (in memory) and use the original file object."""

		if not self.writable:
			return

		self.file_object.close()
		self.file_object = self.old_file_object
		self.writable = False

	def apply_tail_page(self):
		"""Apply a tail log record page to the log file. The log file version should be 1.1. The file object should be writable."""

		if self.log_version != (1, 1):
			raise RuntimeError('The log file version is not 1.1')

		tail_page_1 = self.get_log_record_page_by_number(2)
		tail_page_2 = self.get_log_record_page_by_number(3)

		if tail_page_1 is None and tail_page_2 is None: # Nothing to do, both tail log record pages are invalid.
			return

		single_tail_page = None

		if tail_page_1 is None and tail_page_2 is not None: # Only the second tail log record page is present.
			single_tail_page = tail_page_2
		elif tail_page_2 is None and tail_page_1 is not None: # Only the first tail log record page is present.
			single_tail_page = tail_page_1
		elif tail_page_1 is not None and tail_page_2 is not None: # Both tail log record pages are valid, choose the latest one.
			if tail_page_1.get_last_end_lsn() > tail_page_2.get_last_end_lsn():
				single_tail_page = tail_page_1
			else:
				single_tail_page = tail_page_2

		if single_tail_page is not None: # A proper tail log record page was found.
			file_offset = single_tail_page.get_file_offset_11()

			self.file_object.seek(file_offset)
			self.file_object.write(single_tail_page.buf_protected)

	def apply_fast_pages(self):
		"""Apply fast log record pages to the log file. The log file version should be 2.0 or higher. The file object should be writable."""

		if self.log_version[0] < 2:
			raise RuntimeError('The log file version is not 2.x (or higher)')

		# Locate the highest LSN present in the "infinite" area.
		highest_lsn = 0
		for log_record_page in self.log_record_pages(0):
			current_lsn = log_record_page.get_last_lsn()
			if current_lsn > highest_lsn:
				highest_lsn = current_lsn

		fast_pages = []

		i = 2
		while i < 34:
			fast_page = self.get_log_record_page_by_number(i)
			if fast_page is not None and fast_page.get_last_lsn() > highest_lsn:
				fast_pages.append(fast_page)

			i += 1

		fast_pages.sort(key = lambda x: x.get_last_lsn()) # Sort the fast pages according to the log sequence numbers they have (fast pages with more recent log data should be written at the end).

		for fast_page in fast_pages:
			file_offset = fast_page.get_file_offset_2x()

			self.file_object.seek(file_offset)
			self.file_object.write(fast_page.buf_protected)

	def log_record_pages(self, mode):
		"""This method yields each log record page (LogRecordPage).
		When 'mode' is 0, yield log record pages from the "infinite" (circular) area only.
		When 'mode' is 1, yield each log record page from the whole file (not just from the "infinite" area).
		"""

		if mode not in [0, 1]:
			raise ValueError('Invalid mode of operation: {}'.format(mode))

		if mode == 0:
			start_page = self.get_wrapped_log_record_page_number()
		elif mode == 1:
			start_page = 2 # 2 restart pages.

		i = start_page
		while i < self.file_size // self.log_page_size:
			log_page = self.get_log_record_page_by_number(i)

			if log_page is not None:
				yield log_page

			i += 1

	def get_client_data(self, lsn):
		"""Get, parse and return client data (ClientData) for a given log sequence number (LSN)."""

		log_page_number, offset_in_page = self.lsn_to_offset(lsn)

		log_record_page = self.get_log_record_page_by_number(log_page_number)
		log_record_header = log_record_page.get_log_record_at_offset(offset_in_page, self.record_header_length)

		client_data_length = log_record_header.get_client_data_length()

		if client_data_length <= self.log_page_size - offset_in_page - self.record_header_length: # Client data is in the current log record page only.
			client_buf = log_record_header.buf[self.record_header_length : self.record_header_length + client_data_length]
			client_data = ClientData(client_buf, log_record_header.get_record_type(), lsn, log_record_header.get_transaction_id(), self.cluster_size)

			return client_data

		else: # Client data is in two or more log record pages.
			client_buf = log_record_header.buf[self.record_header_length : ]
			client_data_length_left = client_data_length - len(client_buf)

			while client_data_length_left > 0:
				log_page_number += 1

				# Handle the wrap.
				if log_page_number * self.log_page_size >= self.file_size:
					log_page_number = self.get_wrapped_log_record_page_number()

				log_record_page = self.get_log_record_page_by_number(log_page_number)
				if log_record_page is None: # This page is missing in the current state of the log file.
					break

				if client_data_length_left >= self.log_page_size - self.log_page_data_offset:
					client_buf_more_data = log_record_page.buf[self.log_page_data_offset : ]
				else:
					client_buf_more_data = log_record_page.buf[self.log_page_data_offset : self.log_page_data_offset + client_data_length_left]

				client_buf += client_buf_more_data

				client_data_length_left -= len(client_buf_more_data)

			client_data = ClientData(client_buf, log_record_header.get_record_type(), lsn, log_record_header.get_transaction_id(), self.cluster_size)

			return client_data

	def parse_ntfs_records(self, recover_log_data = True):
		"""This method yields NTFS client data (NTFSRestartArea and NTFSLogRecord) from each log record found in the log file.
		If 'recover_log_data' is True, apply a tail log record page or fast log record pages before parsing the log data.
		"""

		if recover_log_data:
			self.prepare_for_writes()

			if self.log_version == (1, 1):
				self.apply_tail_page()
			elif self.log_version[0] >= 2:
				self.apply_fast_pages()

		self.collect_lsns()
		self.sort_lsns()

		for client_id in self.lsns_sorted.keys():
			latest_oat_dump = None
			old_oat_dump = None
			latest_an_dump = None
			old_an_dump = None

			oat_dump_count = 0
			an_dump_count = 0

			oat = dict()

			for lsn in self.lsns_sorted[client_id]:
				client_data = self.get_client_data(lsn)
				try:
					client_data_decoded = client_data.data_decoded()
				except NotImplementedError:
					pass
				else:
					if type(client_data_decoded) is NTFSLogRecord:
						redo_op = client_data_decoded.get_redo_operation()
						if redo_op == OpenNonresidentAttribute:
							attribute_name = client_data_decoded.get_undo_data().decode('utf-16le', errors = 'replace')

							oat_index = client_data_decoded.get_target_attribute()
							oat_entry_data = client_data_decoded.get_redo_data()

							try:
								if self.oat_version >= 1:
									oat_entry = OpenAttributeEntry1(oat_entry_data)
								else:
									oat_entry = OpenAttributeEntry0(oat_entry_data)
							except ClientException:
								# Something is wrong, clear the open attribute table.
								oat = dict()
							else:
								oat[oat_index] = (oat_entry.get_file_reference(), attribute_name)
						elif self.use_dumps and redo_op == OpenAttributeTableDump:
							old_oat_dump = latest_oat_dump
							latest_oat_dump = OpenAttributeTableDumpParser(client_data_decoded.get_redo_data(), self.oat_version)
							oat_dump_count += 1
						elif self.use_dumps and redo_op == AttributeNamesDump:
							old_an_dump = latest_an_dump
							latest_an_dump = AttributeNamesDumpParser(client_data_decoded.get_redo_data())
							an_dump_count += 1

						client_data_decoded.oat = oat.copy()

						if self.use_dumps and oat_dump_count > 0 and oat_dump_count == an_dump_count:
							client_data_decoded.oat_dump = latest_oat_dump
							client_data_decoded.an_dump = latest_an_dump
						elif self.use_dumps and oat_dump_count > 0 and oat_dump_count != an_dump_count:
							client_data_decoded.oat_dump = old_oat_dump
							client_data_decoded.an_dump = old_an_dump
						else:
							client_data_decoded.oat_dump = None
							client_data_decoded.an_dump = None

					yield client_data_decoded

		if recover_log_data:
			self.discard_changes()

	def __str__(self):
		return 'LogFileParser, file size: {}'.format(self.file_size)

class ClientData(object):
	"""This class is used to work with client data."""

	buf = None
	"""Client data."""

	record_type = None
	"""A record type of this client data."""

	lsn = None
	"""A log sequence number (LSN) for this client data."""

	cluster_size = None
	"""A number of bytes per cluster."""

	transaction_id = None
	"""A transaction ID."""

	def __init__(self, client_data_raw, record_type, log_sequence_number, transaction_id, cluster_size):
		self.buf = client_data_raw
		self.record_type = record_type
		self.lsn = log_sequence_number
		self.transaction_id = transaction_id

		self.cluster_size = cluster_size

	def data_decoded(self):
		"""Parse and return decoded data (NTFSRestartArea or NTFSLogRecord). Only the NTFS client is supported."""

		if self.record_type == LfsClientRestart:
			return NTFSRestartArea(self.buf, self.lsn)
		elif self.record_type == LfsClientRecord:
			return NTFSLogRecord(self.buf, self.lsn, self.transaction_id, self.cluster_size)
		else:
			raise NotImplementedError('The following record type is not supported: {}'.format(self.record_type))

	def __str__(self):
		return 'ClientData, length: {}, record type: {}, LSN: {}'.format(len(self.buf), self.record_type, self.lsn)

class NTFSRestartArea(object):
	"""This class is used work with an NTFS restart area."""

	buf = None
	"""Data of this NTFS restart area."""

	lsn = None
	"""A log sequence number (LSN) of an NTFS restart area."""

	def __init__(self, restart_area_raw, lsn):
		self.buf = restart_area_raw
		self.lsn = lsn

		if len(self.buf) < 64:
			raise ClientException('Invalid restart area length: {}'.format(len(self.buf)))

	def get_major_version(self):
		"""Get and return the major version of a client."""

		return struct.unpack('<L', self.buf[: 4])[0]

	def get_minor_version(self):
		"""Get and return the minor version of a client."""

		return struct.unpack('<L', self.buf[4 : 8])[0]

	def get_start_of_checkpoint_lsn(self):
		"""Get and return the log sequence number (LSN) of a checkpoint record."""

		return struct.unpack('<Q', self.buf[8 : 16])[0]

	def get_open_attribute_table_lsn(self):
		"""Get and return the log sequence number (LSN) of an open attribute table."""

		return struct.unpack('<Q', self.buf[16 : 24])[0]

	def get_attribute_names_lsn(self):
		"""Get and return the log sequence number (LSN) of attribute names."""

		return struct.unpack('<Q', self.buf[24 : 32])[0]

	def get_dirty_page_table_lsn(self):
		"""Get and return the log sequence number (LSN) of a dirty page table."""

		return struct.unpack('<Q', self.buf[32 : 40])[0]

	def get_transaction_table_lsn(self):
		"""Get and return the log sequence number (LSN) of a transaction table."""

		return struct.unpack('<Q', self.buf[40 : 48])[0]

	def get_open_attribute_table_length(self):
		"""Get and return the length of an open attribute table."""

		return struct.unpack('<L', self.buf[48 : 52])[0]

	def get_attribute_names_length(self):
		"""Get and return the length of attribute names."""

		return struct.unpack('<L', self.buf[52 : 56])[0]

	def get_dirty_page_table_length(self):
		"""Get and return the length of a dirty page table."""

		return struct.unpack('<L', self.buf[56 : 60])[0]

	def get_transaction_table_length(self):
		"""Get and return the length of a transaction table."""

		return struct.unpack('<L', self.buf[60 : 64])[0]

	def get_usn_journal_restart_offset(self):
		"""Get and return the absolute offset used as a starting point for checking update sequence number (USN) change journal records."""

		if len(self.buf) >= 72:
			return struct.unpack('<q', self.buf[64 : 72])[0]

	def get_last_lsn(self):
		"""Get and return the last value (as of the previous volume restart) of the "current" log sequence number (LSN)."""

		if len(self.buf) >= 80:
			return struct.unpack('<Q', self.buf[72 : 80])[0]

	def get_bytes_per_cluster(self):
		"""Get and return the number of bytes per cluster."""

		if len(self.buf) >= 84:
			return struct.unpack('<L', self.buf[80 : 84])[0]

	def get_usn_journal_reference(self):
		"""Get and return the file record segment (FRS) reference for the update sequence number (USN) change journal."""

		if len(self.buf) >= 96:
			return struct.unpack('<Q', self.buf[88 : 96])[0]

	def get_usn_base(self):
		"""Get and return the base offset for the update sequence number (USN) change journal.
		Since the $J data stream of this journal can be very large, this value is used to rebase offsets for high-level API functions (making them relative from the base offset).
		"""

		if len(self.buf) >= 104:
			return struct.unpack('<q', self.buf[96 : 104])[0]

	def get_oldest_lsn(self):
		"""Get and return the oldest log sequence number (LSN) required by this client (as of the checkpoint)."""

		if len(self.buf) >= 112:
			return struct.unpack('<Q', self.buf[104 : 112])[0]

	def __str__(self):
		return 'NTFSRestartArea (LSN: {}), version: {}.{}, start of checkpoint LSN: {}'.format(self.lsn, self.get_major_version(), self.get_minor_version(), self.get_start_of_checkpoint_lsn())

class NTFSLogRecord(object):
	"""This class is used work with an NTFS log record."""

	buf = None
	"""Data of this NTFS log record."""

	lsn = None
	"""A log sequence number (LSN) of this NTFS log record."""

	oat = None
	"""An open attribute table (it is set externally in the 'parse_ntfs_records' method of the LogFileParser class)."""

	oat_dump = None
	"""An open attribute table dump (as raw bytes; it is set externally in the 'parse_ntfs_records' method of the LogFileParser class)."""

	an_dump = None
	"""An attribute names dump (as raw bytes; it is set externally in the 'parse_ntfs_records' method of the LogFileParser class)."""

	transaction_id = None
	"""A transaction ID."""

	def __init__(self, log_record_raw, lsn, transaction_id, cluster_size):
		self.buf = log_record_raw
		self.lsn = lsn
		self.transaction_id = transaction_id

		self.cluster_size = cluster_size

		if len(self.buf) < 32:
			raise ClientException('Invalid log record length: {}'.format(len(self.buf)))

	def get_redo_operation(self):
		"""Get and return the redo operation code (as an integer)."""

		return struct.unpack('<H', self.buf[0 : 2])[0]

	def get_undo_operation(self):
		"""Get and return the undo operation code (as an integer)."""

		return struct.unpack('<H', self.buf[2 : 4])[0]

	def get_redo_offset(self):
		"""Get and return the offset of an undo record."""

		offset = struct.unpack('<H', self.buf[4 : 6])[0]
		if offset > 0 and offset < 32:
			raise ClientException('Invalid redo offset: {}'.format(offset))

		return offset

	def get_redo_length(self):
		"""Get and return the length of an undo record."""

		return struct.unpack('<H', self.buf[6 : 8])[0]

	def get_undo_offset(self):
		"""Get and return the offset of an undo record."""

		offset = struct.unpack('<H', self.buf[8 : 10])[0]
		if offset > 0 and offset < 32:
			raise ClientException('Invalid undo offset: {}'.format(offset))

		return offset

	def get_undo_length(self):
		"""Get and return the length of an undo record."""

		return struct.unpack('<H', self.buf[10 : 12])[0]

	def get_target_attribute(self):
		"""Get and return the open attribute table index for this update."""

		return struct.unpack('<H', self.buf[12 : 14])[0]

	def get_lcns_to_follow(self):
		"""Get and return the number of logical cluster numbers (LCNs) in use at the end of the header."""

		return struct.unpack('<H', self.buf[14 : 16])[0]

	def get_record_offset(self):
		"""Get and return the record offset."""

		return struct.unpack('<H', self.buf[16 : 18])[0]

	def get_attribute_offset(self):
		"""Get and return the attribute offset."""

		return struct.unpack('<H', self.buf[18 : 20])[0]

	def get_cluster_block_offset(self):
		"""Get and return the cluster block offset (this is a number of 512-byte blocks)."""

		return struct.unpack('<H', self.buf[20 : 22])[0]

	def get_target_block_size(self):
		"""For operations on the $MFT file, this field is set to the size (in bytes) of the file record segment (FRS) divided by 512.
		If the attribute is $INDEX_ALLOCATION, this field is set to the size (in bytes) of the index record divided by 512.
		In other cases, this field is set to 0.
		"""

		return struct.unpack('<H', self.buf[22 : 24])[0]

	def get_target_vcn(self):
		"""Get and return the target virtual cluster number (VCN)."""

		return struct.unpack('<q', self.buf[24 : 32])[0]

	def get_lcns_for_page(self):
		"""Get and return the array of logical cluster numbers (LCNs) as a list of integers."""

		lcns = []

		i = 0
		while i < self.get_lcns_to_follow():
			lcn_buf = self.buf[32 + i * 8 : 40 + i * 8]
			if len(lcn_buf) != 8:
				raise ClientException('Invalid (truncated) log record length: {}'.format(len(self.buf)))

			lcn = struct.unpack('<q', lcn_buf)[0]

			lcns.append(lcn)

			i += 1

		return lcns

	def get_redo_data(self):
		"""Get and return redo data."""

		redo_length = self.get_redo_length()
		if redo_length == 0:
			return b''

		redo_offset = self.get_redo_offset()
		return self.buf[redo_offset : redo_offset + redo_length]

	def get_undo_data(self):
		"""Get and return undo data."""

		undo_length = self.get_undo_length()
		if undo_length == 0:
			return b''

		undo_offset = self.get_undo_offset()
		return self.buf[undo_offset : undo_offset + undo_length]

	def calculate_mft_target_number(self):
		"""Calculate and return the number of a target file record segment (or None, if not applicable).
		Note: this is for resident updates only.
		"""

		if self.get_redo_operation() in LOGGED_RESIDENT_UPDATES or self.get_undo_operation() in LOGGED_RESIDENT_UPDATES:
			target_vcn = self.get_target_vcn()
			cluster_block_offset = self.get_cluster_block_offset()

			target_block_size = self.get_target_block_size()
			if target_block_size > 0:
				frs_size = target_block_size * 512
			else:
				frs_size = FILE_RECORD_SEGMENT_SIZE_DEFAULT

			return (target_vcn * self.cluster_size + cluster_block_offset * 512) // frs_size

	def calculate_offset_in_target(self):
		"""Calculate and return the offset within target data (or None, if not applicable)."""

		if self.get_redo_operation() in LOGGED_RESIDENT_UPDATES or self.get_undo_operation() in LOGGED_RESIDENT_UPDATES:
			return self.get_attribute_offset() + self.get_record_offset()

		elif self.get_redo_operation() in LOGGED_NONRESIDENT_UPDATES or self.get_undo_operation() in LOGGED_NONRESIDENT_UPDATES:
			return self.get_target_vcn() * self.cluster_size + self.get_cluster_block_offset() * 512 + self.get_attribute_offset() + self.get_record_offset()

	def calculate_mft_target_reference_and_name(self):
		"""Calculate and return the reference to a target file record segment (FRS) and a target attribute name as a tuple (or None, if not applicable or not found).
		Note: this is for nonresident updates present in an open attribute table.
		"""

		if self.oat is None:
			return

		if self.get_redo_operation() in LOGGED_NONRESIDENT_UPDATES or self.get_undo_operation() in LOGGED_NONRESIDENT_UPDATES:
			target_attribute = self.get_target_attribute()
			if target_attribute in self.oat.keys():
				return self.oat[target_attribute]

			# If not found, try the table dumps.
			if self.oat_dump is not None and self.an_dump is not None:
				try:
					target_file_reference = self.oat_dump.find_file_reference_by_index(target_attribute)
				except ClientException:
					pass
				else:
					target_attribute_name = self.an_dump.find_name_by_index(target_attribute)
					return (target_file_reference, target_attribute_name)

	def __str__(self):
		if self.get_redo_offset() > 0:
			redo_length = self.get_redo_length()
		else:
			redo_length = 0

		if self.get_undo_offset() > 0:
			undo_length = self.get_undo_length()
		else:
			undo_length = 0

		if redo_length > 0 and redo_length == undo_length and self.get_redo_offset() == self.get_undo_offset():
			redo_undo_status = '=='
		else:
			redo_undo_status = '!='

		frs_number = self.calculate_mft_target_number()
		if frs_number is not None:
			target_spec = '{} (FRS number)'.format(frs_number)
		else:
			frs_reference_and_attribute_name = self.calculate_mft_target_reference_and_name()
			if frs_reference_and_attribute_name is not None:
				frs_reference, attribute_name = frs_reference_and_attribute_name
				target_spec = '{}/{} (FRS reference / attribute name)'.format(frs_reference, attribute_name)
			else:
				target_spec = 'unknown'

		target_offset = self.calculate_offset_in_target()
		if target_offset is None:
			target_offset = 'unknown'

		return 'NTFSLogRecord (LSN: {}), redo operation: {} (length: {}), undo operation: {} (length: {}), redo {} undo, target: {}, offset in target: {}'.format(self.lsn, ResolveNTFSOperation(self.get_redo_operation()), redo_length, ResolveNTFSOperation(self.get_undo_operation()), undo_length, redo_undo_status, target_spec, target_offset)

class OpenAttributeEntry1(object):
	"""This class is used to work with the OPEN_ATTRIBUTE_ENTRY structure (version: 1.0+)."""

	buf = None
	"""Data of this OPEN_ATTRIBUTE_ENTRY structure."""

	def __init__(self, open_attribute_entry_raw):
		self.buf = open_attribute_entry_raw

		if len(self.buf) < 40:
			raise ClientException('Invalid open attribute entry length: {}'.format(len(self.buf)))

	def get_allocated_or_next_free(self):
		"""Get the free link (this value is 0xFFFFFFFF if this entry is allocated)."""

		return struct.unpack('<L', self.buf[0 : 4])[0]

	def get_bytes_per_index_buffer(self):
		"""Get and return the number of bytes per index buffer."""

		return struct.unpack('<L', self.buf[4 : 8])[0]

	def get_attribute_type_code(self):
		"""Get and return the attribute type code."""

		return struct.unpack('<L', self.buf[8 : 12])[0]

	# At least one source states that there is a field between these two fields, but there is none.

	def get_file_reference(self):
		"""Get and return the file reference."""

		return struct.unpack('<Q', self.buf[16 : 24])[0]

	def get_lsn_of_open_record(self):
		"""Get and return the log sequence number (LSN) of an open log record (OpenNonresidentAttribute)."""

		return struct.unpack('<Q', self.buf[24 : 32])[0]

	# No field for the pointer is supported (because it is valid for a running machine only).

class OpenAttributeEntry0(object):
	"""This class is used to work with the OPEN_ATTRIBUTE_ENTRY structure (version: 0.0)."""

	buf = None
	"""Data of this OPEN_ATTRIBUTE_ENTRY structure."""

	def __init__(self, open_attribute_entry_raw):
		self.buf = open_attribute_entry_raw

		if len(self.buf) < 44:
			raise ClientException('Invalid open attribute entry length: {}'.format(len(self.buf)))

	def get_allocated_or_next_free(self):
		"""Get the free link (this value is 0xFFFFFFFF if this entry is allocated)."""

		return struct.unpack('<L', self.buf[0 : 4])[0]

	def get_table_index(self):
		"""Get and return the table index (offset) of an original (version: 1.0+) entry (in a table in memory)."""

		return struct.unpack('<L', self.buf[4 : 8])[0]

	def get_file_reference(self):
		"""Get and return the file reference."""

		return struct.unpack('<Q', self.buf[8 : 16])[0]

	def get_lsn_of_open_record(self):
		"""Get and return the log sequence number (LSN) of an open log record (OpenNonresidentAttribute)."""

		return struct.unpack('<Q', self.buf[16 : 24])[0]

	def get_attribute_type_code(self):
		"""Get and return the attribute type code."""

		return struct.unpack('<L', self.buf[28 : 32])[0]

	def get_bytes_per_index_buffer(self):
		"""Get and return the number of bytes per index buffer."""

		return struct.unpack('<L', self.buf[40 : 44])[0]

class AttributeNameEntry(object):
	"""This class is used to work with the ATTRIBUTE_NAME_ENTRY structure."""

	buf = None
	"""Data of this ATTRIBUTE_NAME_ENTRY structure."""

	def __init__(self, attribute_name_entry_raw):
		self.buf = attribute_name_entry_raw

		if len(self.buf) < 8:
			raise ClientException('Invalid attribute name entry length: {}'.format(len(self.buf)))

	def get_index(self):
		"""Get and return the table index (offset) of a corresponding entry in the open attribute table."""

		return struct.unpack('<H', self.buf[0 : 2])[0]

	def get_name_length(self):
		"""Get and return the name length."""

		return struct.unpack('<H', self.buf[2 : 4])[0]

	def get_name(self):
		"""Get and return the name."""

		name_buf = self.buf[4 : 4 + self.get_name_length()]
		name = name_buf.decode('utf-16le', errors = 'replace')

		return name

	def calculate_sizeof(self):
		"""Calculate and return the size of this entry."""

		return 4 + self.get_name_length() + 2 # Include the terminating null character.

class AttributeNamesDumpParser(object):
	"""This class is used to work with the array of ATTRIBUTE_NAME_ENTRY structures."""

	buf = None
	"""Data of this array."""

	def __init__(self, attribute_names_dump_raw):
		self.buf = attribute_names_dump_raw

	def find_name_by_index(self, index):
		"""Find and return the name by its index (or None, if not found)."""

		pos = 0
		while pos < len(self.buf):
			attribute_name_entry_buf = self.buf[pos : ]

			try:
				attribute_name_entry = AttributeNameEntry(attribute_name_entry_buf)
			except ClientException:
				break

			attribute_name_entry_index = attribute_name_entry.get_index()
			if attribute_name_entry_index == index:
				return attribute_name_entry.get_name()

			pos += attribute_name_entry.calculate_sizeof()

class OpenAttributeTableDumpParser(object):
	"""This class is used to work with the array of OPEN_ATTRIBUTE_ENTRY structures."""

	buf = None
	"""Data of this array."""

	oat_class = None
	"""Either OpenAttributeEntry0 or OpenAttributeEntry1."""

	def __init__(self, attribute_names_dump_raw, version):
		self.buf = attribute_names_dump_raw

		if version >= 1:
			self.oat_class = OpenAttributeEntry1
		else:
			self.oat_class = OpenAttributeEntry0

	def find_file_reference_by_index(self, index):
		"""Find and return the file reference using the entry index."""

		if index >= len(self.buf):
			raise ClientException('Invalid index: {}'.format(index))

		open_attribute_entry_buf = self.buf[index : ]
		open_attribute_entry = self.oat_class(open_attribute_entry_buf)

		return open_attribute_entry.get_file_reference()
