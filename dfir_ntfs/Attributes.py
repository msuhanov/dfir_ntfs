# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with attributes.

import struct
import datetime
import uuid
from collections import namedtuple

# Attributes and their codes:
ATTR_TYPE_STANDARD_INFORMATION = 0x10
ATTR_TYPE_ATTRIBUTE_LIST = 0x20
ATTR_TYPE_FILE_NAME = 0x30
ATTR_TYPE_OBJECT_ID = 0x40
ATTR_TYPE_SECURITY_DESCRIPTOR = 0x50
ATTR_TYPE_VOLUME_NAME = 0x60
ATTR_TYPE_VOLUME_INFORMATION = 0x70
ATTR_TYPE_DATA = 0x80
ATTR_TYPE_INDEX_ROOT = 0x90
ATTR_TYPE_INDEX_ALLOCATION = 0xA0
ATTR_TYPE_BITMAP = 0xB0
ATTR_TYPE_REPARSE_POINT = 0xC0
ATTR_TYPE_EA_INFORMATION = 0xD0
ATTR_TYPE_EA = 0xE0
ATTR_TYPE_LOGGED_UTILITY_STREAM = 0x100
ATTR_TYPE_END = 0xFFFFFFFF

# Starting from Windows 2000, the following 32-bit value is stored after the ATTR_TYPE_END marker: 0x11477982.
# This value represents an invalid (not aligned to 8 bytes) attribute record length.
# If the ATTR_TYPE_END marker is corrupt (not equal to 0xFFFFFFFF), then the Chkdsk scan will detect the corruption using this length.
# This is done because the Chkdsk tool allows unknown attribute codes. This "fake" size is not used for anything else.
ATTR_TYPE_END_FAKE_SIZE = 0x11477982

ATTRIBUTES_SUPPORTED = [ ATTR_TYPE_STANDARD_INFORMATION, ATTR_TYPE_ATTRIBUTE_LIST, ATTR_TYPE_FILE_NAME, ATTR_TYPE_OBJECT_ID, ATTR_TYPE_SECURITY_DESCRIPTOR, ATTR_TYPE_VOLUME_NAME, ATTR_TYPE_VOLUME_INFORMATION, ATTR_TYPE_DATA, ATTR_TYPE_INDEX_ROOT, ATTR_TYPE_INDEX_ALLOCATION, ATTR_TYPE_BITMAP, ATTR_TYPE_REPARSE_POINT, ATTR_TYPE_EA_INFORMATION, ATTR_TYPE_EA, ATTR_TYPE_LOGGED_UTILITY_STREAM ]

# Flags for the $FILE_NAME attribute:
FILE_NAME_NTFS = 1 # A Win32 name space.
FILE_NAME_DOS = 2 # A DOS name space.

# Flags for the $VOLUME_INFORMATION attribute:
VOLUME_DIRTY = 0x1 # A volume is corrupt (dirty).
VOLUME_RESIZE_LOG_FILE = 0x2 # Need to resize the $LogFile journal.
VOLUME_UNKNOWN_NAME_4 = 0x4 # Need to upgrade the volume version.
VOLUME_UNKNOWN_NAME_8 = 0x8 # The object IDs, the quotas, and the USN journal metadata can be corrupt (this flag is set by Windows NT 4.0).
VOLUME_UNKNOWN_NAME_10 = 0x10 # Need to delete the USN journal.
VOLUME_UNKNOWN_NAME_20 = 0x20 # Need to repair the object IDs.
VOLUME_UNKNOWN_NAME_40 = 0x40 # A volume is corrupt and it caused a bug check.
VOLUME_UNKNOWN_NAME_80 = 0x80 # Persistent volume state: no tunneling cache, the short file names creation is disabled (PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED).
VOLUME_UNKNOWN_NAME_100 = 0x100 # Need to run the full Chkdsk scan.
VOLUME_UNKNOWN_NAME_200 = 0x200 # Need to run the proactive scan.
VOLUME_UNKNOWN_NAME_400 = 0x400 # Persistent volume state: the TxF feature is disabled.
VOLUME_UNKNOWN_NAME_800 = 0x800 # Persistent volume state: the volume scrub is disabled (PERSISTENT_VOLUME_STATE_VOLUME_SCRUB_DISABLED).
VOLUME_UNKNOWN_NAME_1000 = 0x1000 # Do not create the corruption log file ($Verify and $Corrupt).
VOLUME_UNKNOWN_NAME_2000 = 0x2000 # Persistent volume state: the heat gathering is disabled (PERSISTENT_VOLUME_STATE_NO_HEAT_GATHERING).
VOLUME_UNKNOWN_NAME_4000 = 0x4000 # This was a system volume during the Chkdsk scan.
VOLUME_UNKNOWN_NAME_8000 = 0x8000 # A volume was modified by the Chkdsk scan.

# File attributes for the $STANDARD_INFORMATION and $FILE_NAME attributes:
FILE_ATTR_READ_ONLY = 0x0001
FILE_ATTR_HIDDEN = 0x0002
FILE_ATTR_SYSTEM = 0x0004
FILE_ATTR_DIRECTORY = 0x0010
FILE_ATTR_ARCHIVE = 0x0020
FILE_ATTR_DEVICE = 0x0040
FILE_ATTR_NORMAL = 0x0080
FILE_ATTR_TEMPORARY = 0x0100
FILE_ATTR_SPARSE = 0x0200
FILE_ATTR_REPARSE_POINT = 0x0400
FILE_ATTR_COMPRESSED = 0x0800
FILE_ATTR_OFFLINE = 0x1000
FILE_ATTR_NOT_CONTENT_INDEXED = 0x2000
FILE_ATTR_ENCRYPTED = 0x4000
FILE_ATTR_INTEGRITY_STREAM = 0x8000
FILE_ATTR_NO_SCRUB_DATA = 0x20000
FILE_ATTR_RECALL_ON_DATA_ACCESS = 0x400000
FILE_ATTR_RECALL_ON_OPEN = 0x40000
FILE_ATTR_VIRTUAL = 0x10000

# These flags are valid for the $FILE_NAME attribute:
DUP_FILE_NAME_INDEX_PRESENT = 0x10000000 # Is a directory (a file name index is present).
DUP_FILE_UNKNOWN_NAME_20000000 = 0x20000000 # Is an index file (a view index is present).

FILE_ATTR_LIST = {
	FILE_ATTR_READ_ONLY: 'READ_ONLY',
	FILE_ATTR_HIDDEN: 'HIDDEN',
	FILE_ATTR_SYSTEM: 'SYSTEM',
	FILE_ATTR_DIRECTORY: 'DIRECTORY',
	FILE_ATTR_ARCHIVE: 'ARCHIVE',
	FILE_ATTR_DEVICE: 'DEVICE',
	FILE_ATTR_NORMAL: 'NORMAL',
	FILE_ATTR_TEMPORARY: 'TEMPORARY',
	FILE_ATTR_SPARSE: 'SPARSE',
	FILE_ATTR_REPARSE_POINT: 'REPARSE_POINT',
	FILE_ATTR_COMPRESSED: 'COMPRESSED',
	FILE_ATTR_OFFLINE: 'OFFLINE',
	FILE_ATTR_NOT_CONTENT_INDEXED: 'NOT_CONTENT_INDEXED',
	FILE_ATTR_ENCRYPTED: 'ENCRYPTED',
	FILE_ATTR_INTEGRITY_STREAM: 'INTEGRITY_STREAM',
	FILE_ATTR_NO_SCRUB_DATA: 'NO_SCRUB_DATA',
	FILE_ATTR_RECALL_ON_DATA_ACCESS: 'RECALL_ON_DATA_ACCESS',
	FILE_ATTR_RECALL_ON_OPEN: 'RECALL_ON_OPEN',
	FILE_ATTR_VIRTUAL: 'VIRTUAL'
}

# Extra flags for the $STANDARD_INFORMATION attribute:
EXTRA_FLAG_UNKNOWN_NAME_1 = 0x1 # Is case sensitive.

# Flags for the index header:
INDEX_NODE = 0x01 # Is an intermediate node.

# Flags for the index entry:
INDEX_ENTRY_NODE = 0x01 # Is an intermediate node.
INDEX_ENTRY_END = 0x02 # Is an end record.

# Flags for the extended attributes:
FILE_NEED_EA = 0x00000080 # An application should read the extended attribute to interpret a file.

# Some values for index buffers:
MULTI_SECTOR_HEADER_SIGNATURE_INDEX = b'INDX'
UPDATE_SEQUENCE_STRIDE_INDEX = 512

def ResolveFileAttributes(FileAttributes):
	"""Convert file attributes to a string. Only known file attributes are converted."""

	str_list = []
	for file_attr in sorted(FILE_ATTR_LIST.keys()):
		if FileAttributes & file_attr > 0:
			str_list.append(FILE_ATTR_LIST[file_attr])

	return ' | '.join(str_list)

def DecodeFiletime(Timestamp, DoNotRaise = True):
	"""Decode the FILETIME timestamp and return the datetime object."""

	try:
		return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds = Timestamp / 10)
	except Exception: # Allow a caller to handle an invalid timestamp.
		if not DoNotRaise:
			raise

		return

def DecodeGUIDTime(Timestamp, DoNotRaise = True):
	"""Decode the GUID timestamp and return the datetime object."""

	try:
		return datetime.datetime(1582, 10, 15) + datetime.timedelta(microseconds = Timestamp / 10)
	except Exception: # Allow a caller to handle an invalid timestamp.
		if not DoNotRaise:
			raise

		return

def VerifyAndUnprotectIndexSectors(Buffer):
	"""Apply an update sequence array (USA) to multiple sectors (as a bytearray object), verify and return the resulting buffer. Only an index buffer can be used as input data.
	If something is wrong with input data, return None.
	"""

	if len(Buffer) < 2 * UPDATE_SEQUENCE_STRIDE_INDEX or len(Buffer) % UPDATE_SEQUENCE_STRIDE_INDEX != 0:
		return

	usa_offset, usa_size = struct.unpack('<HH', Buffer[4 : 8])

	if usa_offset < 40 or usa_offset > UPDATE_SEQUENCE_STRIDE_INDEX - 6:
		return

	if usa_size < 2 or (usa_size - 1) * UPDATE_SEQUENCE_STRIDE_INDEX != len(Buffer):
		return

	if usa_offset + usa_size * 2 >= len(Buffer):
		return

	sequence_number_in_usa_bytes = Buffer[usa_offset : usa_offset + 2]

	i = 1 # Skip the first element (sequence_number_in_usa_bytes).
	while i < usa_size:
		offset_in_usa = i * 2
		update_bytes = Buffer[usa_offset + offset_in_usa : usa_offset + offset_in_usa + 2]

		offset_in_buf = i * UPDATE_SEQUENCE_STRIDE_INDEX - 2
		sequence_number_in_sector_bytes = Buffer[offset_in_buf : offset_in_buf + 2]

		if sequence_number_in_usa_bytes != sequence_number_in_sector_bytes:
			return

		Buffer[offset_in_buf] = update_bytes[0]
		Buffer[offset_in_buf + 1] = update_bytes[1]

		i += 1

	end_of_usa_offset = usa_offset + usa_size * 2

	signature = Buffer[ : 4]
	if signature != MULTI_SECTOR_HEADER_SIGNATURE_INDEX:
		return

	return Buffer

class GenericAttribute(object):
	"""This class is used to describe a generic attribute (either resident or nonresident)."""

	value = None
	"""This attribute as raw bytes."""

	def __init__(self, value):
		self.value = value

class GenericAttributeNonresident(object):
	"""This class is used to describe a generic nonresident attribute.
	This class should be used for a large nonresident attribute.
	"""

	fragmented_file = None
	"""Data of this attribute as a file-like object."""

	def __init__(self, fragmented_file):
		self.fragmented_file = fragmented_file

class StandardInformation(GenericAttribute):
	"""$STANDARD_INFORMATION."""

	def get_ctime(self):
		"""Get, decode and return the C (file created) timestamp."""

		timestamp_int = struct.unpack('<Q', self.value[0 : 8])[0]
		return DecodeFiletime(timestamp_int)

	def get_mtime(self):
		"""Get, decode and return the M (file modified) timestamp."""

		timestamp_int = struct.unpack('<Q', self.value[8 : 16])[0]
		return DecodeFiletime(timestamp_int)

	def get_etime(self):
		"""Get, decode and return the E ($MFT entry modified) timestamp."""

		timestamp_int = struct.unpack('<Q', self.value[16 : 24])[0]
		return DecodeFiletime(timestamp_int)

	def get_atime(self):
		"""Get, decode and return the A (file last accessed) timestamp."""

		timestamp_int = struct.unpack('<Q', self.value[24 : 32])[0]
		return DecodeFiletime(timestamp_int)

	def get_file_attributes(self):
		"""Get and return the file attributes (as an integer)."""

		return struct.unpack('<L', self.value[32 : 36])[0]

	def get_maximum_versions(self):
		"""Get and return the maximum versions allowed for this file."""

		return struct.unpack('<L', self.value[36 : 40])[0]

	def get_version_number(self):
		"""Get and return the version number for this file."""

		return struct.unpack('<L', self.value[40 : 44])[0]

	def get_extra_flags(self):
		"""Get and return the extra flags for this file."""

		return struct.unpack('<L', self.value[40 : 44])[0] # The same offset as above!

	def is_case_sensitive(self):
		"""Check if the file (directory) is case sensitive."""

		return self.get_extra_flags() & EXTRA_FLAG_UNKNOWN_NAME_1 > 0

	def get_storage_reserve_id(self):
		"""Get and return the storage reserve ID."""

		return (self.get_extra_flags() >> 8) & 0xFF

	def get_class_id(self):
		"""Get and return the class ID for this file."""

		return struct.unpack('<L', self.value[44 : 48])[0]

	def get_owner_id(self):
		"""Get and return the owner ID for this file."""

		data = self.value[48 : 52]
		if len(data) == 4:
			return struct.unpack('<L', data)[0]

	def get_security_id(self):
		"""Get and return the security ID for this file."""

		data = self.value[52 : 56]
		if len(data) == 4:
			return struct.unpack('<L', data)[0]

	def get_quota_charged(self):
		"""Get and return the amount of quota already charged for this file."""

		data = self.value[56 : 64]
		if len(data) == 8:
			return struct.unpack('<Q', data)[0]

	def get_usn(self):
		"""Get and return the update sequence number (USN) for this file."""

		data = self.value[64 : 72]
		if len(data) == 8:
			return struct.unpack('<Q', data)[0]

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$STANDARD_INFORMATION:')
		print(' File created: {}'.format(self.get_ctime()))
		print(' File modified: {}'.format(self.get_mtime()))
		print(' File last accessed: {}'.format(self.get_atime()))
		print(' $MFT entry modified: {}'.format(self.get_etime()))
		print(' File attributes: {}'.format(hex(self.get_file_attributes())))
		print(' Current version, maximum versions: {}, {}'.format(self.get_version_number(), self.get_maximum_versions()))
		print(' Is case sensitive: {}'.format(self.is_case_sensitive()))
		print(' Storage reserve ID: {}'.format(self.get_storage_reserve_id()))
		print(' Class ID, owner ID, security ID: {}, {}, {}'.format(self.get_class_id(), self.get_owner_id(), self.get_security_id()))
		print(' Quota charged: {}'.format(self.get_quota_charged()))
		print(' Update sequence number: {}'.format(self.get_usn()))

class StandardInformationPartial(object):
	"""Partial $STANDARD_INFORMATION (as seen in the $LogFile journal)."""

	def __init__(self, value, offset):
		self.value = (b'\x00' * offset) + value
		self.offset = offset

	def get_ctime(self):
		"""Get, decode and return the C (file created) timestamp."""

		if self.offset == 0 and len(self.value) >= 8:
			timestamp_int = struct.unpack('<Q', self.value[0 : 8])[0]
			return DecodeFiletime(timestamp_int)

	def get_mtime(self):
		"""Get, decode and return the M (file modified) timestamp."""

		if self.offset <= 8 and len(self.value) >= 16:
			timestamp_int = struct.unpack('<Q', self.value[8 : 16])[0]
			return DecodeFiletime(timestamp_int)

	def get_etime(self):
		"""Get, decode and return the E ($MFT entry modified) timestamp."""

		if self.offset <= 16 and len(self.value) >= 24:
			timestamp_int = struct.unpack('<Q', self.value[16 : 24])[0]
			return DecodeFiletime(timestamp_int)

	def get_atime(self):
		"""Get, decode and return the A (file last accessed) timestamp."""

		if self.offset <= 24 and len(self.value) >= 32:
			timestamp_int = struct.unpack('<Q', self.value[24 : 32])[0]
			return DecodeFiletime(timestamp_int)

class DuplicatedInformation(object):
	"""DUPLICATED_INFORMATION (not an attribute)."""

	def __init__(self, value, offset = 0):
		self.value_di = value[offset : ]

	def get_ctime(self):
		"""Get, decode and return the C (file created) timestamp."""

		timestamp_int = struct.unpack('<Q', self.value_di[0 : 8])[0]
		return DecodeFiletime(timestamp_int)

	def get_mtime(self):
		"""Get, decode and return the M (file modified) timestamp."""

		timestamp_int = struct.unpack('<Q', self.value_di[8 : 16])[0]
		return DecodeFiletime(timestamp_int)

	def get_etime(self):
		"""Get, decode and return the E ($MFT entry modified) timestamp."""

		timestamp_int = struct.unpack('<Q', self.value_di[16 : 24])[0]
		return DecodeFiletime(timestamp_int)

	def get_atime(self):
		"""Get, decode and return the A (file last accessed) timestamp."""

		timestamp_int = struct.unpack('<Q', self.value_di[24 : 32])[0]
		return DecodeFiletime(timestamp_int)

	def get_allocated_length(self):
		"""Get and return the allocated length for this file."""

		return struct.unpack('<q', self.value_di[32 : 40])[0]

	def get_file_size(self):
		"""Get and return the file size."""

		return struct.unpack('<q', self.value_di[40 : 48])[0]

	def get_file_attributes(self):
		"""Get and return the file attributes (as an integer)."""

		return struct.unpack('<L', self.value_di[48 : 52])[0]

	def get_packed_ea_size(self):
		"""Get and return the size required to store packed extended attributes."""

		return struct.unpack('<H', self.value_di[52 : 54])[0]

	def get_unpacked_ea_size_difference(self):
		"""Get and return the difference between the size required to store unpacked (aligned in memory) extended attributes and the size required to store packed extended attributes.
		If this value is smaller than 4, then 4 should be assumed.
		"""

		return struct.unpack('<H', self.value_di[54 : 56])[0]

class FileName(GenericAttribute, DuplicatedInformation):
	"""$FILE_NAME."""

	def __init__(self, value):
		GenericAttribute.__init__(self, value)
		DuplicatedInformation.__init__(self, value, 8)

	def get_parent_directory(self):
		"""Get and return the file reference to a parent directory."""

		return struct.unpack('<Q', self.value[0 : 8])[0]

	# Field methods below must account the size of the DUPLICATED_INFORMATION structure.

	def get_file_name_length(self):
		"""Get and return the file name length in characters."""

		return struct.unpack('B', self.value[64 : 65])[0]

	def get_flags(self):
		"""Get and return the flags (as an integer) for this file name."""

		return struct.unpack('B', self.value[65 : 66])[0]

	def get_file_name(self):
		"""Get, decode and return the file name."""

		filename_raw = self.value[66 : 66 + 2 * self.get_file_name_length()]
		return filename_raw.decode('utf-16le', errors = 'replace')

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$FILE_NAME:')
		print(' Parent directory: {}'.format(self.get_parent_directory()))
		print(' File created: {}'.format(self.get_ctime()))
		print(' File modified: {}'.format(self.get_mtime()))
		print(' File last accessed: {}'.format(self.get_atime()))
		print(' $MFT entry modified: {}'.format(self.get_etime()))
		print(' Allocated length, file size: {}, {}'.format(self.get_allocated_length(), self.get_file_size()))
		print(' File attributes: {}'.format(hex(self.get_file_attributes())))
		print(' Packed EA size, unpacked EA size difference: {}, {}'.format(self.get_packed_ea_size(), self.get_unpacked_ea_size_difference()))
		print(' Flags: {}'.format(hex(self.get_flags())))
		print(' File name (decoded): {}'.format(self.get_file_name()))

class ObjectID(GenericAttribute):
	"""$OBJECT_ID."""

	def get_object_id(self):
		"""Get, decode and return the object ID."""

		data = bytes(self.value[0 : 16])
		if len(data) != 16:
			return

		return uuid.UUID(bytes_le = data)

	def get_timestamp(self):
		"""Get, decode and return the timestamp from the object ID (if possible)."""

		guid = self.get_object_id()
		if guid is not None and guid.version == 1:
			return DecodeGUIDTime(guid.time)

	def get_extra_data(self):
		"""Get and return extra data (as raw bytes)."""

		return self.value[16 : ]

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$OBJECT_ID:')
		print(' GUID: {}'.format(self.get_object_id()))
		print(' GUID timestamp: {}'.format(self.get_timestamp()))
		if len(self.get_extra_data()) > 0:
			print(' Extra data is set')

class Data(GenericAttribute):
	"""$DATA."""

	def print_information(self):
		"""Print all information in a human-readable form."""

		if self.value is not None:
			print('$DATA:')
			print(' Length (bytes): {}'.format(len(self.value)))
		else:
			print('$DATA')

AttributeListEntry = namedtuple('AttributeListEntry', [ 'attribute_type_code', 'attribute_name', 'attribute_instance', 'lowest_vcn', 'segment_reference' ])

class AttributeList(GenericAttribute):
	"""$ATTRIBUTE_LIST."""

	def entries(self):
		"""This method yields each attribute list entry (AttributeListEntry)."""

		pos = 0
		while pos < len(self.value):
			list_entry_header = self.value[pos : pos + 26]
			if len(list_entry_header) != 26: # The end.
				break

			attribute_type_code, record_length, attribute_name_length, attribute_name_offset, lowest_vcn, segment_reference, attribute_instance = struct.unpack('<LHBBQQH', list_entry_header)

			if record_length < 26: # This list entry is invalid.
				break

			if attribute_name_length > 0:
				if attribute_name_offset + attribute_name_length * 2 > record_length: # This list entry is invalid.
					break

				attribute_name_raw = self.value[pos + attribute_name_offset : pos + attribute_name_offset + attribute_name_length * 2]
				attribute_name = attribute_name_raw.decode('utf-16le', errors = 'replace')
			else:
				attribute_name = None

			yield AttributeListEntry(attribute_type_code = attribute_type_code, attribute_name = attribute_name, attribute_instance = attribute_instance, lowest_vcn = lowest_vcn, segment_reference = segment_reference)

			if record_length % 8 == 0:
				record_length_aligned = record_length
			else:
				record_length_aligned = record_length + 8 - record_length % 8

			pos += record_length_aligned

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$ATTRIBUTE_LIST:')

		i = 1
		for list_entry in self.entries():
			if list_entry.attribute_name is None:
				name_str = 'no name'
			else:
				name_str = 'name: {}'.format(list_entry.attribute_name)

			print(' Attribute #{} type code: {}, {}'.format(i, hex(list_entry.attribute_type_code), name_str))
			print(' Attribute #{} instance: {}, lowest VCN: {}, segment reference: {}'.format(i, list_entry.attribute_instance, list_entry.lowest_vcn, list_entry.segment_reference))

			i += 1

class SecurityDescriptor(GenericAttribute):
	"""$SECURITY_DESCRIPTOR."""

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$SECURITY_DESCRIPTOR:')
		print(' Length (bytes): {}'.format(len(self.value)))

class VolumeName(GenericAttribute):
	"""$VOLUME_NAME."""

	def get_name(self):
		"""Get and return the decoded volume name."""

		return self.value.decode('utf-16le', errors = 'replace')

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$VOLUME_NAME:')
		print(' Volume name: {}'.format(self.get_name()))

class VolumeInformation(GenericAttribute):
	"""$VOLUME_INFORMATION."""

	def get_major_version(self):
		"""Get and return the major version number."""

		return struct.unpack('B', self.value[8 : 9])[0]


	def get_minor_version(self):
		"""Get and return the minor version number."""

		return struct.unpack('B', self.value[9 : 10])[0]

	def get_flags(self):
		"""Get and return the flags (as an integer)."""

		return struct.unpack('<H', self.value[10 : 12])[0]

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$VOLUME_INFORMATION:')
		print(' Version: {}.{}'.format(self.get_major_version(), self.get_minor_version()))
		print(' Flags: {}'.format(hex(self.get_flags())))

class IndexHeader(object):
	"""This class is used to describe the index header."""

	def __init__(self, index_header_raw):
		self.index_header_raw = index_header_raw

	def get_first_index_entry(self):
		"""Get and return the relative offset to the first index entry."""

		return struct.unpack('<L', self.index_header_raw[0 : 4])[0]

	def get_first_free_byte(self):
		"""Get and return the relative offset to the first free byte."""

		return struct.unpack('<L', self.index_header_raw[4 : 8])[0]

	def get_bytes_available(self):
		"""Get and return the total number of bytes available, starting from the first index entry."""

		return struct.unpack('<L', self.index_header_raw[8 : 12])[0]

	def get_flags(self):
		"""Get and return the flags for the index header (as an integer)."""

		return struct.unpack('B', self.index_header_raw[12 : 13])[0]

class IndexEntry(object):
	"""This class is used to describe the index entry (in the directory index)."""

	def __init__(self, index_entry_raw):
		self.index_entry_raw = index_entry_raw

	def get_file_reference(self):
		"""Get and return the file reference."""

		return struct.unpack('<Q', self.index_entry_raw[0 : 8])[0]

	def get_length(self):
		"""Get and return the length of this index entry."""

		return struct.unpack('<H', self.index_entry_raw[8 : 10])[0]

	def get_attribute_length(self):
		"""Get and return the length of the attribute in this index entry."""

		return struct.unpack('<H', self.index_entry_raw[10 : 12])[0]

	def get_flags(self):
		"""Get and return the flags for this index entry (as an integer)."""

		return struct.unpack('<H', self.index_entry_raw[12 : 14])[0]

	def get_attribute(self):
		"""Get and return the attribute (as raw bytes)."""

		attribute_length = self.get_attribute_length()
		if self.get_flags() & INDEX_ENTRY_END == 0 and attribute_length > 0:
			attribute_raw = self.index_entry_raw[16 : 16 + attribute_length]
			return attribute_raw

	def get_vcn(self):
		"""Get and return the subnode VCN."""

		entry_length = self.get_length()
		if self.get_flags() & INDEX_ENTRY_NODE > 0 and entry_length - 8 > 0:
			vcn_raw = self.index_entry_raw[entry_length - 8 : entry_length]
			return struct.unpack('<Q', vcn_raw)[0]

class IndexRoot(GenericAttribute):
	"""$INDEX_ROOT."""

	def get_indexed_attribute_type_code(self):
		"""Get and return the attribute type code used in this index."""

		return struct.unpack('<L', self.value[0 : 4])[0]

	def get_collation_rule(self):
		"""Get and return the collation type for this index."""

		return struct.unpack('<L', self.value[4 : 8])[0]

	def get_bytes_per_index_buffer(self):
		"""Get and return the number of bytes used by the index allocation buffer."""

		return struct.unpack('<L', self.value[8 : 12])[0]

	def get_blocks_per_index_buffer(self):
		"""Get and return the number of blocks used by the index allocation buffer."""

		return struct.unpack('<L', self.value[12 : 16])[0]

	def get_index_header(self):
		"""Get and return the index header (IndexHeader)."""

		index_header_raw = self.value[16 : 32]
		return IndexHeader(index_header_raw)

	def index_entries(self):
		"""This method yields each index entry (IndexEntry)."""

		index_header = self.get_index_header()
		index_entry_pos = 16 + index_header.get_first_index_entry()
		while index_entry_pos < 16 + index_header.get_first_free_byte() and index_entry_pos < len(self.value):
			index_entry_raw = self.value[index_entry_pos : ]
			index_entry = IndexEntry(index_entry_raw)

			index_entry_length = index_entry.get_length()

			if index_entry_length < 16 or index_entry.get_attribute_length() == 0: # This index entry is invalid.
				break

			yield index_entry

			if index_entry_length % 8 != 0:
				index_entry_length_aligned = index_entry_length + 8 - index_entry_length % 8
			else:
				index_entry_length_aligned = index_entry_length

			index_entry_pos += index_entry_length_aligned

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$INDEX_ROOT:')
		print(' Indexed attribute type code: {}'.format(hex(self.get_indexed_attribute_type_code())))
		print(' Collation rule: {}'.format(self.get_collation_rule()))
		print(' Bytes and blocks per the index allocation buffer: {}, {}'.format(self.get_bytes_per_index_buffer(), self.get_blocks_per_index_buffer()))

		index_header = self.get_index_header()
		print('')
		print('Index header:')
		print(' Relative offset to the first index entry: {}'.format(index_header.get_first_index_entry()))
		print(' Relative offset to the first free byte: {}'.format(index_header.get_first_free_byte()))
		print(' Bytes available: {}'.format(index_header.get_bytes_available()))
		print(' Flags: {}'.format(hex(index_header.get_flags())))

		if self.get_indexed_attribute_type_code() == ATTR_TYPE_FILE_NAME:
			print_header = True
			vcn_list = []

			for index_entry in self.index_entries():
				vcn = index_entry.get_vcn()
				if vcn is not None:
					vcn = str(vcn)
				else:
					vcn = '-'

				vcn_list.append(str(vcn))

				attribute_raw = index_entry.get_attribute()
				if attribute_raw is not None:
					attribute = FileName(attribute_raw)

					if print_header:
						print('')
						print('File names in the index:')
						print_header = False

					attribute.print_information()

			if len(vcn_list) > 0:
				print('')
				print('Subnode VCN list: {}'.format(' '.join(vcn_list)))

class IndexBuffer(object):
	"""This class is used to describe the index buffer (in the directory index)."""

	def __init__(self, index_buffer_raw):
		self.index_buffer_raw = index_buffer_raw

	def get_logfile_sequence_number(self):
		"""Get and return the log file sequence number (LSN)."""

		return struct.unpack('<Q', self.index_buffer_raw[8 : 16])[0]

	def get_this_block(self):
		"""Get and return the block number for this index."""

		return struct.unpack('<Q', self.index_buffer_raw[16 : 24])[0]

	def get_index_header(self):
		"""Get and return the index header (IndexHeader)."""

		index_header_raw = self.index_buffer_raw[24 : 40]
		return IndexHeader(index_header_raw)

	def index_entries(self):
		"""This method yields each index entry (IndexEntry)."""

		index_header = self.get_index_header()
		index_entry_pos = 24 + index_header.get_first_index_entry()
		while index_entry_pos < 24 + index_header.get_first_free_byte() and index_entry_pos < len(self.index_buffer_raw):
			index_entry_raw = self.index_buffer_raw[index_entry_pos : ]
			index_entry = IndexEntry(index_entry_raw)

			index_entry_length = index_entry.get_length()

			if index_entry_length < 16 or index_entry.get_attribute_length() == 0: # This index entry is invalid.
				break

			yield index_entry

			if index_entry.get_flags() & INDEX_ENTRY_END > 0:
				break

			if index_entry_length % 8 != 0:
				index_entry_length_aligned = index_entry_length + 8 - index_entry_length % 8
			else:
				index_entry_length_aligned = index_entry_length

			index_entry_pos += index_entry_length_aligned

	def get_slack(self):
		"""Get and return the slack space (as raw bytes)."""

		index_header = self.get_index_header()
		return self.index_buffer_raw[24 + index_header.get_first_free_byte() : ]

class IndexAllocation(GenericAttributeNonresident):
	"""$INDEX_ALLOCATION."""

	index_buffer_size = None
	"""A size of each index buffer."""

	def __init__(self, fragmented_file):
		super(IndexAllocation, self).__init__(fragmented_file)

		# Try to determine the index buffer size for this attribute.
		self.fragmented_file.seek(4)
		usa_offset_and_size_raw = self.fragmented_file.read(4)

		if len(usa_offset_and_size_raw) == 4:
			usa_offset, usa_size = struct.unpack('<HH', usa_offset_and_size_raw)
			if usa_size - 1 >= 2:
				index_buffer_size = (usa_size - 1) * UPDATE_SEQUENCE_STRIDE_INDEX

				if index_buffer_size > 0 and index_buffer_size % 512 == 0 and index_buffer_size <= 240640: # (512-40-2)*512=240640.
					self.fragmented_file.seek(0)
					index_buf = bytearray(self.fragmented_file.read(index_buffer_size))

					if len(index_buf) != index_buffer_size or VerifyAndUnprotectIndexSectors(index_buf) is None:
						# Something is wrong with the first index buffer.
						self.index_buffer_size = None
					else:
						self.index_buffer_size = index_buffer_size

	def index_buffers(self):
		"""This method yields each index buffer (IndexBuffer)."""

		if self.index_buffer_size is not None:
			i = 0
			while True:
				self.fragmented_file.seek(i * self.index_buffer_size)
				index_buf_raw = bytearray(self.fragmented_file.read(self.index_buffer_size))

				if len(index_buf_raw) != self.index_buffer_size:
					break

				index_buf = VerifyAndUnprotectIndexSectors(index_buf_raw)
				if index_buf is not None:
					yield IndexBuffer(index_buf)

				i += 1

	def get_slack(self):
		"""Get and return the slack space (as a list of raw bytes)."""

		slack_space_list = []
		for index_buf in self.index_buffers():
			slack_space = index_buf.get_slack()

			if len(slack_space) <= 8: # Ignore small chunks of index slack data.
				continue

			slack_space_list.append(slack_space)

		return slack_space_list

	def print_information(self):
		"""Print all information in a human-readable form."""

		if self.index_buffer_size is None:
			index_buffer_size = 'unknown'
		else:
			index_buffer_size = self.index_buffer_size

		print('$INDEX_ALLOCATION')
		print(' Bytes per index buffer: {}'.format(index_buffer_size))
		print(' Length: {}'.format(self.fragmented_file.file_size))

class Bitmap(GenericAttribute):
	"""$BITMAP."""

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$BITMAP:')
		print(' Length (bits): {}'.format(len(self.value) * 8))

class ReparsePoint(GenericAttribute):
	"""$REPARSE_POINT."""

	def get_reparse_tag(self):
		"""Get and return the reparse tag."""

		return struct.unpack('<L', self.value[0 : 4])[0]

	def is_reparse_tag_microsoft(self):
		"""Check if the reparse tag is used by Microsoft."""

		return self.get_reparse_tag() & 0x80000000 > 0

	def get_reparse_data_length(self):
		"""Get and return the reparse data length."""

		return struct.unpack('<H', self.value[4 : 6])[0]

	def get_reparse_guid(self):
		"""Get and return the reparse GUID. Third-party reparse points only!"""

		if not self.is_reparse_tag_microsoft():
			data = self.value[8 : 24]
			return uuid.UUID(bytes_le = data)

	def get_reparse_buffer(self):
		"""Get and return the reparse buffer."""

		if self.is_reparse_tag_microsoft():
			return self.value[8 : 8 + self.get_reparse_data_length()]
		else:
			return self.value[24 : 24 + self.get_reparse_data_length()]

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$REPARSE_POINT:')
		print(' Reparse tag: {} (is Microsoft: {})'.format(hex(self.get_reparse_tag()), self.is_reparse_tag_microsoft()))
		print(' Reparse data length: {}'.format(self.get_reparse_data_length()))

class EAInformation(GenericAttribute):
	"""$EA_INFORMATION."""

	def get_packed_ea_size(self):
		"""Get and return the size required to store packed extended attributes."""

		return struct.unpack('<H', self.value[0 : 2])[0]

	def get_need_ea_count(self):
		"""Get and return the number of extended attributes with the NEED_EA flag set."""

		return struct.unpack('<H', self.value[2 : 4])[0]

	def get_unpacked_ea_size(self):
		"""Get and return the size required to store unpacked (aligned in memory) extended attributes."""

		return struct.unpack('<L', self.value[4 : 8])[0]

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$EA_INFORMATION:')
		print(' Packed EA size: {}'.format(self.get_packed_ea_size()))
		print(' Need EA count: {}'.format(self.get_need_ea_count()))
		print(' Unpacked EA size: {}'.format(self.get_unpacked_ea_size()))

class EA(GenericAttribute):
	"""$EA."""

	def data_parsed(self):
		"""Attempt to parse the extended attribute and yield (name, flags, value) tuples."""

		buf = self.value[:]
		while True:
			if len(buf) <= 8:
				break

			next_entry_offset, flags, ea_name_length, ea_value_length = struct.unpack('<LBBH', buf[: 8])

			# 1. According to Microsoft, the 'NextEntryOffset' field contains "the offset of the next FILE_FULL_EA_INFORMATION-type entry".
			# However, this offset is relative from the current entry.
			# 2. Also, according to Microsoft, "this member is zero if no other entries follow this one".
			# This is not always the case.
			# 3. Finally, according to Microsoft, "the value(s) associated with each entry follows the EaName array".
			# However, according to the implementation of the IoCheckEaBufferValidity() routine, only one value is allowed.
			# ---
			# URL: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_file_full_ea_information

			if 9 + ea_name_length + ea_value_length > len(buf) or next_entry_offset > len(buf): # The extended attribute is invalid.
				break

			name = buf[8 : 8 + ea_name_length + 1] # Include the null character.
			value = buf[8 + ea_name_length + 1 : 8 + ea_name_length + 1 + ea_value_length]

			if name[-1] != 0: # The name is invalid.
				break

			if len(value) != ea_value_length: # The value is invalid.
				break

			yield (bytes(name), flags, value)

			if next_entry_offset == 0: # The end.
				break

			buf = buf[next_entry_offset : ]

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$EA:')
		print(' Length (bytes): {}'.format(len(self.value)))

		i = 1
		for name, flags, value in self.data_parsed():
			print(' EA #{} name: {}'.format(i, name.decode('utf-8', errors = 'replace')))
			print(' EA #{} flags: {}'.format(i, hex(flags)))
			print(' EA #{} value length (bytes): {}'.format(i, len(value)))

			i += 1

class LoggedUtilityStream(GenericAttribute):
	"""$LOGGED_UTILITY_STREAM."""

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('$LOGGED_UTILITY_STREAM:')
		print(' Length (bytes): {}'.format(len(self.value)))

AttributeTypes = {
	ATTR_TYPE_STANDARD_INFORMATION: ('$STANDARD_INFORMATION', StandardInformation),
	ATTR_TYPE_ATTRIBUTE_LIST: ('$ATTRIBUTE_LIST', AttributeList),
	ATTR_TYPE_FILE_NAME: ('$FILE_NAME', FileName),
	ATTR_TYPE_OBJECT_ID: ('$OBJECT_ID', ObjectID),
	ATTR_TYPE_SECURITY_DESCRIPTOR: ('$SECURITY_DESCRIPTOR', SecurityDescriptor),
	ATTR_TYPE_VOLUME_NAME: ('$VOLUME_NAME', VolumeName),
	ATTR_TYPE_VOLUME_INFORMATION: ('$VOLUME_INFORMATION', VolumeInformation),
	ATTR_TYPE_DATA: ('$DATA', Data),
	ATTR_TYPE_INDEX_ROOT: ('$INDEX_ROOT', IndexRoot),
	ATTR_TYPE_INDEX_ALLOCATION: ('$INDEX_ALLOCATION', IndexAllocation),
	ATTR_TYPE_BITMAP: ('$BITMAP', Bitmap),
	ATTR_TYPE_REPARSE_POINT: ('$REPARSE_POINT', ReparsePoint),
	ATTR_TYPE_EA_INFORMATION: ('$EA_INFORMATION', EAInformation),
	ATTR_TYPE_EA: ('$EA', EA),
	ATTR_TYPE_LOGGED_UTILITY_STREAM: ('$LOGGED_UTILITY_STREAM', LoggedUtilityStream)
}
