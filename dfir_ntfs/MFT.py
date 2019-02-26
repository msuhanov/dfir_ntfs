# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with file record segments and file records in an $MFT file.

from . import Attributes
import struct

FILE_RECORD_SEGMENT_SIZES_SUPPORTED = [ 1024, 4096 ]
MULTI_SECTOR_HEADER_SIGNATURE_GOOD = b'FILE'
MULTI_SECTOR_HEADER_SIGNATURES_SUPPORTED = [ MULTI_SECTOR_HEADER_SIGNATURE_GOOD, b'BAAD', b'CHKD' ]
UPDATE_SEQUENCE_STRIDE = 512 # This is true even for 4Kn drives.

PATH_SEPARATOR = '/' # Do not use the backslash (it is a valid character for a file name)!
UNKNOWN_PATH_PLACEHOLDER = '<Orphan>' # Orphan file records go here. A path separator is not used before this placeholder! (So the path is unambiguous.)

# Flags for the file record segment (FRS):
FILE_RECORD_SEGMENT_IN_USE = 1 # Is in use (allocated).
FILE_FILE_NAME_INDEX_PRESENT = 2 # Is a directory.
FILE_UNKNOWN_NAME_4 = 4 # The file quota is never charged; this file cannot be opened by its FRS reference number (unless a special flag is given).
FILE_UNKNOWN_NAME_8 = 8 # Is an index file.

# Form codes for the file record segment (FRS):
FORM_CODE_RESIDENT = 0
FORM_CODE_NONRESIDENT = 1

# Special files:
FILE_NUMBER_MFT = 0
FILE_NUMBER_MFTMIRR = 1
FILE_NUMBER_LOGFILE = 2
FILE_NUMBER_VOLUME = 3
FILE_NUMBER_ATTRDEF = 4
FILE_NUMBER_ROOT = 5
FILE_NUMBER_BITMAP = 6
FILE_NUMBER_BOOT = 7
FILE_NUMBER_BADCLUS = 8
FILE_NUMBER_SECURE = 9
FILE_NUMBER_UPCASE = 10
FILE_NUMBER_EXTEND = 11

class MasterFileTableException(Exception):
	"""This is a top-level exception for this module."""

	pass

class FileRecordSegmentException(MasterFileTableException):
	"""This exception is raised when something is wrong with a file record segment (FRS)."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class FileRecordSegmentSignatureException(FileRecordSegmentException):
	"""This exception is raised when a file record segment (FRS) does not have a valid signature."""

	pass

class AttributeException(FileRecordSegmentException):
	"""This exception is raised when a file record segment (FRS) contains an invalid attribute."""

	pass

def DecodeFileRecordSegmentReference(ReferenceNumber):
	"""Decode a file record segment reference, return the (file_record_segment_number, sequence_number) tuple."""

	file_record_segment_number = ReferenceNumber & 0xFFFFFFFFFFFF
	sequence_number = ReferenceNumber >> 48

	return (file_record_segment_number, sequence_number)

def EncodeFileRecordSegmentReference(FileRecordSegmentNumber, SequenceNumber):
	"""Encode a file record segment reference and return it."""

	return (SequenceNumber << 48) | FileRecordSegmentNumber

def ResolveAttributeType(TypeCode):
	"""Convert a type code of an attribute to a string."""

	if TypeCode in Attributes.AttributeTypes.keys():
		return Attributes.AttributeTypes[TypeCode][0]

	return hex(TypeCode) # An unknown attribute.

def UnpackAttributeRecordPartialHeader(Buffer):
	"""Unpack the first 16 bytes of the attribute record header, return a tuple: (type_code, record_length, form_code, name_length, name_offset, flags, instance)."""

	return struct.unpack('<LLBBHHH', Buffer)

def UnpackAttributeRecordRemainingHeaderResident(Buffer):
	"""Unpack the remaining 8 bytes of the attribute record header, return a tuple: (value_length, value_offset, resident_flags, reserved).
	Note: this is for resident attributes only.
	"""

	return struct.unpack('<LHBB', Buffer)

class FileRecordSegment(object):
	"""This class is used to work with a file record segment (FRS)."""

	frs_data = None
	"""Data of a file record segment (FRS) with updates from an update sequence array (USA) applied (if requested)."""

	usa_offset = None
	"""A relative offset of an update sequence array (USA)."""

	usa_size = None
	"""A size of an update sequence array (USA)."""

	frs_real_size = None
	"""A real size of this file record segment (FRS)."""

	def __init__(self, file_record_segment_buf, apply_update_sequence_array = True):
		"""Create a FileRecordSegment object from bytes (the 'file_record_segment_buf' argument). Apply an update sequence array, if requested (the 'apply_update_sequence_array' argument)."""

		if len(file_record_segment_buf) not in FILE_RECORD_SEGMENT_SIZES_SUPPORTED:
			raise FileRecordSegmentException('Invalid (unsupported) size of the file record segment: {}'.format(len(file_record_segment_buf)))

		self.frs_data = bytearray(file_record_segment_buf)
		self.usa_offset, self.usa_size = self.parse_and_validate_multi_sector_header(apply_update_sequence_array)

		if apply_update_sequence_array:
			usa_elements_applied = self.apply_update_sequence_array()
			if usa_elements_applied == 0:
				raise FileRecordSegmentException('No update elements applied')

		self.validate_file_record_segment_header()

	def parse_and_validate_multi_sector_header(self, validate_update_sequence_array_offset_and_size = True):
		"""Parse and validate a multisector header, return the (usa_offset, usa_size) tuple, which describes an update sequence array (USA).
		If a multisector header is invalid, an exception (FileRecordSegmentException) is raised.
		"""

		signature, usa_offset, usa_size = struct.unpack('<4sHH', self.frs_data[ : 8])
		if signature not in MULTI_SECTOR_HEADER_SIGNATURES_SUPPORTED:
			raise FileRecordSegmentSignatureException('Invalid signature: {}'.format(signature))

		if validate_update_sequence_array_offset_and_size:
			# These are sanity checks for the update sequence array.
			if usa_offset < 42 or usa_offset > UPDATE_SEQUENCE_STRIDE - 6:
				raise FileRecordSegmentException('Invalid update sequence array offset: {}'.format(usa_offset))

			if usa_size < 2 or (usa_size - 1) * UPDATE_SEQUENCE_STRIDE != len(self.frs_data):
				raise FileRecordSegmentException('Invalid update sequence array size: {}'.format(usa_size))

			if usa_offset + usa_size * 2 >= len(self.frs_data):
				raise FileRecordSegmentException('Invalid update sequence array offset and size: {}, {}'.format(usa_offset, usa_size))

		return (usa_offset, usa_size)

	def apply_update_sequence_array(self):
		"""Apply an update sequence array (USA) to a file record segment (FRS), return the number of updates applied."""

		sequence_number_in_usa_bytes = self.frs_data[self.usa_offset : self.usa_offset + 2]

		i = 1 # Skip the first element (sequence_number_in_usa_bytes).
		usa_elements_applied = 0
		while i < self.usa_size:
			offset_in_usa = i * 2
			update_bytes = self.frs_data[self.usa_offset + offset_in_usa : self.usa_offset + offset_in_usa + 2]

			offset_in_frs = i * UPDATE_SEQUENCE_STRIDE - 2
			sequence_number_in_sector_bytes = self.frs_data[offset_in_frs : offset_in_frs + 2]

			if sequence_number_in_usa_bytes != sequence_number_in_sector_bytes:
				if usa_elements_applied * UPDATE_SEQUENCE_STRIDE < self.get_first_free_byte_offset():
					raise FileRecordSegmentException('Invalid sequence number in the file record segment, relative offset: {}'.format(offset_in_frs))
				elif usa_elements_applied > 0:
					# Do not raise an exception if an error did not touch the used data region.
					# If the offset to the first free byte is invalid, we will raise an exception later.
					break

			self.frs_data[offset_in_frs] = update_bytes[0]
			self.frs_data[offset_in_frs + 1] = update_bytes[1]

			i += 1
			usa_elements_applied += 1

		return usa_elements_applied

	def validate_file_record_segment_header(self):
		"""Validate a file record segment (FRS) header. If a file record segment (FRS) is invalid, an exception (FileRecordSegmentException) is raised."""

		file_record_segment_size = self.get_file_record_segment_size()

		if file_record_segment_size not in FILE_RECORD_SEGMENT_SIZES_SUPPORTED:
			raise FileRecordSegmentException('Invalid (unsupported) declared size of the file record segment: {}'.format(file_record_segment_size))

		if file_record_segment_size > len(self.frs_data): # We allow extra bytes at the end of the buffer.
			raise FileRecordSegmentException('Invalid length of input data: {} > {}'.format(file_record_segment_size, len(self.frs_data)))

		# Sanity check for the offset to the first free byte.
		first_free_byte_offset = self.get_first_free_byte_offset()
		if first_free_byte_offset < 42 or first_free_byte_offset > file_record_segment_size:
			raise FileRecordSegmentException('Invalid offset to the first free byte: {}'.format(first_free_byte_offset))

		# Sanity check for the offset to the first attribute.
		first_attribute_offset = self.get_first_attribute_offset()
		if first_attribute_offset < 8 or first_attribute_offset % 8 != 0 or first_attribute_offset > file_record_segment_size - 24 or first_attribute_offset < self.usa_offset + self.usa_size * 2:
			raise FileRecordSegmentException('Invalid offset to the first attribute: {}'.format(first_attribute_offset))

	def is_bad(self):
		"""Check if a file record segment (FRS) is bad."""

		return struct.unpack('<4s', self.frs_data[ : 4])[0] != MULTI_SECTOR_HEADER_SIGNATURE_GOOD

	def get_logfile_sequence_number(self):
		"""Get and return a log file sequence number (LSN)."""

		return struct.unpack('<Q', self.frs_data[8 : 16])[0]

	def get_sequence_number(self):
		"""Get and return a sequence number."""

		return struct.unpack('<H', self.frs_data[16 : 18])[0]

	def get_reference_count(self):
		"""Get and return a reference count."""

		return struct.unpack('<H', self.frs_data[18 : 20])[0]

	def get_first_attribute_offset(self):
		"""Get and return a relative offset to the first attribute."""

		return struct.unpack('<H', self.frs_data[20 : 22])[0]

	def get_flags(self):
		"""Get and return flags (as a number)."""

		return struct.unpack('<H', self.frs_data[22 : 24])[0]

	def is_in_use(self):
		"""Check if a file record segment (FRS) is in use (according to its flags)."""

		return self.get_flags() & FILE_RECORD_SEGMENT_IN_USE > 0

	def get_first_free_byte_offset(self):
		"""Get and return a relative offset to the first free byte in this file record segment (FRS)."""

		return struct.unpack('<L', self.frs_data[24 : 28])[0]

	def get_file_record_segment_size(self):
		"""Get and return a size of this file record segment (FRS)."""

		return struct.unpack('<L', self.frs_data[28 : 32])[0]

	def get_base_file_record_segment(self):
		"""Get and return a reference to a base file record segment (a base FRS)."""

		return struct.unpack('<Q', self.frs_data[32 : 40])[0]

	def is_base_file_record_segment(self):
		"""Check if a file record segment (FRS) is a base one."""

		return self.get_base_file_record_segment() == 0

	def get_next_attribute_instance(self):
		"""Get an attribute instance number to be used for a new allocation and return it."""

		return struct.unpack('<H', self.frs_data[40 : 42])[0]

	def get_master_file_table_number(self):
		"""Get an $MFT number for this file record segment (FRS) and return it."""

		# This is a 48-bit integer (other sources incorrectly state that this is a 32-bit integer), but the higher part (16 bits) is stored in the lower bytes.
		mft_number_hi, mft_number_lo = struct.unpack('<HL', self.frs_data[42 : 48])
		return (mft_number_hi << 32) | mft_number_lo

	def get_slack(self):
		"""Get and return the slack space (as a SlackSpace object or None, if not available) from this file record segment (FRS)."""

		if self.frs_real_size is None:
			for __ in self.attributes():
				pass

		if self.frs_real_size is None: # This file record segment (FRS) is invalid.
			return

		return SlackSpace(self.frs_data[self.frs_real_size : ])

	def attributes(self):
		"""This method yields each attribute (AttributeRecordResident or AttributeRecordNonresident) of this file record segment (FRS)."""

		pos = self.get_first_attribute_offset()
		while pos < self.get_first_free_byte_offset():
			attribute_record_partial_header = self.frs_data[pos : pos + 16]
			if len(attribute_record_partial_header) == 16:
				type_code, record_length, form_code, name_length, name_offset, flags, instance = UnpackAttributeRecordPartialHeader(attribute_record_partial_header)
			elif len(attribute_record_partial_header) >= 4 and len(attribute_record_partial_header) < 16:
				type_code, = struct.unpack('<L', attribute_record_partial_header[: 4])

				if type_code == Attributes.ATTR_TYPE_END: # Stop here.
					self.frs_real_size = pos + 4
					break
				else:
					raise AttributeException('Unexpected end of the file record segment')
			else:
				raise AttributeException('Unexpected end of the file record segment')

			if type_code == Attributes.ATTR_TYPE_END: # Stop here.
				self.frs_real_size = pos + 4
				break

			if record_length < 8 or record_length % 8 != 0 or pos + record_length > self.get_first_free_byte_offset():
				raise AttributeException('Invalid record length within the attribute header: {}'.format(record_length))

			if name_length > 0:
				# An attribute with a name.
				name_length_in_bytes = name_length * 2 # Two bytes per wide character.

				if name_offset % 2 != 0 or (form_code == FORM_CODE_NONRESIDENT and name_offset < 64) or (form_code == FORM_CODE_RESIDENT and name_offset < 24):
					raise AttributeException('Invalid name offset within the attribute header: {}'.format(name_offset))

				if pos + name_offset + name_length_in_bytes > self.get_first_free_byte_offset():
					raise AttributeException('Invalid name offset and length within the attribute header, name offset: {}, name length (bytes): {}'.format(name_offset, name_length_in_bytes))

				attribute_name_bytes = self.frs_data[pos + name_offset : pos + name_offset + name_length_in_bytes]
				if len(attribute_name_bytes) == name_length_in_bytes:
					attribute_name = attribute_name_bytes.decode('utf-16le', errors = 'replace')
				else:
					raise AttributeException('Unexpected end of the name within the attribute header')
			else:
				attribute_name = None

			if form_code == FORM_CODE_NONRESIDENT:
				attribute_record_remaining_header = self.frs_data[pos + 16: pos + 64]
				if len(attribute_record_remaining_header) != 48:
					raise AttributeException('Unexpected end of the file record segment')

				# A compression unit is an 8-bit integer (but some sources incorrectly state that this is a 16-bit integer).
				lowest_vcn, highest_vcn, mapping_pairs_offset, compression_unit, reserved, allocated_length, file_size, valid_data_length = struct.unpack('<QQHB5sqqq', attribute_record_remaining_header)

				if lowest_vcn > highest_vcn:
					raise AttributeException('"Lowest" VCN is higher than "highest" VCN: {} > {}'.format(lowest_vcn, highest_vcn))

				if mapping_pairs_offset >= record_length or (name_length == 0 and mapping_pairs_offset < 64) or (name_length > 0 and mapping_pairs_offset < name_offset + name_length_in_bytes):
					raise AttributeException('Invalid mapping pairs offset within the attribute header: {}'.format(mapping_pairs_offset))

				if valid_data_length < 0 or valid_data_length > file_size or allocated_length < file_size:
					raise AttributeException('Invalid values of allocated length, file size, valid data length within the attribute header: {}, {}, {}'.format(allocated_length, file_size, valid_data_length))

				mapping_pairs = self.frs_data[pos + mapping_pairs_offset : pos + record_length]
				yield AttributeRecordNonresident(type_code, attribute_name, mapping_pairs, lowest_vcn, highest_vcn, file_size)

			elif form_code == FORM_CODE_RESIDENT:
				attribute_record_remaining_header = self.frs_data[pos + 16: pos + 24]
				if len(attribute_record_remaining_header) != 8:
					raise AttributeException('Unexpected end of the file record segment')

				value_length, value_offset, resident_flags, reserved = UnpackAttributeRecordRemainingHeaderResident(attribute_record_remaining_header)
				if value_offset < 8 or value_offset % 8 != 0:
					raise AttributeException('Invalid value offset within the attribute header: {}'.format(value_offset))

				if value_offset + value_length > record_length or (name_length == 0 and value_offset < 24) or (name_length > 0 and value_offset < name_offset + name_length_in_bytes):
					raise AttributeException('Invalid value offset and length within the attribute header, value offset: {}, value length: {}'.format(value_offset, value_length))

				attribute_value = self.frs_data[pos + value_offset : pos + value_offset + value_length]
				if len(attribute_value) != value_length:
					raise AttributeException('Unexpected end of the attribute value')

				yield AttributeRecordResident(type_code, attribute_name, attribute_value)
			else:
				raise AttributeException('Invalid form code within the attribute header: {}'.format(form_code))

			pos += record_length

	def __str__(self):
		if self.is_bad():
			status_str = 'bad'
		else:
			status_str = 'good'

		if self.is_in_use():
			is_in_use_str = 'allocated'
		else:
			is_in_use_str = 'unallocated'

		if self.is_base_file_record_segment():
			is_base_frs_str = 'base'
		else:
			is_base_frs_str = 'child'

		return 'FileRecordSegment, {}, $MFT number: {}, {}, {}'.format(status_str, self.get_master_file_table_number(), is_in_use_str, is_base_frs_str)

class AttributeRecordResident(object):
	"""This class is used to work with a resident attribute record."""

	type_code = None
	"""A type code of this attribute record."""

	name = None
	"""A name of this attribute record."""

	value = None
	"""A value (raw data) of this attribute record."""

	def __init__(self, type_code, name, value):
		self.type_code = type_code
		self.name = name
		self.value = value

	def type_str(self):
		"""Resolve a type code to a string and return it."""

		return ResolveAttributeType(self.type_code)

	def value_decoded(self):
		"""Return a decoded value (as an object from the Attributes module)."""

		if self.type_code in Attributes.AttributeTypes.keys():
			# A known attribute.
			return Attributes.AttributeTypes[self.type_code][1](self.value)

		# An unknown attribute.
		return Attributes.GenericAttribute(self.value)

	def __str__(self):
		if self.name is None:
			name_str = 'no name'
		else:
			name_str = 'name: {}'.format(self.name)

		return 'AttributeRecordResident, type: {}, {}'.format(self.type_str(), name_str)

class AttributeRecordNonresident(object):
	"""This class is used to work with a nonresident attribute record."""

	type_code = None
	"""A type code of this attribute record."""

	name = None
	"""A name of this attribute record."""

	mapping_pairs = None
	"""Mapping pairs (not validated) of this attribute record."""

	lowest_vcn = None
	"""Lowest VCN (virtual cluster number) covered by this attribute record."""

	highest_vcn = None
	"""Highest VCN (virtual cluster number) covered by this attribute record."""

	file_size = None
	"""File (data) size."""

	def __init__(self, type_code, name, mapping_pairs, lowest_vcn, highest_vcn, file_size):
		self.type_code = type_code
		self.name = name
		self.mapping_pairs = mapping_pairs
		self.lowest_vcn = lowest_vcn
		self.highest_vcn = highest_vcn
		self.file_size = file_size

	def type_str(self):
		"""Resolve a type code to a string and return it."""

		return ResolveAttributeType(self.type_code)

	def value_decoded(self):
		"""Return a decoded value (as an object from the Attributes module)."""

		raise NotImplementedError('Nonresident attribute records are not supported')

	def __str__(self):
		if self.name is None:
			name_str = 'no name'
		else:
			name_str = 'name: {}'.format(self.name)

		return 'AttributeRecordNonresident, type: {}, {}, VCN range: {}-{}'.format(self.type_str(), name_str, self.lowest_vcn, self.highest_vcn)

class SlackSpace(object):
	"""This class is used to work with slack space."""

	value = None
	"""A value (raw data) for this slack space."""

	def __init__(self, value):
		self.value = value

		self.timestamp_not_before = 125000000000000000 # Year: 1997.
		self.timestamp_not_after = 145000000000000000 # Year: 2060.

	def carve(self):
		"""This method yields possible attributes (as objects from the Attributes module) extracted from this slack space.
		Only the $FILE_NAME attributes are supported.
		"""

		def validate_timestamp(timestamp):
			return timestamp >= self.timestamp_not_before and timestamp <= self.timestamp_not_after

		def validate_file_name(file_name):
			if len(file_name) == 0 or len(file_name) > 255:
				return False

			if '/' in file_name or '\x00' in file_name:
				return False

			return True


		if len(self.value) >= 8:
			pos = 0
			if len(self.value) % 2 != 0:
				pos = 1

			while pos < len(self.value):
				buf = self.value[pos : pos + 32]
				if len(buf) != 32:
					break

				ts_tuple = struct.unpack('<QQQQ', buf)

				ts_valid = True
				for ts in ts_tuple:
					if not validate_timestamp(ts):
						ts_valid = False
						break

				if ts_valid and pos >= 8:
					attr_pos = pos - 8
					attr_buf = self.value[attr_pos : ]

					try:
						file_name = Attributes.FileName(attr_buf)
						ts_m = file_name.get_mtime()
						ts_a = file_name.get_atime()
						ts_c = file_name.get_ctime()
						ts_e = file_name.get_etime()
						file_name_str = file_name.get_file_name()
					except Exception:
						pass
					else:
						if validate_file_name(file_name_str):
							yield file_name

							# Jump to the file name part and continue.
							pos += 68
							continue

				pos += 2

	def __str__(self):
		return 'SlackSpace, size: {}'.format(len(self.value))

class FileRecord(object):
	"""This class is used to represent a file record (one or more file record segments)."""

	def __init__(self, base_file_record_segment, child_file_record_segments_list):
		self.base_frs = base_file_record_segment
		self.child_frs_list = child_file_record_segments_list

	def slack(self):
		"""This method yields slack space objects (SlackSpace) for this file record."""

		slack = self.base_frs.get_slack()
		if slack is not None:
			yield slack

		for child_frs in self.child_frs_list:
			slack = child_frs.get_slack()
			if slack is not None:
				yield slack

	def attributes(self):
		"""This method yields each attribute (AttributeRecordResident or AttributeRecordNonresident) of this file record."""

		for attr in self.base_frs.attributes():
			yield attr

		for child_frs in self.child_frs_list:
			for attr in child_frs.attributes():
				yield attr

	def get_logfile_sequence_number(self):
		"""Get and return a log file sequence number (LSN) for a base file record segment (FRS)."""

		return self.base_frs.get_logfile_sequence_number()

	def get_sequence_number(self):
		"""Get and return a sequence number for a base file record segment (FRS)."""

		return self.base_frs.get_sequence_number()

	def is_in_use(self):
		"""Check if a base file record segment (FRS) is in use (according to its flags)."""

		return self.base_frs.is_in_use()

	def get_flags(self):
		"""Get and return flags (as a number)."""

		return self.base_frs.get_flags()

	def get_master_file_table_number(self):
		"""Get an $MFT number for a base file record segment (FRS) and return it."""

		return self.base_frs.get_master_file_table_number()

	def __str__(self):
		return 'FileRecord, 1 base file record segment, {} child file record segment(s)'.format(len(self.child_frs_list))

class MasterFileTableParser(object):
	"""This class is used to read and parse an $MFT file."""

	file_object = None
	"""A file object for an $MFT file."""

	file_size = None
	"""A size of this $MFT file."""

	file_record_segment_size = None
	"""A size of each file record segment (FRS) in this $MFT file."""

	child_cache = None
	"""A cache of child file record segments."""

	statistics = None
	"""A tuple: (total number of file record segments, number of child in-use file record segments)"""

	def __init__(self, file_object, do_first_pass = True):
		"""Create an MFTReader object from a file object (the 'file_object' argument). Complete the first pass, if requested (the 'do_first_pass' argument)."""

		self.file_object = file_object
		self.child_cache = dict()
		self.statistics = (None, None)

		self.file_object.seek(0)
		signature = self.file_object.read(4)
		if signature != MULTI_SECTOR_HEADER_SIGNATURE_GOOD:
			raise FileRecordSegmentSignatureException('Invalid signature: {}'.format(signature))

		self.file_object.seek(28)
		file_record_segment_size_bytes = self.file_object.read(4)
		if len(file_record_segment_size_bytes) != 4:
			raise FileRecordSegmentException('Read error within the first file record segment')

		self.file_record_segment_size = struct.unpack('<L', file_record_segment_size_bytes)[0]
		if self.file_record_segment_size not in FILE_RECORD_SEGMENT_SIZES_SUPPORTED:
			raise FileRecordSegmentException('Invalid (unsupported) declared size of the file record segment: {}'.format(self.file_record_segment_size))

		self.file_object.seek(0, 2)
		self.file_size = self.file_object.tell()
		self.file_object.seek(0)

		self.check_ntfs_version()

		if do_first_pass:
			self.execute_first_pass()

	def check_ntfs_version(self):
		"""Check NTFS version numbers to see if they are supported."""

		frs_volume = self.get_file_record_segment_by_number(FILE_NUMBER_VOLUME)
		for attr in frs_volume.attributes():
			attr_decoded = attr.value_decoded()
			if type(attr_decoded) is Attributes.VolumeInformation:
				major_version = attr_decoded.get_major_version()
				minor_version = attr_decoded.get_minor_version()

				break

		if major_version != 3:
			raise MasterFileTableException('NTFS major version number not supported: {}'.format(major_version))

		if minor_version < 1:
			raise MasterFileTableException('NTFS minor version number not supported: {}'.format(minor_version))

	def get_file_record_segment_by_number(self, file_record_segment_number):
		"""Get and return a file record segment (FileRecordSegment) by its number."""

		file_record_segment_offset = file_record_segment_number * self.file_record_segment_size
		if file_record_segment_offset > self.file_size:
			raise MasterFileTableException('Invalid offset (too large): {}'.format(file_record_segment_offset))

		self.file_object.seek(file_record_segment_offset)
		buf = self.file_object.read(self.file_record_segment_size)

		return FileRecordSegment(buf)

	def get_file_record_by_number(self, base_file_record_segment_number, expected_sequence_number = None, allow_child_file_record_segment_number = True):
		"""Get and return a file record (FileRecord) by its base file record segment (FRS) number.
		If a child file record segment (FRS) number is given (instead of a base one) and the 'allow_child_file_record_segment_number' argument is True,
		then a base file record segment (FRS) will be located (in the cache) and used instead.
		"""

		base_file_record_segment_offset = base_file_record_segment_number * self.file_record_segment_size
		if base_file_record_segment_offset > self.file_size:
			raise MasterFileTableException('Invalid offset (too large): {}'.format(base_file_record_segment_offset))

		self.file_object.seek(base_file_record_segment_offset)
		buf = self.file_object.read(self.file_record_segment_size)

		frs = FileRecordSegment(buf)
		if frs.is_base_file_record_segment():
			mft_number = frs.get_master_file_table_number()
			sequence_number = frs.get_sequence_number()

			if not frs.is_in_use(): # The sequence number is incremented each time a file record segment is deallocated (and the new sequence number can be zero).
				if sequence_number >= 2:
					sequence_number -= 1
				elif sequence_number == 0:
					sequence_number = 0xFFFF # Handle the overflow.
				# When a file record segment is allocated, the existing sequence number is used, if it is not equal to zero (if it is, then the sequence number is set to one).
				# Some sources state something different from that.

			if expected_sequence_number is not None and sequence_number != expected_sequence_number:
				raise MasterFileTableException('A sequence number is not equal to an expected sequence number: {} != {}'.format(sequence_number, expected_sequence_number))

			reference = EncodeFileRecordSegmentReference(mft_number, sequence_number)
			if reference in self.child_cache.keys():
				child_frs_list = []
				for child_frs_number in self.child_cache[reference]:
					child_frs_list.append(self.get_file_record_segment_by_number(child_frs_number))

				return FileRecord(frs, child_frs_list)
			else:
				return FileRecord(frs, [])
		else:
			if allow_child_file_record_segment_number:
				mft_number = frs.get_master_file_table_number()
				sequence_number = frs.get_sequence_number()

				if not frs.is_in_use(): # The sequence number is incremented each time a file record segment is deallocated (and the new sequence number can be zero).
					if sequence_number >= 2:
						sequence_number -= 1
					elif sequence_number == 0:
						sequence_number = 0xFFFF # Handle the overflow.
					# When a file record segment is allocated, the existing sequence number is used, if it is not equal to zero (if it is, then the sequence number is set to one).
					# Some sources state something different from that.

				if expected_sequence_number is not None and sequence_number != expected_sequence_number:
					raise MasterFileTableException('A sequence number is not equal to an expected sequence number: {} != {}'.format(sequence_number, expected_sequence_number))

				# A number of a child file record segment (FRS) was given instead of a base one.
				child_file_record_segment_number = base_file_record_segment_number

				for parent_reference in self.child_cache.keys():
					if child_file_record_segment_number in self.child_cache[parent_reference]:
						base_file_record_segment_number, base_expected_sequence_number = DecodeFileRecordSegmentReference(parent_reference)

						return self.get_file_record_by_number(base_file_record_segment_number, base_expected_sequence_number, False)

			raise MasterFileTableException('An invalid base file record segment number given: {}'.format(base_file_record_segment_number))

	def build_full_paths(self, file_record, include_attributes = False):
		"""Build and return a list of full paths (as strings) for a given file record (FileRecord).
		If 'include_attributes' is True, a list of (full path, $FILE_NAME attribute value) tuples is returned.
		Note: the root directory is returned as is ("/.").
		"""

		def get_preferred_file_name(file_record):
			file_names = []

			for attr in file_record.attributes():
				if type(attr) is AttributeRecordNonresident:
					continue

				attr_value = attr.value_decoded()
				if type(attr_value) is not Attributes.FileName:
					continue

				file_names.append((attr_value.get_flags(), attr_value.get_file_name(), attr_value.get_parent_directory()))

			if len(file_names) == 0:
				raise MasterFileTableException('A given file record has no file names')

			for flags, file_name, parent_reference in file_names:
				if flags & Attributes.FILE_NAME_NTFS > 0 or flags == 0: # Win32 and POSIX name spaces are preferred.
					return (file_name, parent_reference)

			# No preferred file name found, return the first one.
			flags, file_name, parent_reference = file_names[0]
			return (file_name, parent_reference)

		paths = []

		attr_file_names = []
		for attr in file_record.attributes():
			if type(attr) is AttributeRecordNonresident:
				continue

			attr_value = attr.value_decoded()
			if type(attr_value) is not Attributes.FileName:
				continue

			flags = attr_value.get_flags()

			if flags & Attributes.FILE_NAME_NTFS > 0 or flags == 0: # Win32 and POSIX name spaces are preferred.
				attr_file_names.insert(0, attr_value)
			else:
				attr_file_names.append(attr_value)

		for attr_value_to_return in attr_file_names:
			path_components = [ attr_value_to_return.get_file_name() ]
			parent_reference = attr_value_to_return.get_parent_directory()
			parent_reference_number, parent_sequence_number = DecodeFileRecordSegmentReference(parent_reference)

			if parent_reference_number == FILE_NUMBER_ROOT:
				path_components.append('') # Add a root directory.
				path_components.reverse()

				if not include_attributes:
					paths.append(PATH_SEPARATOR.join(path_components))
				else:
					paths.append((PATH_SEPARATOR.join(path_components), attr_value_to_return))

				continue

			try:
				parent_file_record = self.get_file_record_by_number(parent_reference_number, parent_sequence_number, False)
			except MasterFileTableException:
				# An invalid parent file record.
				path_components.append(UNKNOWN_PATH_PLACEHOLDER)
			else:
				if parent_file_record.get_flags() & FILE_FILE_NAME_INDEX_PRESENT == 0:
					# Not a directory.
					path_components.append(UNKNOWN_PATH_PLACEHOLDER)
				else:
					track = set()
					track.add(parent_reference_number)

					current_file_record = parent_file_record
					while True:
						file_name, parent_reference = get_preferred_file_name(current_file_record)
						parent_reference_number, parent_sequence_number = DecodeFileRecordSegmentReference(parent_reference)

						path_components.append(file_name)

						if parent_reference_number in track:
							# An invalid path.
							path_components.append(UNKNOWN_PATH_PLACEHOLDER)
							break
						else:
							track.add(parent_reference_number)

						try:
							current_file_record = self.get_file_record_by_number(parent_reference_number, parent_sequence_number, False)
						except MasterFileTableException:
							# An invalid parent file record.
							path_components.append(UNKNOWN_PATH_PLACEHOLDER)
							break

						if parent_reference_number == FILE_NUMBER_ROOT:
							path_components.append('') # Add a root directory.
							break

						if current_file_record.get_flags() & FILE_FILE_NAME_INDEX_PRESENT == 0:
							# Not a directory.
							path_components.append(UNKNOWN_PATH_PLACEHOLDER)
							break

			path_components.reverse()

			if not include_attributes:
				paths.append(PATH_SEPARATOR.join(path_components))
			else:
				paths.append((PATH_SEPARATOR.join(path_components), attr_value_to_return))

		return paths

	def execute_first_pass(self):
		"""Populate a cache of child in-use file record segments, calculate the statistics."""

		frs_cnt = 0
		child_frs_cnt = 0

		pos = 0
		while pos < self.file_size:
			self.file_object.seek(pos)
			buf = self.file_object.read(self.file_record_segment_size)

			if len(buf) != self.file_record_segment_size: # A read error or a truncated $MFT file.
				break

			try:
				frs = FileRecordSegment(buf)
			except FileRecordSegmentException:
				# An invalid file record segment, ignore it and continue.
				pos += self.file_record_segment_size
				continue

			frs_cnt += 1

			if not frs.is_base_file_record_segment():
				child_frs_cnt += 1
				reference_parent = frs.get_base_file_record_segment()

				child_frs_number = pos // self.file_record_segment_size
				if reference_parent in self.child_cache.keys():
					self.child_cache[reference_parent].append(child_frs_number)
				else:
					self.child_cache[reference_parent] = [ child_frs_number ]

			pos += self.file_record_segment_size

		self.statistics = (frs_cnt, child_frs_cnt)

	def file_records(self, in_use_file_records_only = False):
		"""This method yields file records (FileRecord). If the 'in_use_file_records_only' argument is True, limit the output to in-use file records only."""

		pos = 0
		while pos < self.file_size:
			self.file_object.seek(pos)
			buf = self.file_object.read(self.file_record_segment_size)

			if len(buf) != self.file_record_segment_size: # A read error or a truncated $MFT file.
				break

			try:
				frs = FileRecordSegment(buf)
			except FileRecordSegmentException:
				# An invalid file record segment, ignore it and continue.
				pos += self.file_record_segment_size
				continue

			if in_use_file_records_only and not frs.is_in_use():
				# Skip this file record.
				pos += self.file_record_segment_size
				continue

			if frs.is_base_file_record_segment():
				mft_number = frs.get_master_file_table_number()
				sequence_number = frs.get_sequence_number()

				if not frs.is_in_use(): # The sequence number is incremented each time a file record segment is deallocated (and the new sequence number can be zero).
					if sequence_number >= 2:
						sequence_number -= 1
					elif sequence_number == 0:
						sequence_number = 0xFFFF # Handle the overflow.
					# When a file record segment is allocated, the existing sequence number is used, if it is not equal to zero (if it is, then the sequence number is set to one).
					# Some sources state something different from that.

				reference = EncodeFileRecordSegmentReference(mft_number, sequence_number)
				if reference in self.child_cache.keys():
					child_frs_list = []
					for child_frs_number in self.child_cache[reference]:
						child_frs_list.append(self.get_file_record_segment_by_number(child_frs_number))

					yield FileRecord(frs, child_frs_list)
				else:
					yield FileRecord(frs, [])

			pos += self.file_record_segment_size

	def __str__(self):
		return 'MasterFileTableReader'
