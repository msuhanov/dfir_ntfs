# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to parse the MoveTable (tracking.log).

import struct
import uuid
from collections import namedtuple
from .Attributes import DecodeFiletime, DecodeGUIDTime

# Values for the header:
MOVETABLE_HEADER_SIGNATURE = b'\xEC\xA7\x43\x66\xFE\xEF\xD1\x11\xB2\xAE\x00\xC0\x4F\xB9\x38\x6D'
FLAG_LOG_IS_FLUSHED = 1

# Values for the log entry:
LOG_ENTRY_TYPE_UNUSED = 1
LOG_ENTRY_TYPE_MOVE_NOTIFICATION = 2

ExpansionData = namedtuple('ExpansionData', [ 'lowest_log_entry_index_present', 'highest_log_entry_index_present', 'file_size' ])
ExtendedHeader = namedtuple('ExtendedHeader', [ 'machine_id', 'volume_object_id', 'unknown_32', 'unknown_timestamp_int_40', 'unknown_timestamp_int_48', 'unknown_flags_56', 'unknown_state_60', 'unknown_log_entry_index_64', 'unknown_log_entry_index_68', 'unknown_log_entry_index_72', 'unknown_log_entry_index_76', 'unknown_log_entry_index_80', 'unknown_log_entry_index_84', 'unknown_log_entry_index_88' ])

def ValidateSectorSize(SectorSize):
	"""Check if a given sector size is valid (either 512 or 4096 bytes)."""

	if SectorSize not in [ 512, 4096 ]:
		raise ValueError('Invalid sector size: {}'.format(SectorSize))

	return True

def DecodeString(Buffer):
	"""Decode a given buffer into a human-readable string and return this string."""

	try:
		s1 = Buffer.decode('cp866')
	except Exception:
		s1 = None

	try:
		s2 = Buffer.decode('windows-1252')
	except Exception:
		s2 = None

	if s2 is None and s1 is not None:
		return s1

	if s1 is None and s2 is not None:
		return s2

	if s1 is None and s2 is None:
		return '(unknown encoding)'

	if s1 == s2:
		return s1

	return '"{}" (cp-866), "{}" (windows-1252)'.format(s1, s2)

class Header(object):
	"""This class is used to parse the MoveTable header."""

	buf = None
	"""A header as raw bytes."""

	def __init__(self, header_sector_raw):
		ValidateSectorSize(len(header_sector_raw))

		self.buf = header_sector_raw

		signature = self.get_signature()
		if signature != MOVETABLE_HEADER_SIGNATURE:
			raise ValueError('Invalid signature: {}'.format(signature))

	def get_signature(self):
		"""Get and return the signature."""

		return self.buf[ : 16]

	def get_unknown_16(self):
		"""Get and return the unknown field."""

		return struct.unpack('<L', self.buf[16 : 20])[0]

	def get_flags(self):
		"""Get and return the flags."""

		return struct.unpack('<L', self.buf[20 : 24])[0]

	def is_log_flushed(self):
		"""Check if this log is flushed."""

		return self.get_flags() & FLAG_LOG_IS_FLUSHED > 0

	def get_unknown_24(self):
		"""Get and return the unknown field."""

		return struct.unpack('<L', self.buf[24 : 28])[0]

	def get_expansion_data(self):
		"""Get and return the expansion data as a named tuple (ExpansionData)."""

		lowest_log_entry_index_present, highest_log_entry_index_present, file_size = struct.unpack('<LLL', self.buf[28 : 40])
		return ExpansionData(lowest_log_entry_index_present = lowest_log_entry_index_present, highest_log_entry_index_present = highest_log_entry_index_present, file_size = file_size)

	def get_extended_header(self):
		"""Get, decode and return the extended header as a named tuple (ExtendedHeader).
		The volume object ID returned is expected to be random (not based on a MAC address and time)."""

		extended_header_buf = self.buf[40 : 132]
		machine_id_raw, volume_object_id_raw, unknown_32, unknown_timestamp_int_40, unknown_timestamp_int_48, unknown_flags_56, unknown_state_60, unknown_log_entry_index_64, unknown_log_entry_index_68, unknown_log_entry_index_72, unknown_log_entry_index_76, unknown_log_entry_index_80, unknown_log_entry_index_84, unknown_log_entry_index_88 = struct.unpack('<16s16sQQQLLLLLLLLL', extended_header_buf)

		# Convert the machine ID from a null-terminated string into a usual string.
		null_pos = machine_id_raw.find(b'\x00')
		if null_pos != -1:
			machine_id_raw = machine_id_raw[ : null_pos]

		machine_id = DecodeString(machine_id_raw)

		# Decode the GUID.
		volume_object_id = uuid.UUID(bytes_le = volume_object_id_raw)

		return ExtendedHeader(machine_id = machine_id, volume_object_id = volume_object_id, unknown_32 = unknown_32, unknown_timestamp_int_40 = unknown_timestamp_int_40, unknown_timestamp_int_48 = unknown_timestamp_int_48, unknown_flags_56 = unknown_flags_56, unknown_state_60 = unknown_state_60, unknown_log_entry_index_64 = unknown_log_entry_index_64, unknown_log_entry_index_68 = unknown_log_entry_index_68, unknown_log_entry_index_72 = unknown_log_entry_index_72, unknown_log_entry_index_76 = unknown_log_entry_index_76, unknown_log_entry_index_80 = unknown_log_entry_index_80, unknown_log_entry_index_84 = unknown_log_entry_index_84, unknown_log_entry_index_88 = unknown_log_entry_index_88)

	def __str__(self):
		return 'Header'

class LogSectorFooter(object):
	"""This class is used to parse the MoveTable's log sector footer."""

	buf = None
	"""A log sector footer as raw bytes."""

	def __init__(self, log_sector_raw):
		ValidateSectorSize(len(log_sector_raw))

		self.buf = log_sector_raw[-16 : ]

	def get_lowest_log_entry_index_present(self):
		"""Get and return the lowest log entry index present."""

		return struct.unpack('<L', self.buf[ : 4])[0]

	def get_next_log_entry_index(self):
		"""Get and return the next log entry index to be allocated."""

		return struct.unpack('<L', self.buf[4 : 8])[0]

	def get_unused(self):
		"""Get and return the unused field (as raw bytes)."""

		return self.buf[8 : ]

	def __str__(self):
		return 'LogSectorFooter'

class LogEntry(object):
	"""This class is used to parse the MoveTable's log entry."""

	buf = None
	"""A log entry as raw bytes."""

	def __init__(self, log_entry_raw):
		if len(log_entry_raw) != 124:
			raise ValueError('Invalid size of a log entry')

		self.buf = log_entry_raw

		log_entry_type = self.get_log_entry_type()
		if log_entry_type not in [ LOG_ENTRY_TYPE_UNUSED, LOG_ENTRY_TYPE_MOVE_NOTIFICATION ]:
			raise NotImplementedError('Unsupported log entry type: {}'.format(log_entry_type))

	def get_next_log_entry_index(self):
		"""Get and return the next log entry index."""

		return struct.unpack('<L', self.buf[ : 4])[0]

	def get_previous_log_entry_index(self):
		"""Get and return the previous log entry index."""

		return struct.unpack('<L', self.buf[4 : 8])[0]

	def get_log_entry_type(self):
		"""Get and return the log entry type (as an integer)."""

		return struct.unpack('<L', self.buf[8 : 12])[0]

	def get_log_entry_index(self):
		"""Get and return the log entry index."""

		return struct.unpack('<L', self.buf[12 : 16])[0]

	def get_unknown_16(self):
		"""Get and return the unknown field."""

		return struct.unpack('<L', self.buf[16 : 20])[0]

	def get_object_id(self):
		"""Get and return the object ID."""

		object_id_raw = self.buf[20 : 36]
		return uuid.UUID(bytes_le = object_id_raw)

	def get_droid(self):
		"""Get and return the domain-relative object ID (DROID) as a tuple: (volume_field, object_field)."""

		volume_id_raw = self.buf[36 : 52]
		object_id_raw = self.buf[52 : 68]

		volume_id = uuid.UUID(bytes_le = volume_id_raw)
		object_id = uuid.UUID(bytes_le = object_id_raw)

		return (volume_id, object_id)

	def get_machine_id_raw(self):
		"""Get, decode and return the machine ID as stripped bytes (without the terminating null byte and extra bytes after it)."""

		machine_id_raw = self.buf[68 : 84]

		# Convert the machine ID from a null-terminated string into a usual string.
		null_pos = machine_id_raw.find(b'\x00')
		if null_pos != -1:
			machine_id_raw = machine_id_raw[ : null_pos]

		return machine_id_raw

	def get_machine_id(self):
		"""Get, decode and return the machine ID as a human-readable string (it may contain additional information for a human)."""

		machine_id_raw = self.get_machine_id_raw()
		machine_id = DecodeString(machine_id_raw)

		return machine_id

	def get_birth_droid(self):
		"""Get and return the birth domain-relative object ID (birth DROID) as a tuple: (volume_field, object_field)."""

		volume_id_raw = self.buf[84 : 100]
		object_id_raw = self.buf[100 : 116]

		volume_id = uuid.UUID(bytes_le = volume_id_raw)
		object_id = uuid.UUID(bytes_le = object_id_raw)

		return (volume_id, object_id)

	def get_timestamp(self):
		"""Get, decode and return the timestamp as a tuple: (timestamp_lowest, timestamp_highest).
		The real event took place not before 'timestamp_lowest' and not after 'timestamp_highest'.
		"""

		timestamp_int = struct.unpack('<L', self.buf[116 : 120])[0]
		timestamp_int_lowest = timestamp_int << 32
		timestamp_int_highest = timestamp_int_lowest | 0xFFFFFFFF

		timestamp_lowest = DecodeFiletime(timestamp_int_lowest)
		timestamp_highest = DecodeFiletime(timestamp_int_highest)

		return (timestamp_lowest, timestamp_highest)

	def get_guid_timestamps(self):
		"""Get, decode and return GUID timestamps as a tuple: (object_id_timestamp, droid_object_timestamp, birth_droid_object_timestamp).
		These values are for the object ID, DROID object field, birth DROID object field respectively."""

		obj_id = self.get_object_id()
		droid_object = self.get_droid()[1]
		birth_droid_object = self.get_birth_droid()[1]

		object_id_timestamp = None
		if obj_id.version == 1:
			object_id_timestamp = DecodeGUIDTime(obj_id.time)

		droid_object_timestamp = None
		if droid_object.version == 1:
			droid_object_timestamp = DecodeGUIDTime(droid_object.time)

		birth_droid_object_timestamp = None
		if birth_droid_object.version == 1:
			birth_droid_object_timestamp = DecodeGUIDTime(birth_droid_object.time)

		return (object_id_timestamp, droid_object_timestamp, birth_droid_object_timestamp)

	def get_unknown_120(self):
		"""Get and return the unknown field."""

		return struct.unpack('<L', self.buf[120 : 124])[0]

	def __str__(self):
		ts_range = self.get_timestamp()
		return 'LogEntry, machine ID: {}, timestamp range: {} - {}'.format(self.get_machine_id(), ts_range[0], ts_range[1])

class LogSector(object):
	"""This class is used to parse the MoveTable's log sector."""

	buf = None
	"""A log sector as raw bytes."""

	def __init__(self, log_sector_raw):
		ValidateSectorSize(len(log_sector_raw))

		self.buf = log_sector_raw

	def get_footer(self):
		"""Get and return the log sector footer (as a LogSectorFooter object)."""

		return LogSectorFooter(self.buf)

	def log_entries(self):
		"""This method yields each log entry in this sector (as a LogEntry object)."""

		pos = 0
		while pos + 124 <= len(self.buf) - 16:
			log_entry_raw = self.buf[pos : pos + 124]
			if len(log_entry_raw) != 124: # A truncated log entry, exit the loop.
				break

			yield LogEntry(log_entry_raw)

			pos += 124

	def __str__(self):
		return 'LogSector'

class MoveTableParser(object):
	"""This class is used to parse the MoveTable."""

	file_object = None
	"""A file object for the MoveTable."""

	sector_size = None
	"""A sector size."""

	def __init__(self, file_object, sector_size = None):
		self.file_object = file_object
		self.sector_size = sector_size

		if self.sector_size is None: # If no sector size was given, guess it now.
			self.file_object.seek(512)
			s = self.file_object.read(16)

			if s == b'\x00' * 16:
				self.sector_size = 4096
			else:
				self.sector_size = 512

	def get_header(self):
		"""Get, decode and return the MoveTable header (as a Header object)."""

		self.file_object.seek(0)
		sector_raw = self.file_object.read(self.sector_size)

		return Header(sector_raw)

	def log_sectors(self):
		"""This method yields LogSector objects for each log sector in the MoveTable."""

		i = 1
		while True:
			self.file_object.seek(i * self.sector_size)
			sector_raw = self.file_object.read(self.sector_size)

			try:
				yield LogSector(sector_raw)
			except ValueError: # We read truncated data, stop now.
				break

			i += 1

	def log_entries(self):
		"""This method yields LogEntry objects for each log entry in the MoveTable. Unused log entries are ignored."""

		for log_sector in self.log_sectors():
			for log_entry in log_sector.log_entries():
				if log_entry.get_log_entry_type() == LOG_ENTRY_TYPE_UNUSED:
					continue

				yield log_entry

	def __str__(self):
		return 'MoveTableParser'
