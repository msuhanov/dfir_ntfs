# dfir_ntfs: an NTFS/FAT parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This additional module implements an interface to work with exFAT volumes.

# [EXFAT 1.00] is:
# exFAT file system specification
#
# URL: https://docs.microsoft.com/en-us/windows/win32/fileio/exfat-specification
# Microsoft Corporation
#
# [US10614032B2] is:
# Quick filename lookup using name hash
#
# URL: https://patents.google.com/patent/US10614032B2/
#
# [US10726147B2] is:
# File encryption support for FAT file systems
#
# URL: https://patents.google.com/patent/US10726147B2/

import struct
import uuid
import ctypes
from datetime import datetime, timedelta
from collections import namedtuple

PATH_SEPARATOR = '/'

EXFAT_EOC = 0xFFFFFFFF # End of chain.
EXFAT_BAD = 0xFFFFFFF7 # Bad cluster.

# File attributes:
ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04

# 0x08 was ATTR_VOLUME_ID in FAT12/16/32. According to [EXFAT 1.00], this value is reserved.
#
# The macOS exFAT driver (Big Sur and Monterey, but not Catalina) sets the 0x08 flag for directory entries. The meaning of this flag is unclear.
# The flag is set for every newly created directory, but it is not checked when read (not in the exFAT driver, not in the userspace tools like fsck).
#
# See also:
#  * https://www.magiclantern.fm/forum/index.php?topic=25656.0
#  * https://www.ghisler.ch/board/viewtopic.php?t=73553
#
#
# According to the Azure RTOS FileX documentation, this bit means "[e]ntry is reserved" (there, "entry" means "file").
#
# Source:
# * https://docs.microsoft.com/en-us/azure/rtos/filex/chapter3#exfat-file-directory-entry
#
# This is likely a typo.

ATTR_UNKNOWN8 = 0x08

ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20

FILE_ATTR_LIST = {
	ATTR_READ_ONLY: 'READ_ONLY',
	ATTR_HIDDEN: 'HIDDEN',
	ATTR_SYSTEM: 'SYSTEM',
	ATTR_UNKNOWN8: 'UNKNOWN8_MACOS',
	ATTR_DIRECTORY: 'DIRECTORY',
	ATTR_ARCHIVE: 'ARCHIVE'
}

# A maximum number of name entries (for a single file).
MAX_NAME_ENTRIES = 17 # 255/15... Old versions of fuse-exfat allowed 256 characters, this was a bug (now it is fixed). We do not support such invalid names.

# A list of characters forbidden in file names.
FORBIDDEN_CHARACTERS = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x22, 0x2A, 0x2F, 0x3A, 0x3C, 0x3E, 0x3F, 0x5C, 0x7C]

# Known OEM parameters GUIDs:
OEM_NULL_GUID = uuid.UUID('{00000000-0000-0000-0000-000000000000}') # No OEM parameters.
OEM_FLASH_PARAMETERS_GUID = uuid.UUID('{0A0C7E46-3399-4021-90C8-FA6D389C4BA2}')

# Known directory entries (the in-use bit is set to 0):
DE_ALLOCATION_BITMAP = 0x01 # A bitmap used to track cluster allocations.
DE_UPCASE_TABLE = 0x02 # An uppercase table.
DE_VOLUME_LABEL = 0x03 # A volume label.
DE_FILE = 0x05 # A file itself.
DE_VOLUME_GUID = 0x20 # A volume GUID.
DE_TEXFAT_PADDING = 0x21 # A placeholder to fill the first cluster of a TexFAT-enabled directory.
DE_STREAM_EXTENSION = 0x40 # File data.
DE_FILE_NAME = 0x41 # A file name.
DE_VENDOR_EXTENSION = 0x60 # Vendor-specific data stored in the directory entry.
DE_VENDOR_ALLOCATION = 0x61 # Vendor-specific data stored in linked clusters.

# According to [US10614032B2], the following directory entry also exists:
DE_WINDOWS_CE_ACT = 0x22 # An access control table. Not publicly defined.
# The document also lists "Windows CE Access Control" and "Allocation Bitmap Directory Entry", but no description is given (perhaps, this was a draft).

# Some additional entries:
DE_END_OF_DIRECTORY = 0x00 # No further entries are expected in a directory.
DE_INVALID = 0x80 # This entry is not allowed.

# Some values for the entry type fields:
TYPE_IMPORTANCE_CRITICAL = 0
TYPE_IMPORTANCE_BENIGN = 1
TYPE_CATEGORY_PRIMARY = 0
TYPE_CATEGORY_SECONDARY = 1

# Flags for the stream data.
STREAM_DATA_ENCRYPTED = 0x8000 # Files: data is encrypted, directories: files are encrypted by default.

def ResolveFileAttributes(FileAttributes):
	"""Convert file attributes to a string."""

	str_list = []
	for file_attr in sorted(FILE_ATTR_LIST.keys()):
		if FileAttributes & file_attr > 0:
			str_list.append(FILE_ATTR_LIST[file_attr])

	return ' | '.join(str_list)

def BuildName(NameEntities, NameLength):
	"""Parse a given name, return a string (or None, if the name is invalid).
	Decoding errors are not raised.
	"""

	if len(NameEntities) == 0:
		return

	buf = b''.join(NameEntities)

	# Remove everything after the first null character (including it).
	i = 0
	while i < len(buf):
		if buf[i : i + 2] == b'\x00\x00':
			buf = buf[ : i]
			break

		i += 2

	name = buf.decode('utf-16le', errors = 'replace')
	if len(name) == 0: # This is an invalid name.
		return

	if NameLength is not None and len(name) > NameLength: # This name is too long, truncate it.
		return name[ : NameLength]

	for character_code in FORBIDDEN_CHARACTERS:
		character = chr(character_code)
		if character in name: # This is an invalid name.
			return

	if name in [ '.', '..' ]: # These are reserved names.
		return

	return name

def BuildLabel(LabelRaw, LabelLength):
	"""Parse a given volume label, return a string (or None, if the label is invalid).
	Decoding errors are not raised.
	"""

	buf = LabelRaw

	# Remove everything after the first null character (including it).
	i = 0
	while i < len(buf):
		if buf[i : i + 2] == b'\x00\x00':
			buf = buf[ : i]
			break

		i += 2

	name = buf.decode('utf-16le', errors = 'replace')
	if len(name) == 0: # This is an invalid label.
		return

	if len(name) > LabelLength: # This label is too long, truncate it.
		return name[ : LabelLength]

	for character_code in FORBIDDEN_CHARACTERS:
		character = chr(character_code)
		if character in name: # This is an invalid label.
			return

	return name

def DecodeFATTimestamp(Value, Value10ms = 0):
	"""Decode and return the datetime object (or None, if the timestamp is invalid)."""

	ValueTime = Value & 0xFFFF
	ValueDate = (Value >> 16) & 0xFFFFF

	if Value10ms > 199: # Something is wrong, ignore this value.
		Value10ms = 0

	second = ValueTime & 0x1F
	if second > 29:
		return

	second *= 2

	minute = (ValueTime >> 5) & 0x3F
	if minute > 59:
		return

	hour = (ValueTime >> 11) & 0x1F
	if hour > 23:
		return

	day = ValueDate & 0x1F
	if day == 0: # 0x1F = 31.
		return

	month = (ValueDate >> 5) & 0x0F
	if month == 0 or month > 12:
		return

	year = (ValueDate >> 9) & 0x7F
	if year > 127:
		return

	year += 1980

	try:
		return datetime(year, month, day, hour, minute, second) + timedelta(milliseconds = Value10ms * 10)
	except ValueError:
		return

def DecodeFATTimezone(Value):
	"""Decode and return the FAT timezone as an integer (or None, if the timezone is not given).
	This integer is signed and it counts 15-minute intervals from UTC.
	"""

	is_valid = Value & 0x80 > 0
	if not is_valid:
		return

	offset = Value & 0x7F
	if offset & 0x40 == 0: # Unsigned.
		return offset
	else: # Signed.
		return ctypes.c_int8(offset | 0x80).value

def EntryTypeWithoutInUseBit(EntryType):
	"""Return the entry type with the in-use bit unset."""

	if EntryType & 0x80 > 0:
		return EntryType - 0x80

	return EntryType

def DecodeEntryType(EntryType):
	"""Decode the entry type, return a tuple: (type_code, type_importance, type_category, is_in_use)."""

	type_code = EntryType & 0x1F
	type_importance = (EntryType >> 5) & 1
	type_category = (EntryType >> 6) & 1
	is_in_use = EntryType & 0x80 > 0

	return (type_code, type_importance, type_category, is_in_use)

def DecodeFlags(Flags):
	"""Decode the flags found in an entry, return a tuple: (allocation_possible, no_fat_chain)."""

	allocation_possible = Flags & 1 > 0
	no_fat_chain = (Flags >> 1) & 1 > 0

	return (allocation_possible, no_fat_chain)

def EntrySetChecksum(EntrySetRaw):
	"""Calculate and return the entry set checksum (as an integer)."""

	if len(EntrySetRaw) < 32 or len(EntrySetRaw) % 32 != 0:
		raise ValueError('Invalid entry set length')

	checksum = 0
	for idx in range(len(EntrySetRaw)):
		if idx in [2, 3]:
			continue

		if checksum & 1 > 0:
			checksum = 0x8000 | (checksum >> 1)
		else:
			checksum = checksum >> 1

		checksum = (checksum + EntrySetRaw[idx]) & 0xFFFF

	return checksum

class FileSystemException(Exception):
	"""This is a top-level exception for this module."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class BootRegionException(FileSystemException):
	"""This exception is raised when something is wrong with the boot region."""

	pass

class BootRegionChecksumException(BootRegionException):
	"""This exception is raised when something is wrong with the boot region checksum."""

	pass

class FileAllocationTableException(FileSystemException):
	"""This exception is raised when something is wrong with the file allocation table (FAT)."""

	pass

class DirectoryEntriesException(FileSystemException):
	"""This exception is raised when something is wrong with directory entries."""

	pass

class BR(object):
	"""This class is used to work with a boot region (BR) containing boot sectors and other data (12 sectors)."""

	br_buf = None

	def __init__(self, br_buf):
		self.br_buf = br_buf

		if len(self.br_buf) < 12 * 512 or len(self.br_buf) % 512 != 0:
			raise BootRegionException('Invalid boot region size')

		self.validate()

	def get_bs_jmpboot(self):
		"""Get and return the first 3 bytes."""

		return self.br_buf[ : 3]

	def get_bs_fsname(self):
		"""Get and return the FS name (as raw bytes)."""

		return self.br_buf[3 : 11]

	def get_mustbezero(self):
		"""Get and return the null area, a former BPB (as raw bytes)."""

		return self.br_buf[11 : 64]

	def get_partitionoffset(self):
		"""Get and return the partition offset."""

		return struct.unpack('<Q', self.br_buf[64 : 72])[0]

	def get_volumelength(self):
		"""Get and return the volume length (in sectors)."""

		return struct.unpack('<Q', self.br_buf[72 : 80])[0]

	def get_fatoffset(self):
		"""Get and return the FAT offset (in sectors)."""

		return struct.unpack('<L', self.br_buf[80 : 84])[0]

	def get_fatlength(self):
		"""Get and return the FAT length (in sectors)."""

		return struct.unpack('<L', self.br_buf[84 : 88])[0]

	def get_clusterheapoffset(self):
		"""Get and return the cluster heap offset (in sectors)."""

		return struct.unpack('<L', self.br_buf[88 : 92])[0]

	def get_clustercount(self):
		"""Get and return the cluster count."""

		return struct.unpack('<L', self.br_buf[92 : 96])[0]

	def get_firstclusterofrootdirectory(self):
		"""Get and return the first cluster of the root directory."""

		return struct.unpack('<L', self.br_buf[96 : 100])[0]

	def get_volumeserialnumber(self):
		"""Get and return the volume serial number (as an integer)."""

		return struct.unpack('<L', self.br_buf[100 : 104])[0]

	def get_filesystemrevision(self):
		"""Get and return the file system revision, as a tuple (major_version, minor_version)."""

		major_version = self.br_buf[105]
		minor_version = self.br_buf[104]

		return (major_version, minor_version)

	def get_volumeflags(self):
		"""Get and return the volume flags, as a tuple: (active_fat, volume_dirty, media_failure, clear_to_zero)."""

		flags = struct.unpack('<H', self.br_buf[106 : 108])[0]

		active_fat = flags & 1 > 0
		volume_dirty = (flags >> 1) & 1 > 0
		media_failure = (flags >> 2) & 1 > 0
		clear_to_zero = (flags >> 3) & 1 > 0

		return (active_fat, volume_dirty, media_failure, clear_to_zero)

	def get_bytespersector(self):
		"""Calculate and return the bytes per sector value."""

		shift = self.br_buf[108]

		if shift < 9 or shift > 12:
			raise BootRegionException('Invalid bytes per sector shift')

		return 1 << shift

	def get_sectorspercluster(self):
		"""Calculate and return the sectors per cluster value."""

		shift_sec = self.br_buf[108]
		shift_clus = self.br_buf[109]

		if shift_clus > 25 - shift_sec:
			raise BootRegionException('Invalid sectors per cluster shift (too large)')

		return 1 << shift_clus

	def get_numberoffats(self):
		"""Calculate and return the number of FATs."""

		return self.br_buf[110]

	def get_driveselect(self):
		"""Calculate and return the BIOS drive number."""

		return self.br_buf[111]

	def get_percentinuse(self):
		"""Calculate and return the percent in use (or None, if not tracked or invalid)."""

		percent = self.br_buf[112]
		if percent > 100 or percent == 0xFF:
			return

		return percent

	def get_reserved(self):
		"""Get and return the reserved area (as raw bytes)."""

		return self.br_buf[113 : 120]

	def get_bs_bootcode(self):
		"""Get and return the boot code from the boot sector (as raw bytes)."""

		return self.br_buf[120 : 510]

	def get_bs_signature(self):
		"""Get and return the boot signature of the boot sector (as two raw bytes)."""

		return self.br_buf[510 : 512]

	def get_ebs_signature(self, sector_number):
		"""Get and return the signature of a given extended boot sector (as four raw bytes)."""

		if sector_number < 1 or sector_number > 8:
			raise ValueError('Invalid extended boot sector number ({})'.format(sector_number))

		offset = self.get_bytespersector() * sector_number
		return self.br_buf[offset + 508 : offset + 512]

	def get_oem_guid(self):
		"""Get, decode and return the GUID defined in the OEM parameters sector (as an UUID object)."""

		offset = self.get_bytespersector() * 10
		guid_raw = self.br_buf[offset : offset + 16]

		return uuid.UUID(bytes_le = guid_raw)

	def get_oem_flash_parameters(self):
		"""Get and return the OEM flash parameters, if present.
		A tuple is returned: (erase_block_size, page_size, spare_sectors, random_access_time, programming_time, read_cycle, write_cycle).
		Its members are None if the OEM flash parameters are absent.
		"""

		if self.get_oem_guid() != OEM_FLASH_PARAMETERS_GUID:
			return (None, None, None, None, None, None, None)

		parameters_buf = self.br_buf[self.get_bytespersector() * 10 + 16 : self.get_bytespersector() * 10 + 44]
		erase_block_size, page_size, spare_sectors, random_access_time, programming_time, read_cycle, write_cycle = struct.unpack('<LLLLLLL', parameters_buf)

		return (erase_block_size, page_size, spare_sectors, random_access_time, programming_time, read_cycle, write_cycle)

	def get_checksum(self):
		"""Get and return the boot region checksum (as an integer)."""

		offset = self.get_bytespersector() * 11

		# We validate only the first three checksums.
		checksum_1 = self.br_buf[offset : offset + 4]
		checksum_2 = self.br_buf[offset + 4 : offset + 8]
		checksum_3 = self.br_buf[offset + 8 : offset + 12]

		if checksum_1 != checksum_2 or checksum_1 != checksum_3:
			raise BootRegionException('Invalid checksums in the boot region')

		return struct.unpack('<L', checksum_1)[0]

	def calculate_checksum(self):
		"""Calculate and return the boot region checksum (as an integer)."""

		checksum = 0
		for idx in range(self.get_bytespersector() * 11):
			if idx in [106, 107, 112]:
				continue

			if checksum & 1 > 0:
				checksum = 0x80000000 | (checksum >> 1)
			else:
				checksum = checksum >> 1

			checksum = (checksum + self.br_buf[idx]) & 0xFFFFFFFF

		return checksum

	def validate(self, relaxed_checks = True):
		"""Validate the boot region."""

		if self.get_bs_fsname() != b'EXFAT   ':
			raise BootRegionException('Invalid file system name')

		if self.get_bs_signature() != b'\x55\xAA':
			raise BootRegionException('Invalid boot signature')

		if not relaxed_checks:
			if self.get_bs_jmpboot() != b'\xEB\x76\x90':
				raise BootRegionException('Invalid jump code')

		if self.get_mustbezero() != b'\x00' * 53:
			raise BootRegionException('Invalid (non-zero) null area')

		if self.get_checksum() != self.calculate_checksum():
			raise BootRegionChecksumException('Invalid boot region checksum')

		bytes_per_sector = self.get_bytespersector()

		volume_length = self.get_volumelength()
		if volume_length * bytes_per_sector < 1024 * 1024:
			raise BootRegionException('Invalid volume length (too small)')

		number_of_fats = self.get_numberoffats()
		cluster_heap_offset = self.get_clusterheapoffset()

		fat_offset = self.get_fatoffset()
		if fat_offset < 24:
			raise BootRegionException('Invalid FAT offset (too small)')

		if fat_offset > cluster_heap_offset - self.get_fatlength() * number_of_fats:
			raise BootRegionException('Invalid FAT offset (too large)')

		cluster_count = self.get_clustercount()
		sectors_per_cluster = self.get_sectorspercluster()

		fat_length = self.get_fatlength()
		if fat_length * bytes_per_sector < (cluster_count + 2) * 4:
			raise BootRegionException('Invalid FAT length (too small)')

		if fat_length * number_of_fats > cluster_heap_offset - fat_offset:
			raise BootRegionException('Invalid FAT length (too large)')

		if cluster_heap_offset < fat_offset + fat_length * number_of_fats:
			raise BootRegionException('Invalid cluster heap offset (too small)')

		if cluster_heap_offset > cluster_count * sectors_per_cluster:
			raise BootRegionException('Invalid cluster heap offset (too large)')

		if cluster_count > 0xFFFFFFF5:
			raise BootRegionException('Invalid cluster count (too large)')

		if cluster_count * sectors_per_cluster > volume_length - cluster_heap_offset:
			raise BootRegionException('Invalid cluster count (too large)')

		first_cluster_of_root_directory = self.get_firstclusterofrootdirectory()
		if first_cluster_of_root_directory < 2:
			raise BootRegionException('Invalid first root directory cluster (too small)')

		if first_cluster_of_root_directory > cluster_count + 1:
			raise BootRegionException('Invalid first root directory cluster (too large)')

		major_version, minor_version = self.get_filesystemrevision()
		if major_version == 0 or major_version > 99 or minor_version > 99:
			raise BootRegionException('Invalid file system version')

		if major_version > 1:
			raise NotImplementedError('File system major version is not supported: {}'.format(major_version))

		if number_of_fats != 1 and number_of_fats != 2:
			raise BootRegionException('Invalid number of FATs')

		active_fat, __, __, __ = self.get_volumeflags()
		if active_fat == 1 and number_of_fats != 2:
			raise BootRegionException('Invalid number of FATs')

		return True

	def __str__(self):
		return 'BR (boot region)'

class FAT(object):
	"""This class is used to work with a file allocation table."""

	fat_object = None
	fat_offset = None
	fat_size = None
	last_valid_cluster = None

	def __init__(self, fat_object, fat_offset, fat_size, last_valid_cluster):
		self.fat_object = fat_object
		self.fat_offset = fat_offset
		self.fat_size = fat_size
		self.last_valid_cluster = last_valid_cluster

		if self.fat_offset > 0 and self.fat_offset % 512 != 0:
			raise FileAllocationTableException('Invalid FAT offset: {}'.format(self.fat_offset))

		if self.fat_size < 512 or self.fat_size % 512 != 0:
			raise FileAllocationTableException('Invalid FAT size: {}'.format(self.fat_size))

	def get_element(self, number):
		"""Get and return the FAT entry by its number."""

		fat_item_offset = number * 4
		if fat_item_offset + 4 > self.fat_size or number > self.last_valid_cluster:
			raise FileAllocationTableException('Out of bounds, FAT element: {}'.format(number))

		self.fat_object.seek(self.fat_offset + fat_item_offset)
		next_element_raw = self.fat_object.read(4)
		if len(next_element_raw) != 4:
			raise FileAllocationTableException('Truncated FAT entry, FAT element: {}'.format(number))

		next_cluster = struct.unpack('<L', next_element_raw)[0]
		return next_cluster

	def get_media_type(self):
		"""Get and return the media type value."""

		fat_0 = self.get_element(0)
		return fat_0 & 0xFF

	def chain(self, first_cluster):
		"""Get and return the cluster chain for the given first cluster (as a list of cluster numbers).
		For bad clusters, None is given (as an item in the chain).
		"""

		if first_cluster == 0:
			# This file is empty, no chain.
			return []

		if first_cluster == 1:
			# This cluster is reserved, no chain.
			return []

		if first_cluster == EXFAT_BAD:
			# The first cluster is bad.
			raise FileAllocationTableException('Bad starting cluster {}'.format(first_cluster))

		chain = [ first_cluster ]

		curr_cluster = first_cluster
		while True:
			next_cluster = self.get_element(curr_cluster)

			if next_cluster in chain: # This is a loop, the FAT is corrupted, stop (but do not raise an exception).
				break

			if next_cluster == EXFAT_EOC:
				# End of chain, stop.
				break
			elif next_cluster == EXFAT_BAD:
				# Bad cluster, use None and stop.
				chain.append(None)
				break
			elif next_cluster == 0:
				# This is a "file is empty" mark (in a wrong location), stop.
				break
			elif next_cluster == 1:
				# This cluster is reserved, stop.
				break

			chain.append(next_cluster)
			curr_cluster = next_cluster

		return chain

	def __str__(self):
		return 'FAT'

# Here, "ctime" means "created time".
# However, in the Linux kernel, updates to this field are not always consistent (for example, "ctime" is updated for a parent directory when renaming a child file).
#
# "atz", "mtz", "ctz" are measured in 15-minute intervals (UTC+5:45 is 23, UTC-10 is -40). If no time zone is specified, the value is None.
# However, macOS tracks timestamps vice versa, using a wrong sign (UTC+3 is -12).
# [EXFAT 1.00] clearly states that UTC+00:15 is 1 and UTC-00:15 is -1.
FileEntry = namedtuple('FileEntry', [ 'is_deleted', 'is_directory', 'name', 'atime', 'atz', 'mtime', 'mtz', 'ctime', 'ctz', 'size', 'valid_data_length', 'attributes', 'first_cluster', 'is_encrypted', 'no_fat_chain' ])

OrphanEntry = namedtuple('OrphanEntry', [ 'name_partial' ])

VolumeLabelEntry = namedtuple('VolumeLabelEntry', [ 'volume_label' ])
AllocationBitmapEntry = namedtuple('AllocationBitmapEntry', [ 'bitmap_id', 'first_cluster', 'size' ])

def ExpandPath(ParentPath, FileEntryOrOrphanEntry):
	if len(ParentPath) > 0 and ParentPath[-1] != PATH_SEPARATOR:
		ParentPath += PATH_SEPARATOR
	elif len(ParentPath) == 0:
		ParentPath = PATH_SEPARATOR

	if type(FileEntryOrOrphanEntry) is FileEntry:
		FileEntryOrig = FileEntryOrOrphanEntry

		is_deleted = FileEntryOrig.is_deleted
		is_directory = FileEntryOrig.is_directory
		name = ParentPath + FileEntryOrig.name
		atime = FileEntryOrig.atime
		atz = FileEntryOrig.atz
		mtime = FileEntryOrig.mtime
		mtz = FileEntryOrig.mtz
		ctime = FileEntryOrig.ctime
		ctz = FileEntryOrig.ctz
		size = FileEntryOrig.size
		valid_data_length = FileEntryOrig.valid_data_length
		attributes = FileEntryOrig.attributes
		first_cluster = FileEntryOrig.first_cluster
		is_encrypted = FileEntryOrig.is_encrypted
		no_fat_chain = FileEntryOrig.no_fat_chain

		return FileEntry(is_deleted, is_directory, name, atime, atz, mtime, mtz, ctime, ctz, size, valid_data_length, attributes, first_cluster, is_encrypted, no_fat_chain)

	elif type(FileEntryOrOrphanEntry) is OrphanEntry:
		name_partial = ParentPath + FileEntryOrOrphanEntry.name_partial

		return OrphanEntry(name_partial)

	# Something is wrong, return the input entry as is.
	return FileEntryOrOrphanEntry

class DirectoryEntries(object):
	"""This class is used to work with directory entries."""

	clusters_buf = None
	is_root = None

	def __init__(self, clusters_buf, is_root = False):
		self.clusters_buf = clusters_buf
		self.is_root = is_root

		if len(self.clusters_buf) < 512 or len(self.clusters_buf) % 512 != 0:
			raise DirectoryEntriesException('Invalid buffer size: {}'.format(len(self.clusters_buf)))

	def entries(self):
		"""Get, decode and yield directory entries in the clusters (as named tuples: FileEntry and OrphanEntry).
		If the 'is_root' argument to the constructor was True, treat the directory entries as located in the root directory.
		(In this case, the following named tuples can be yielded: VolumeLabelEntry and AllocationBitmapEntry.)
		"""

		label_count = 0
		bitmap_count = 0

		pos = 0
		while pos < len(self.clusters_buf):
			entry_type = self.clusters_buf[pos]

			if entry_type == DE_END_OF_DIRECTORY: # We will not scan further, stop.
				break

			if entry_type == DE_INVALID: # Something is wrong with this directory.
				if self.is_root:
					raise DirectoryEntriesException('Invalid directory entry type found')
				else:
					break

			# Decode the entry type.
			type_code, type_importance, type_category, is_in_use = DecodeEntryType(entry_type)

			# Remove the in-use bit.
			entry_type_pure = EntryTypeWithoutInUseBit(entry_type)

			# We are looking for primary entries.
			if type_category == TYPE_CATEGORY_PRIMARY:
				if (not self.is_root) and is_in_use and entry_type_pure in [DE_ALLOCATION_BITMAP, DE_UPCASE_TABLE, DE_VOLUME_LABEL]: # This directory is invalid.
					break

				if (not self.is_root) and is_in_use and entry_type_pure == DE_VOLUME_GUID: # This is unexpected, but not critical, so skip the entry.
					pos += 32
					continue

				if entry_type_pure == DE_TEXFAT_PADDING: # This is a padding entry, skip it.
					pos += 32
					continue

				if entry_type_pure == DE_WINDOWS_CE_ACT: # This entry is not supported, skip it.
					pos += 32
					continue

				if entry_type_pure == DE_FILE: # This is what we want (a file or a directory).
					secondary_count = self.clusters_buf[pos + 1]
					if secondary_count < 2 or secondary_count > 64: # This file entry is invalid, skip it.
						pos += 32
						continue

					# According to [US10726147B2], the "Reserved1" field is used to store the encryption flag.
					# This is also found in the current official implementation of the exFAT driver.
					set_checksum, attributes, data_flags, ctime_int, mtime_int, atime_int, ctime_10ms, mtime_10ms, ctz_int, mtz_int, atz_int = struct.unpack('<HHHLLLBBBBB', self.clusters_buf[pos + 2 : pos + 25])

					ctime = DecodeFATTimestamp(ctime_int, ctime_10ms)
					mtime = DecodeFATTimestamp(mtime_int, mtime_10ms)
					atime = DecodeFATTimestamp(atime_int)
					ctz = DecodeFATTimezone(ctz_int)
					mtz = DecodeFATTimezone(mtz_int)
					atz = DecodeFATTimezone(atz_int)

					is_deleted = not is_in_use
					is_directory = attributes & ATTR_DIRECTORY > 0

					is_encrypted = data_flags & STREAM_DATA_ENCRYPTED > 0

					# Now, validate the entries. No checksum validation is performed against deleted entries.
					secondary_buf = self.clusters_buf[pos + 32 : pos + 32 + secondary_count * 32]

					if len(secondary_buf) != secondary_count * 32: # This entry set is truncated, skip it.
						pos += 32
						continue

					if (not is_deleted) and set_checksum != EntrySetChecksum(self.clusters_buf[pos : pos + 32] + secondary_buf): # Entry set is allocated, but it is invalid, skip it.
						pos += 32
						continue

					# Validate secondary entries.
					is_invalid_set = False
					file_name_count = 0
					file_name_entities = []
					found_vendor_extension = False

					i = 0
					while i < len(secondary_buf):
						secondary_entry_type = secondary_buf[i]
						if secondary_entry_type in [DE_END_OF_DIRECTORY, DE_INVALID]: # This is an invalid entry set, skip it.
							is_invalid_set = True
							break

						secondary_type_code, secondary_type_importance, secondary_type_category, secondary_is_in_use = DecodeEntryType(secondary_entry_type)
						if secondary_type_category != TYPE_CATEGORY_SECONDARY: # This is not a secondary entry, skip the set.
							is_invalid_set = True
							break

						if (not is_deleted) and (not secondary_is_in_use): # This entry is not allocated, but the set must be allocated, so skip the set.
							is_invalid_set = True
							break

						secondary_entry_type_pure = EntryTypeWithoutInUseBit(secondary_entry_type)

						if i == 0 and secondary_entry_type_pure != DE_STREAM_EXTENSION: # The first secondary entry is wrong, skip the set.
							is_invalid_set = True
							break

						if i == 32 and secondary_entry_type_pure != DE_FILE_NAME: # The second secondary entry is wrong, skip the set.
							is_invalid_set = True
							break

						if i >= 64 and secondary_entry_type_pure == DE_STREAM_EXTENSION: # This secondary entry is wrong, skip the set.
							is_invalid_set = True
							break

						if secondary_entry_type_pure == DE_STREAM_EXTENSION:
							stream_flags = secondary_buf[i + 1]
							stream_allocation_possible, stream_no_fat_chain = DecodeFlags(stream_flags)

							if not stream_allocation_possible: # Something is wrong, skip the set.
								is_invalid_set = True
								break

							# According to [US10726147B2], the "Reserved1" field is used to store the padding size (in bytes) for encrypted files.
							# And the "Reserved2" field is split and its first byte is used to store the EFS header size (in 4096-byte increments). The second byte is still reserved.
							# These are also found in the current official implementation of the exFAT driver.
							#
							# Also, for encrypted files with no user data: the file size is 4096 bytes (the file contains the EFS header only), but the valid data length is 0 bytes.

							efs_padding_size, name_length, name_hash, efs_header_size, __, valid_data_length, __, first_cluster, data_length = struct.unpack('<BBHBBQLLQ', secondary_buf[i + 2 : i + 32])

							if efs_header_size > 0:
								efs_header_size = efs_header_size * 4096

							if name_length == 0: # The name is invalid, skip the set. This is 0 if the name length is 256 (a bug in fuse-exfat).
								is_invalid_set = True
								break

							if name_length <= 15:
								max_file_name_count = 1
							elif name_length % 15 == 0:
								max_file_name_count = name_length // 15
							else:
								max_file_name_count = (name_length // 15) + 1

						if secondary_entry_type_pure == DE_FILE_NAME:
							file_name_count += 1

							if file_name_count > max_file_name_count or file_name_count > MAX_NAME_ENTRIES:
								is_invalid_set = True
								break

							file_name_flags = secondary_buf[i + 1]
							# It is unclear from [EXFAT 1.00] if file name entries must have the AllocationPossible flag set to 0.
							# We assume that this flag is not important here. So, do not check it.

							file_name_part_raw = secondary_buf[i + 2 : i + 32]
							file_name_entities.append(file_name_part_raw)

						if found_vendor_extension and secondary_entry_type_pure not in [DE_VENDOR_EXTENSION, DE_VENDOR_ALLOCATION]:
							is_invalid_set = True
							break

						if secondary_entry_type_pure in [DE_VENDOR_EXTENSION, DE_VENDOR_ALLOCATION]: # Found a vendor-specific extension, no other critical entry types can follow this one.
							found_vendor_extension = True

							# Vendor-specific extensions are not supported, so do not validate them.

						i += 32

					if is_invalid_set: # Skip this invalid set.
						pos += 32
						continue

					size = data_length
					no_fat_chain = stream_no_fat_chain

					name = BuildName(file_name_entities, name_length)
					if name is None: # Something is wrong with the name, skip the set.
						pos += 32
						continue

					yield FileEntry(is_deleted, is_directory, name, atime, atz, mtime, mtz, ctime, ctz, size, valid_data_length, attributes, first_cluster, is_encrypted, no_fat_chain)

					pos += 32 + secondary_count * 32
					continue

				if self.is_root and entry_type_pure == DE_VOLUME_LABEL and is_in_use: # This is what we want (a volume label found in the root directory).
					label_count += 1
					if label_count >= 2:
						raise DirectoryEntriesException('More than one volume label found')

					label_character_count = self.clusters_buf[pos + 1]

					# According to [EXFAT 1.00], the volume label limit is 11 characters.
					# However, at least one third-party implementation (exfatlabel) and one old official implementation (the Windows 7 exFAT driver) allow 15 characters.
					# Such volume labels can be read (but not set) by the current Windows driver. In particular:
					# - for a volume label to be read, the limit is 15 characters;
					# - for a volume label to be set, the limit is 11 characters.
					if label_character_count > 15:
						raise DirectoryEntriesException('Invalid volume label length specified')

					if label_character_count > 0:
						volume_label = self.clusters_buf[pos + 2 : pos + 2 + label_character_count * 2]

						volume_label = BuildLabel(volume_label, label_character_count)
						if volume_label is None: # The volume label is invalid.
							raise DirectoryEntriesException('Invalid volume label characters found')

						yield VolumeLabelEntry(volume_label)

				if self.is_root and entry_type_pure == DE_ALLOCATION_BITMAP and is_in_use: # This is what we want (an allocation bitmap found in the root directory).
					bitmap_count += 1
					if bitmap_count >= 3:
						raise DirectoryEntriesException('More than two allocation bitmaps found')

					bitmap_flags = self.clusters_buf[pos + 1]
					bitmap_id = bitmap_flags & 1

					bitmap_first_cluster = struct.unpack('<L', self.clusters_buf[pos + 20 : pos + 24])[0]
					bitmap_data_length = struct.unpack('<Q', self.clusters_buf[pos + 24 : pos + 32])[0]

					yield AllocationBitmapEntry(bitmap_id, bitmap_first_cluster, bitmap_data_length)

			else: # A secondary entry found outside of a valid directory set.
				if entry_type_pure == DE_FILE_NAME:
					file_name_entities = []

					i = 0
					next_entry_type = None
					while next_entry_type == entry_type or next_entry_type is None:
						this_file_name_flags = self.clusters_buf[pos + i * 32 + 1]
						# It is unclear from [EXFAT 1.00] if file name entries must have the AllocationPossible flag set to 0.
						# Previously, we assumed that this flag is not important. Now, when dealing with orphan entries, check it.

						if this_file_name_flags != 0: # This is unusual, skip.
							break

						file_name_part_raw = self.clusters_buf[pos + i * 32 + 2 : pos + i * 32 + 32]
						file_name_entities.append(file_name_part_raw)

						i += 1
						if i >= MAX_NAME_ENTRIES:
							break

						if file_name_part_raw.endswith(b'\x00\x00'): # This was the last entry in the set.
							break

						try:
							next_entry_type = self.clusters_buf[pos + i * 32]
						except IndexError:
							break

					if i > 0:
						name_partial = BuildName(file_name_entities, None)
						if name_partial is not None:
							yield OrphanEntry(name_partial)

							pos += 32 * i
							continue

			pos += 32

	def __str__(self):
		return 'DirectoryEntries'

class Bitmap(object):
	"""This class is used to work with an allocation bitmap."""

	bitmap_buf = None
	last_valid_cluster = None

	def __init__(self, bitmap_buf, last_valid_cluster):
		self.bitmap_buf = bitmap_buf
		self.last_valid_cluster = last_valid_cluster

	def is_allocated(self, cluster):
		"""Check if a given cluster is marked as allocated."""

		if cluster < 2: # The first two clusters are reserved.
			return

		if cluster > self.last_valid_cluster:
			return

		cluster -= 2

		byte_pos = cluster // 8
		bit_pos = cluster % 8

		is_allocated = (self.bitmap_buf[byte_pos] >> bit_pos) & 1 > 0
		return is_allocated

	def __str__(self):
		return 'Bitmap (allocation)'

class FileSystemParser(object):
	"""This class is used to read and parse an exFAT file system (volume)."""

	volume_object = None
	"""A file object for a volume."""

	volume_offset = None
	"""An offset of a volume (in bytes)."""

	volume_size = None
	"""A volume size (in bytes)."""

	br = None
	"""A BR object for this volume."""

	fat = None
	"""A FAT object for this volume."""

	bm = None
	"""A Bitmap object for this volume."""

	cluster_size = None
	"""A cluster size for this volume (in bytes)."""

	data_area_offset = None
	"""Offset of data area (in bytes, relative to the first byte of the volume)."""

	last_valid_cluster = None
	"""The last cluster of this volume."""

	backup_used = None
	"""True if a backup boot region has been used to parse this volume."""

	def __init__(self, volume_object, volume_offset, volume_size = None):
		def try_br(br_offset):
			self.volume_object.seek(self.volume_offset + br_offset)
			br_buf = self.volume_object.read(12 * 4096)
			self.br = BR(br_buf)


		self.volume_object = volume_object
		self.volume_offset = volume_offset
		self.volume_size = volume_size

		if self.volume_size is not None and self.volume_size < 1024 * 1024:
			raise ValueError('Volume is too small')

		for br_offset in [ 0, 12 * 512, 12 * 4096 ]: # A list of boot region offsets to try (one main, one backup for 512-byte sectors, one backup for 4096-byte sectors).
			try:
				try_br(br_offset)
			except (BootRegionException, NotImplementedError):
				self.br = None
			else:
				break

		if self.br is None or (br_offset == 12 * 512 and self.br.get_bytespersector() != 512) or (br_offset == 12 * 4096 and self.br.get_bytespersector() != 4096):
			# No valid boot region found. Or a backup boot region found has a wrong sector size.
			raise BootRegionException('No valid boot region found')

		self.backup_used = br_offset != 0

		sector_size = self.br.get_bytespersector()

		self.cluster_size = sector_size * self.br.get_sectorspercluster()
		self.data_area_offset = self.br.get_clusterheapoffset() * sector_size

		fat_offset = self.br.get_fatoffset() * sector_size
		fat_size = self.br.get_fatlength() * sector_size

		active_fat, __, __, __ = self.br.get_volumeflags()
		if active_fat == 1: # Select the second FAT.
			fat_offset += fat_size

		self.last_valid_cluster = self.br.get_clustercount() + 1
		self.fat = FAT(self.volume_object, self.volume_offset + fat_offset, fat_size, self.last_valid_cluster)

		root_dir_buf = self.read_chain(self.br.get_firstclusterofrootdirectory())
		root_dir = DirectoryEntries(root_dir_buf, True)

		self.bm = None
		for entry in root_dir.entries():
			if type(entry) is AllocationBitmapEntry and entry.bitmap_id == active_fat:
				self.bm = Bitmap(self.read_chain(entry.first_cluster), self.last_valid_cluster)
				break

		if self.bm is None:
			raise FileSystemException('No matching allocation bitmap found')

	def read_chain(self, first_cluster, file_size = None, no_fat_chain = False):
		"""Read clusters in a chain described by its first cluster, return them (as raw bytes).
		Bad clusters are filled with null bytes.
		"""

		if not no_fat_chain: # Use FAT.
			clusters = self.fat.chain(first_cluster)
		else: # Do not use FAT.
			if file_size is None:
				raise ValueError('File size is unknown')

			clusters = []

			if file_size > 0 and first_cluster >= 2:
				curr_cluster = first_cluster
				remaining_size = file_size

				while remaining_size > 0:
					# It is unclear from [EXFAT 1.00] if we should check such a cluster for the "bad" mark set in the FAT.
					# The official implementation has no check for this case. So, we skip it too.

					if curr_cluster > self.last_valid_cluster:
						break

					clusters.append(curr_cluster)

					curr_cluster += 1
					remaining_size -= self.cluster_size

		if len(clusters) == 0: # No data.
			return b''

		bufs = []
		read_bytes = 0

		for cluster in clusters:
			if file_size is not None and read_bytes >= file_size: # If the file size is given, stop when it is reached.
				break

			if cluster is None:
				bufs.append(b'\x00' * self.cluster_size)
				read_bytes += self.cluster_size
				continue

			cluster -= 2 # The first two FAT entries are reserved.

			cluster_offset = self.data_area_offset + cluster * self.cluster_size

			self.volume_object.seek(self.volume_offset + cluster_offset)
			if self.volume_size is not None and cluster_offset + self.cluster_size > self.volume_size:
				raise ValueError('Trying to read beyond the volume')

			cluster_buf = self.volume_object.read(self.cluster_size)
			if len(cluster_buf) != self.cluster_size:
				raise ValueError('Truncated cluster data')

			bufs.append(cluster_buf)
			read_bytes += self.cluster_size

		if file_size is None:
			return b''.join(bufs)

		# If the file size is known, truncate the resulting data.
		return b''.join(bufs)[: file_size]

	def walk(self, scan_reallocated = False):
		"""Walk over the file system, yield tuples (FileEntry, OrphanEntry and VolumeLabelEntry).
		If the 'scan_reallocated' argument is True, also scan reallocated deleted directories.
		"""

		def process_buf(buf, parent_path, stack):
			dir_entries = DirectoryEntries(buf, len(parent_path) == 0)

			prev_first_cluster = None

			for dir_entry in dir_entries.entries():
				if type(dir_entry) is VolumeLabelEntry:
					yield dir_entry

				elif type(dir_entry) is FileEntry:
					if prev_first_cluster is not None and prev_first_cluster in stack:
						stack.remove(prev_first_cluster)

					if dir_entry.is_directory and dir_entry.first_cluster != 0:
						if dir_entry.first_cluster in stack:
							# This is a loop, skip this entry.
							continue

						stack.add(dir_entry.first_cluster)
						prev_first_cluster = dir_entry.first_cluster # We will remove this entry from the stack after this iteration.

					yield ExpandPath(parent_path, dir_entry)

					is_allocated = self.bm.is_allocated(dir_entry.first_cluster)

					if is_allocated is None:
						# This is an invalid cluster.
						continue

					if dir_entry.is_directory: # Walk over subdirectories.
						if (not scan_reallocated) and dir_entry.is_deleted and is_allocated:
							# Do not deal with a deleted directory having its first cluster allocated.
							continue

						try:
							new_buf = self.read_chain(dir_entry.first_cluster, dir_entry.size, dir_entry.no_fat_chain)
						except (FileSystemException, ValueError):
							continue

						if len(new_buf) == 0: # This directory is really empty, skip it.
							continue

						for item in process_buf(new_buf, parent_path + PATH_SEPARATOR + dir_entry.name, set(stack)):
							yield item

				elif type(dir_entry) is OrphanEntry:
					yield ExpandPath(parent_path, dir_entry)


		first = self.br.get_firstclusterofrootdirectory()
		buf = self.read_chain(first)

		stack = set([first])

		for item in process_buf(buf, '', set(stack)): # Pass a new instance of the set ('stack').
			yield item

	def __str__(self):
		return 'FileSystemParser (exFAT)'
