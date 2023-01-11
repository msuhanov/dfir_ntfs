# dfir_ntfs: an NTFS/FAT parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This additional module implements an interface to work with FAT12/16/32 volumes.

# [FATGEN 1.03] is:
# Microsoft Extensible Firmware Initiative FAT32 File System Specification
# FAT: General Overview of On-Disk Format
#
# Version 1.03, December 6, 2000
# Microsoft Corporation
#
# [CC768180] is:
# Chapter 10 - Disks and File Systems
#
# URL: https://docs.microsoft.com/en-us/previous-versions/cc768180(v=technet.10)
# Microsoft Corporation

import struct
from string import ascii_lowercase
from datetime import date, time, datetime, timedelta
from collections import namedtuple

PATH_SEPARATOR = '/'

ClnShutBitMask32 = 0x08000000 # If set, the volume is clean.
HrdErrBitMask32 = 0x04000000 # If set, no hard errors detected.

ClnShutBitMask16 = 0x8000 # If set, the volume is clean.
HrdErrBitMask16 = 0x4000 # If set, no hard errors detected.

FAT_BS_DIRTY = 0x01 # The volume is dirty.
FAT_BS_TEST_SURFACE = 0x02 # The volume has media errors.

FAT32_EOC = 0x0FFFFFF8 # End of chain.
FAT32_BAD = 0x0FFFFFF7 # Bad cluster.

FAT16_EOC = 0xFFF8 # End of chain.
FAT16_BAD = 0xFFF7 # Bad cluster.

FAT12_EOC = 0x0FF8 # End of chain.
FAT12_BAD = 0x0FF7 # Bad cluster.

# File attributes:
ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LONG_NAME = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID

ATTR_LONG_NAME_MASK = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID | ATTR_DIRECTORY | ATTR_ARCHIVE

# Flags for long name entries:
LAST_LONG_ENTRY = 0x40

# A maximum number of long name entries (for a single file).
MAX_LFN_ENTRIES = 20 # ROUNDUP(255/13)...

FILE_ATTR_LIST = { # ATTR_LONG_NAME is not listed on purpose.
	ATTR_READ_ONLY: 'READ_ONLY',
	ATTR_HIDDEN: 'HIDDEN',
	ATTR_SYSTEM: 'SYSTEM',
	ATTR_VOLUME_ID: 'VOLUME_ID',
	ATTR_DIRECTORY: 'DIRECTORY',
	ATTR_ARCHIVE: 'ARCHIVE'
}

# A list of characters forbidden in short (8.3) names.
#
# According to [FATGEN 1.03], the 0x2E character (dot) is forbidden:
#
#   "The following characters are not legal in any bytes of DIR_Name: [...] 0x2E [...]".
#
# This is obviously wrong for the dot and dot-dot entries.
FORBIDDEN_CHARACTERS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 34, 42, 43, 44, 46, 47, 58, 59, 60, 61, 62, 63, 91, 92, 93, 124]

FORBIDDEN_CHARACTERS_LABEL = [0, 10, 13]

# A list of ASCII lowercase characters.
LOWERCASE = ascii_lowercase.encode()

def ResolveFileAttributes(FileAttributes):
	"""Convert file attributes to a string."""

	str_list = []
	for file_attr in sorted(FILE_ATTR_LIST.keys()):
		if FileAttributes & file_attr > 0:
			str_list.append(FILE_ATTR_LIST[file_attr])

	return ' | '.join(str_list)

def IsVolumeLabel(FileAttributes):
	"""Check if given file attributes describe a volume label."""

	if FileAttributes & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME: # This is a long file name.
		return False

	if FileAttributes & (ATTR_DIRECTORY | ATTR_VOLUME_ID) == ATTR_VOLUME_ID: # This is a volume label.
		return True

	return False

# According to [FATGEN 1.03], the only way to determine the FAT type is based on the count of clusters.
# This way is implemented in four functions below. However, there are some notable exceptions...
#
# 1. The Microsoft implementation treats file systems with 4085 or 4086 data clusters as FAT12, not FAT16.
# 2. The FreeBSD implementation treats file systems with 4084 data clusters as FAT16, not FAT12.
# 3. Some users exploit "small" FAT32 volumes for use in embedded devices.
#
# Sources:
# * https://github.com/microsoft/Windows-driver-samples/blob/9e1a643093cac60cd333b6d69abc1e4118a12d63/filesys/fastfat/fat.h#L515
# * https://github.com/freebsd/freebsd-src/blob/b935e867af1855d008de127151d69a1061541ba5/sys/fs/msdosfs/msdosfs_vfsops.c#L612 (note the " + 1" part)
# * https://mail.gnu.org/archive/html/info-mtools/2022-08/msg00000.html and https://mail.gnu.org/archive/html/info-mtools/2022-09/msg00003.html
#
# Currently, no workaround for these cases is provided.

def GetCountOfClusters(BSBPB):
	"""Calculate and return the number of data clusters in the FAT12/16/32 file system."""

	totsec = BSBPB.get_bpb_totsec16()
	if totsec == 0:
		totsec = BSBPB.get_bpb_totsec32()

	if BSBPB.get_bpb_fatsz16() > 0:
		RootDirSectors = (BSBPB.get_bpb_rootentcnt() * 32 + BSBPB.get_bpb_bytspersec() - 1) // BSBPB.get_bpb_bytspersec()
		DataSec = totsec - (BSBPB.get_bpb_rsvdseccnt() + BSBPB.get_bpb_numfats() * BSBPB.get_bpb_fatsz16() + RootDirSectors)
		CountofClusters = DataSec // BSBPB.get_bpb_secperclus()

		return CountofClusters

	DataSec = totsec - (BSBPB.get_bpb_rsvdseccnt() + BSBPB.get_bpb_numfats() * BSBPB.get_bpb_fatsz32())
	CountofClusters = DataSec // BSBPB.get_bpb_secperclus()

	return CountofClusters

def IsFileSystem32(BSBPB):
	"""Check if a given BSBPB object belongs to the FAT32 file system."""

	return GetCountOfClusters(BSBPB) >= 65525

def IsFileSystem16(BSBPB):
	"""Check if a given BSBPB object belongs to the FAT16 file system."""

	CountOfClusters = GetCountOfClusters(BSBPB)
	return CountOfClusters < 65525 and CountOfClusters >= 4085

def IsFileSystem12(BSBPB):
	"""Check if a given BSBPB object belongs to the FAT12 file system."""

	CountOfClusters = GetCountOfClusters(BSBPB)
	return CountOfClusters < 4085 and CountOfClusters > 0

def ValidateShortName(Name):
	"""Validate a given short (8.3) name.
	This function must be used against bytes, not strings.
	"""

	# A special case to consider: "EA DATA  SF".
	# This file contains extended attributes set by the Microsoft implementation (tested on a Windows XP installation).
	# However, extended attributes can exist in FAT12/16 volumes only.
	# In the current versions of the FAT driver, extended attributes are not supported.
	# This case is special because some tools fail to display that file.

	def validate_first(char):
		if char == 0x20: # No space is allowed in the first character.
			return False

		if char in LOWERCASE: # Lowercase characters are not allowed.
			return False

		if char == 0x05: # This is a special case for the first character (KANJI).
			return True

		if char == 0x00: # This is also allowed for the first character.
			return True

		if char in FORBIDDEN_CHARACTERS: # This list includes two special cases mentioned above.
			return False

		return True


	if len(Name) != 11:
		return False

	if Name in [ b'.          ', b'..         ' ]: # Allow dot and dot-dot entries.
		return True

	if not validate_first(Name[0]):
		return False

	for char in Name[1 : ]:
		if char in LOWERCASE:
			return False

		if char in FORBIDDEN_CHARACTERS:
			return False

	return True

def ParseShortName(Name, Encoding = 'ascii', LowerCaseBase = False, LowerCaseExtension = False):
	"""Parse a given short (8.3) name, return a string (or None, if the name is invalid).
	Decoding errors are not raised.
	If the 'Encoding' argument is None, do not decode the string and do not convert its case, return bytes.
	"""

	if not ValidateShortName(Name):
		return

	if Name[0] == 0x00 or Name[0] == 0xE5: # Handle deleted entries.
		Name = b'_' + Name[1 : ]

	elif Name[0] == 0x05: # Handle a special case (KANJI).
		Name = b'\xE5' + Name[1 : ]

	if Encoding is not None:
		base = Name[ : 8].rstrip(b' ').decode(Encoding, errors = 'replace')
		if LowerCaseBase:
			base = base.lower()

		extension = Name[8 : ].rstrip(b' ').decode(Encoding, errors = 'replace')
		if LowerCaseExtension:
			extension = extension.lower()
	else:
		base = Name[ : 8].rstrip(b' ')
		extension = Name[8 : ].rstrip(b' ')

	if len(extension) > 0: # Merge the base name and the extension.
		if Encoding is not None:
			return base + '.' + extension
		else:
			return base + b'.' + extension

	# Return the base name only.
	return base

def BuildLongName(LongEntities):
	"""Parse a given long name, return a string (or None, if the name is empty).
	Decoding errors are not raised.
	"""

	if len(LongEntities) == 0:
		return

	LongEntities.reverse()
	buf = b''.join(LongEntities)

	# Remove everything after the first null character (including it).
	i = 0
	while i < len(buf):
		if buf[i : i + 2] == b'\x00\x00':
			buf = buf[ : i]
			break

		i += 2

	long_name = buf.decode('utf-16le', errors = 'replace')
	if len(long_name) == 0: # This is an invalid long name.
		return

	if len(long_name) > 255: # If this name is too long, truncate it.
		return long_name[ : 255]

	return long_name

def BuildChecksum(ShortNameRaw):
	"""Calculate and return the short name checksum."""

	checksum = 0
	for i in range(11):
		right_bit = checksum & 1
		if right_bit == 0:
			checksum = checksum >> 1
		else:
			checksum = (checksum >> 1) | 0x80

		checksum = (checksum + ShortNameRaw[i]) & 0xFF

	return checksum

def DecodeFATDate(Value):
	"""Decode and return the date object (or None, if the date is invalid)."""

	day = Value & 0x1F
	if day == 0: # 0x1F = 31.
		return

	month = (Value >> 5) & 0x0F
	if month == 0 or month > 12:
		return

	year = (Value >> 9) & 0x7F
	if year > 127:
		return

	year += 1980

	try:
		return date(year, month, day)
	except ValueError:
		return

def DecodeFATTime(Value):
	"""Decode and return the time object (or None, if the time is invalid)."""

	second = Value & 0x1F
	if second > 29:
		return

	second *= 2

	minute = (Value >> 5) & 0x3F
	if minute > 59:
		return

	hour = (Value >> 11) & 0x1F
	if hour > 23:
		return

	return time(hour, minute, second)

NTBytePaddings = { # Remaining bits: padding size.
	0x00: 0,
	0xE4: 15,
	0xE0: 14,
	0xC4: 13,
	0xC0: 12,
	0xA4: 11,
	0xA0: 10,
	0x84: 9,
	0x80: 8,
	0x64: 7,
	0x60: 6,
	0x44: 5,
	0x40: 4,
	0x24: 3,
	0x20: 2,
	0x04: 1
}

def ParseNTByte(Value):
	"""Decode the NTByte field, return a tuple: (lowercase_base, lowercase_extension, encrypted, large_efs_header, padding_size)."""

	# According to the Azure RTOS FileX driver source code, the 0x08 and 0x10 flags have these meanings:
	#  * "BIT3 - set if 8.3 is all in lower case and no extended filename";
	#  * "BIT4 - set for file, clear for directory entry if no extended filename".
	#
	# Sources:
	# * https://github.com/azure-rtos/filex/blob/3b203634dce8fc51e77ac67ec28d91d693c2c570/common/src/fx_directory_entry_read.c#L632
	# * https://github.com/azure-rtos/filex/blob/3b203634dce8fc51e77ac67ec28d91d693c2c570/common/src/fx_unicode_directory_entry_read.c#L644
	#
	# This is a mistake. In the Windows driver, 0x08 is "base name (8) is lowercase" and 0x10 is "extension (3) is lowercase".
	#
	# This mistake could be caused by misinterpreting the following test:
	# * create a file with lowercase characters in its name and extension (this sets both bits);
	# * create a directory with lowercase characters in its name, while no extension is given (this sets one bit).
	#
	# (Now, both bits can be misinterpreted.)

	lowercase_base = Value & 0x08 > 0
	lowercase_extension = Value & 0x10 > 0
	encrypted = Value & 0x01 > 0

	if encrypted:
		large_efs_header = Value & 0x02 > 0
	else:
		large_efs_header = False

	if encrypted:
		remaining_bits = Value & 0xE4
		padding_size = NTBytePaddings[remaining_bits]
	else:
		padding_size = None

	return (lowercase_base, lowercase_extension, encrypted, large_efs_header, padding_size)

class FileSystemException(Exception):
	"""This is a top-level exception for this module."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class BootSectorException(FileSystemException):
	"""This exception is raised when something is wrong with the boot sector or the BIOS parameter block."""

	pass

class FileSystemInfoException(FileSystemException):
	"""This exception is raised when something is wrong with the file system information (FSI) sector."""

	pass

class FileAllocationTableException(FileSystemException):
	"""This exception is raised when something is wrong with the file allocation table (FAT)."""

	pass

class DirectoryEntriesException(FileSystemException):
	"""This exception is raised when something is wrong with directory entries."""

	pass

class BSBPB(object):
	"""This class is used to work with a boot sector (BS) containing a BIOS parameter block (BPB)."""

	bs_buf = None
	is_fat32 = None

	def __init__(self, bs_buf, relaxed_checks = False):
		self.bs_buf = bs_buf

		if len(self.bs_buf) != 512:
			raise BootSectorException('Invalid boot sector size')

		if not relaxed_checks:
			if self.get_signature() != b'\x55\xaa': # Check the boot sector signature.

				# If there is no valid boot sector signature, check the jump code. See:
				# * https://reviews.freebsd.org/D34699

				jmp_code = self.get_bs_jmpboot()
				if jmp_code[0] != 0xE9 and jmp_code[0] != 0xEB: # In the latter case, the NOP instruction (0x90) in the third byte is not checked.
					raise BootSectorException('Invalid boot sector signature and no valid jump code present')

		# First, assume FAT32.
		self.is_fat32 = True
		try:
			if IsFileSystem32(self):
				self.get_bpb_fsver()
		except BootSectorException:
			# Then, try FAT12/16.
			self.is_fat32 = False
			if not (IsFileSystem16(self) or IsFileSystem12(self)):
				raise BootSectorException('Unsupported file system (not FAT12/16/32)')

	def get_bs_jmpboot(self):
		"""Get and return the first 3 bytes."""

		return self.bs_buf[ : 3]

	def get_bs_oemname(self):
		"""Get and return the OEM name (as raw bytes)."""

		return self.bs_buf[3 : 11]

	def get_bpb_bytspersec(self):
		"""Get and return the bytes per sector value."""

		bps = struct.unpack('<H', self.bs_buf[11 : 13])[0]
		if bps not in [512, 1024, 2048, 4096]:
			raise BootSectorException('Invalid number of bytes per sector: {}'.format(bps))

		return bps

	def get_bpb_secperclus(self):
		"""Get and return the sectors per cluster value."""

		spc = struct.unpack('<B', self.bs_buf[13 : 14])[0]

		# According to one source, 0 means 256 here. This is not supported now. See:
		# * https://github.com/FDOS/kernel/pull/95/commits/293a3f5b5a27ad16148ca515a27fa827e233f7fd

		if spc not in [1, 2, 4, 8, 16, 32, 64, 128]:
			raise BootSectorException('Invalid number of sectors per cluster: {}'.format(spc))

		# According to [FATGEN 1.03], the number of bytes per cluster should never be greater than 32768 bytes.
		# It also notes that "[s]ome versions of some systems allow 64K bytes per cluster value".
		# This limit is not checked here. The reason is that Linux-based operating systems can create and mount a FAT volume with a larger cluster size.
		# (For example, 524288 bytes per cluster are supported: 4096 bytes per sector, 128 sectors per cluster.)

		return spc

	def get_bpb_rsvdseccnt(self):
		"""Get and return the reserved sectors count."""

		rsvd = struct.unpack('<H', self.bs_buf[14 : 16])[0]
		if rsvd == 0:
			raise BootSectorException('Invalid number of reserved sectors')

		return rsvd

	def get_bpb_numfats(self):
		"""Get and return the number of FATs."""

		fats = struct.unpack('<B', self.bs_buf[16 : 17])[0]
		if fats == 0:
			raise BootSectorException('Invalid number of FATs')

		return fats

	def get_bpb_rootentcnt(self):
		"""Get and return the number of entries in the root directory."""

		cnt = struct.unpack('<H', self.bs_buf[17 : 19])[0]
		if cnt > 0 and self.is_fat32:
			raise BootSectorException('Invalid number of root entries')

		return cnt

	def get_bpb_totsec16(self):
		"""Get and return the 16-bit number of sectors on the volume."""

		tot = struct.unpack('<H', self.bs_buf[19 : 21])[0]
		if tot > 0 and self.is_fat32:
			raise BootSectorException('Invalid number (16) of total sectors')

		return tot

	def get_bpb_media(self):
		"""Get and return the media type (as an integer)."""

		media = struct.unpack('<B', self.bs_buf[21 : 22])[0]
		if media not in [0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF]:
			raise BootSectorException('Invalid media type: {}'.format(hex(media)))

		return media

	def get_bpb_fatsz16(self):
		"""Get and return the 16-bit number of sectors in one FAT."""

		cnt = struct.unpack('<H', self.bs_buf[22 : 24])[0]
		if cnt > 0 and self.is_fat32:
			raise BootSectorException('Invalid number (16) of FAT sectors')

		return cnt

	def get_bpb_secpertrk(self):
		"""Get and return the number of sectors per track."""

		return struct.unpack('<H', self.bs_buf[24 : 26])[0]

	def get_bpb_numheads(self):
		"""Get and return the number of heads."""

		return struct.unpack('<H', self.bs_buf[26 : 28])[0]

	def get_bpb_hiddsec(self):
		"""Get and return the number of hidden sectors (before the partition)."""

		return struct.unpack('<L', self.bs_buf[28 : 32])[0]

	def get_bpb_totsec32(self):
		"""Get and return the 32-bit number of sectors on the volume."""

		tot = struct.unpack('<L', self.bs_buf[32 : 36])[0]
		if tot == 0 and self.is_fat32:
			raise BootSectorException('Invalid number of total sectors')

		return tot

	def get_signature(self):
		"""Get and return the boot signature (as two raw bytes)."""

		return self.bs_buf[510 : 512]

	def get_bpb_fatsz32(self):
		"""Get and return the 32-bit number of sectors in one FAT."""

		if not self.is_fat32:
			return

		cnt = struct.unpack('<L', self.bs_buf[36 : 40])[0]
		if cnt == 0:
			raise BootSectorException('Invalid number of FAT sectors')

		return cnt

	def get_bpb_extflags(self):
		"""Get and return the flags as a tuple: (active_fat_number, is_fat_mirroring_disabled)."""

		if not self.is_fat32:
			return (None, None)

		flags = struct.unpack('<H', self.bs_buf[40 : 42])[0]

		active_fat_number = flags & 0xF
		is_fat_mirroring_disabled = flags & 0x80 > 0

		return (active_fat_number, is_fat_mirroring_disabled)

	def get_bpb_fsver(self):
		"""Get and return the file system version (as an integer).
		This must be zero (0.0).
		"""

		if not self.is_fat32:
			return

		fsver = struct.unpack('<H', self.bs_buf[42 : 44])[0]
		if fsver != 0:
			raise NotImplementedError('File system version is not supported: {}'.format(hex(fsver)))

		return fsver

	def get_bpb_rootclus(self):
		"""Get and return the root cluster."""

		if not self.is_fat32:
			return

		rootclus = struct.unpack('<L', self.bs_buf[44 : 48])[0]
		if rootclus < 2:
			raise BootSectorException('Invalid root cluster: {}'.format(rootclus))

		return rootclus

	def get_bpb_fsinfo(self):
		"""Get and return the file system information sector number."""

		if not self.is_fat32:
			return

		return struct.unpack('<H', self.bs_buf[48 : 50])[0]

	def get_bpb_bkbootsec(self):
		"""Get and return the backup boot sector."""

		if not self.is_fat32:
			return

		bk = struct.unpack('<H', self.bs_buf[50 : 52])[0]
		if bk == 0:
			raise BootSectorException('Invalid backup boot sector: {}'.format(bk))

		return bk

	def get_bpb_reserved(self):
		"""Get and return the reserved area (as raw bytes)."""

		if not self.is_fat32:
			return

		return self.bs_buf[52 : 64]

	def get_bs_drvnum(self):
		"""Get and return the drive number."""

		if not self.is_fat32:
			return struct.unpack('<B', self.bs_buf[36 : 37])[0]

		return struct.unpack('<B', self.bs_buf[64 : 65])[0]

	def get_bs_dirty_flags(self):
		"""Get and return the dirty flags."""

		# According to [FATGEN 1.03], this field is reserved, but it is not.

		if not self.is_fat32:
			return struct.unpack('<B', self.bs_buf[37 : 38])[0]

		return struct.unpack('<B', self.bs_buf[65 : 66])[0]

	def is_volume_dirty(self):
		"""Check if the volume is marked as dirty, return a tuple: (is_dirty, needs_surface_check)."""

		flags = self.get_bs_dirty_flags()

		is_dirty = (flags & FAT_BS_DIRTY) > 0
		needs_surface_check = (flags & FAT_BS_TEST_SURFACE) > 0

		return (is_dirty, needs_surface_check)

	def get_bs_bootsig(self):
		"""Get and return the boot signature."""

		if not self.is_fat32:
			return struct.unpack('<B', self.bs_buf[38 : 39])[0]

		return struct.unpack('<B', self.bs_buf[66 : 67])[0]

	def get_bs_extfields(self):
		"""Get and return the extended fields (if set).
		A tuple is returned: (volume_id, volume_label, fs_type).
		If the extended fields are not present, return (None, None, None).
		"""

		if self.get_bs_bootsig() != 0x29:
			return (None, None, None)

		if self.is_fat32:
			volume_id = struct.unpack('<L', self.bs_buf[67 : 71])[0]
			volume_label = self.bs_buf[71 : 82]
			fs_type = self.bs_buf[82 : 90]
		else:
			volume_id = struct.unpack('<L', self.bs_buf[39 : 43])[0]
			volume_label = self.bs_buf[43 : 54]
			fs_type = self.bs_buf[54 : 62]

		return (volume_id, volume_label, fs_type)

	def fat_offset_and_size(self):
		"""Calculate and return the offset and size of the active FAT (plus, the last valid data cluster).
		A tuple is returned: (offset_in_bytes, size_in_bytes, last_data_cluster_plus_one).
		"""

		if not self.is_fat32:
			# Use FAT 0.
			offset_in_bytes = self.get_bpb_rsvdseccnt() * self.get_bpb_bytspersec()
			size_in_bytes = self.get_bpb_fatsz16() * self.get_bpb_bytspersec()
			last_data_cluster_plus_one = GetCountOfClusters(self) + 1

			return (offset_in_bytes, size_in_bytes, last_data_cluster_plus_one)

		active_fat_number, is_fat_mirroring_disabled = self.get_bpb_extflags()

		if not is_fat_mirroring_disabled:
			fat_num = 0 # Use FAT 0.
		else:
			fat_num = active_fat_number
			if fat_num + 1 > self.get_bpb_numfats(): # Something is wrong, use FAT 0.
				fat_num = 0

		offset_in_bytes = (self.get_bpb_rsvdseccnt() + self.get_bpb_fatsz32() * fat_num) * self.get_bpb_bytspersec()
		size_in_bytes = self.get_bpb_fatsz32() * self.get_bpb_bytspersec()
		last_data_cluster_plus_one = GetCountOfClusters(self) + 1

		return (offset_in_bytes, size_in_bytes, last_data_cluster_plus_one)

	def __str__(self):
		return 'BSBPB'

class FSINFO(object):
	"""This class is used to work with file system information (FSINFO)."""

	fsinfo_buf = None

	def __init__(self, fsinfo_buf):
		self.fsinfo_buf = fsinfo_buf

		if self.get_fsi_signatures() != (0x41615252, 0x61417272, 0xAA550000):
			raise FileSystemInfoException('Invalid FSI signatures')

	def get_fsi_signatures(self):
		"""Get and return three FSINFO signatures, as a tuple: (lead, struc, trail)."""

		lead = struct.unpack('<L', self.fsinfo_buf[ : 4])[0]
		struc = struct.unpack('<L', self.fsinfo_buf[484 : 488])[0]
		trail = struct.unpack('<L', self.fsinfo_buf[508 : 512])[0]

		return (lead, struc, trail)

	def get_fsi_reserved1(self):
		"""Get and return the first reserved area (as raw bytes)."""

		return self.fsinfo_buf[4 : 484]

	def get_fsi_free_count(self):
		"""Get and return the last known free cluster count."""

		return struct.unpack('<L', self.fsinfo_buf[488 : 492])[0]

	def get_fsi_nxt_free(self):
		"""Get and return the free cluster hint."""

		return struct.unpack('<L', self.fsinfo_buf[492 : 496])[0]

	def get_fsi_reserved2(self):
		"""Get and return the second reserved area (as raw bytes)."""

		return self.fsinfo_buf[496 : 508]

	def __str__(self):
		return 'FSINFO'

class FAT(object):
	"""This class is used to work with a file allocation table (12/16/32-bit)."""

	fat_object = None
	fat_offset = None
	fat_size = None
	last_valid_cluster = None
	fat_type = None

	fat_eoc = None
	fat_bad = None
	fat_element_size = None

	def __init__(self, fat_object, fat_offset, fat_size, last_valid_cluster, fat_type = 32):
		self.fat_object = fat_object
		self.fat_offset = fat_offset
		self.fat_size = fat_size
		self.last_valid_cluster = last_valid_cluster
		self.fat_type = fat_type

		if self.fat_type not in [ 12, 16, 32 ]:
			raise ValueError('Unknown FAT type, known types are: 12, 16 or 32')

		if self.fat_type == 32:
			self.fat_eoc = FAT32_EOC
			self.fat_bad = FAT32_BAD
			self.fat_element_size = 4
		elif self.fat_type == 16:
			self.fat_eoc = FAT16_EOC
			self.fat_bad = FAT16_BAD
			self.fat_element_size = 2
		else:
			self.fat_eoc = FAT12_EOC
			self.fat_bad = FAT12_BAD
			self.fat_element_size = 1.5

		if self.fat_offset > 0 and self.fat_offset % 512 != 0:
			raise FileAllocationTableException('Invalid FAT offset: {}'.format(self.fat_offset))

		if self.fat_size < 512 or self.fat_size % 512 != 0:
			raise FileAllocationTableException('Invalid FAT size: {}'.format(self.fat_size))

	def get_element(self, number):
		"""Get and return the FAT entry by its number."""

		if self.fat_element_size in [2, 4]: # FAT16/32.
			fat_item_offset = number * self.fat_element_size
			if fat_item_offset + self.fat_element_size > self.fat_size or number > self.last_valid_cluster:
				raise FileAllocationTableException('Out of bounds, FAT element: {}'.format(number))

			self.fat_object.seek(self.fat_offset + fat_item_offset)
			next_element_raw = self.fat_object.read(self.fat_element_size)
			if len(next_element_raw) != self.fat_element_size:
				raise FileAllocationTableException('Truncated FAT entry, FAT element: {}'.format(number))

			if self.fat_element_size == 4:
				next_cluster = struct.unpack('<L', next_element_raw)[0] & 0x0FFFFFFF # The high 4 bits are reserved.
			else:
				next_cluster = struct.unpack('<H', next_element_raw)[0]
		else: # FAT12.
			fat_item_offset = number + number // 2
			if fat_item_offset + 2 > self.fat_size or number > self.last_valid_cluster:
				raise FileAllocationTableException('Out of bounds, FAT element: {}'.format(number))

			self.fat_object.seek(self.fat_offset + fat_item_offset)
			next_element_raw = self.fat_object.read(2)
			if len(next_element_raw) != 2:
				raise FileAllocationTableException('Truncated FAT entry, FAT element: {}'.format(number))

			next_item = struct.unpack('<H', next_element_raw)[0]
			if number % 2 == 0:
				next_cluster = next_item & 0x0FFF
			else:
				next_cluster = next_item >> 4

		return next_cluster

	def get_bpb_media(self):
		"""Get and return the BPB media value."""

		fat_0 = self.get_element(0)
		return fat_0 & 0xFF

	# Do not use two methods below. The FAT[1] entry is "broken".
	#
	# According to [FATGEN 1.03], the FAT[1] entry should be set according to two bit masks:
	#   - 0x08000000 (when set, the volume is clean);
	#   - 0x04000000 (when set, the volume has no hard errors detected).
	#
	# According to [CC768180], the last byte of the FAT[1] entry ("the eighth byte") should be set to 0x0F by default.
	# During the write, the fourth bit (of that byte) is set to 0 (0x07).
	# If a hard sector error is detected, the third bit (of that byte) is set to 0 (0x0B).
	# These bits match the bit masks above.
	#
	# In Windows, the following value is written when the volume is dirty (not clean):
	#     0x7FFFFFFF (raw bytes: FFFFFF7F).
	#
	# According to the bit masks, the value means: the volume is clean (while it is not), no hard errors detected.
	#
	# And, for example, macOS sets this entry to the following value (when the volume is dirty):
	#     0xF7FFFFFF (raw bytes: FFFFFFF7).
	#
	# According to the bit masks, the value means: the volume is not clean, no hard errors detected.
	# This value is expected. But Windows uses a different value!
	#
	# So, this looks like a typo in the Windows driver. This goes back to Windows 2000 (or even to an earlier version).

	def is_volume_dirty(self):
		"""Check if the dirty bit is set (FAT16/32). Do not use!"""

		if self.fat_type == 12:
			return

		fat_1 = self.get_element(1)

		if self.fat_type == 32:
			return (fat_1 & ClnShutBitMask32) == 0
		else:
			return (fat_1 & ClnShutBitMask16) == 0

	def are_hard_errors_detected(self):
		"""Check if hard errors bit is set (FAT16/32). Do not use!"""

		if self.fat_type == 12:
			return

		fat_1 = self.get_element(1)

		if self.fat_type == 32:
			return (fat_1 & HrdErrBitMask32) == 0
		else:
			return (fat_1 & HrdErrBitMask16) == 0

	def chain(self, first_cluster):
		"""Get and return the cluster chain for the given first cluster (as a list of cluster numbers).
		For bad clusters, None is given (as an item in the chain).
		"""

		if first_cluster == 0:
			# This file is empty (or the first cluster is marked as unallocated), no chain.
			return []

		if first_cluster == 1:
			# This cluster is reserved, no chain.
			return []

		if first_cluster == self.fat_bad:
			# The first cluster is bad.
			raise FileAllocationTableException('Bad starting cluster {}'.format(first_cluster))

		chain = [ first_cluster ]

		curr_cluster = first_cluster
		while True:
			next_cluster = self.get_element(curr_cluster)

			if next_cluster in chain: # This is a loop, the FAT is corrupted, stop (but do not raise an exception).
				break

			if next_cluster >= self.fat_eoc:
				# End of chain, stop.
				break
			elif next_cluster == self.fat_bad:
				# Bad cluster, use None and stop.
				chain.append(None)
				break
			elif next_cluster == 0:
				# This is unallocated cluster, stop.
				break
			elif next_cluster == 1:
				# This cluster is reserved, stop.
				break

			chain.append(next_cluster)
			curr_cluster = next_cluster

		return chain

	def is_allocated(self, cluster):
		"""Check if a given cluster is marked as allocated (None is returned if the cluster is invalid)."""

		try:
			return self.get_element(cluster) != 0
		except FileAllocationTableException:
			return

	def __str__(self):
		return 'FAT'

# Here, "ctime" means "created time" or "inode changed time".
# In Windows and macOS, it is "created time".
# In Linux, it is "inode changed time" (before Linux 5.19) or "created time" (Linux 5.19 and later).
# QEMU VVFAT maps "inode changed time" into this field too.
FileEntry = namedtuple('FileEntry', [ 'is_deleted', 'is_directory', 'short_name', 'short_name_raw', 'long_name', 'atime', 'mtime', 'ctime', 'size', 'attributes', 'ntbyte', 'first_cluster', 'is_encrypted' ])

OrphanLongEntry = namedtuple('OrphanLongEntry', [ 'long_name_partial' ])

def ExpandPath(ParentPath, FileEntryOrOrphanLongEntry):
	if len(ParentPath) > 0 and ParentPath[-1] != PATH_SEPARATOR:
		ParentPath += PATH_SEPARATOR
	elif len(ParentPath) == 0:
		ParentPath = PATH_SEPARATOR

	if type(FileEntryOrOrphanLongEntry) is FileEntry:
		is_deleted = FileEntryOrOrphanLongEntry.is_deleted
		is_directory = FileEntryOrOrphanLongEntry.is_directory
		short_name = ParentPath + FileEntryOrOrphanLongEntry.short_name
		short_name_raw = FileEntryOrOrphanLongEntry.short_name_raw

		long_name = FileEntryOrOrphanLongEntry.long_name
		if FileEntryOrOrphanLongEntry.long_name is not None:
			long_name = ParentPath + FileEntryOrOrphanLongEntry.long_name

		atime = FileEntryOrOrphanLongEntry.atime
		mtime = FileEntryOrOrphanLongEntry.mtime
		ctime = FileEntryOrOrphanLongEntry.ctime
		size = FileEntryOrOrphanLongEntry.size
		attributes = FileEntryOrOrphanLongEntry.attributes
		ntbyte = FileEntryOrOrphanLongEntry.ntbyte
		first_cluster = FileEntryOrOrphanLongEntry.first_cluster
		is_encrypted = FileEntryOrOrphanLongEntry.is_encrypted

		return FileEntry(is_deleted, is_directory, short_name, short_name_raw, long_name, atime, mtime, ctime, size, attributes, ntbyte, first_cluster, is_encrypted)
	elif type(FileEntryOrOrphanLongEntry) is OrphanLongEntry:
		long_name_partial = ParentPath + FileEntryOrOrphanLongEntry.long_name_partial

		return OrphanLongEntry(long_name_partial)

	# Something is wrong, return the input entry as is.
	return FileEntryOrOrphanLongEntry

class DirectoryEntries(object):
	"""This class is used to work with directory entries."""

	clusters_buf = None
	is_fat32 = None

	def __init__(self, clusters_buf, is_fat32 = True):
		self.clusters_buf = clusters_buf

		if len(self.clusters_buf) < 512 or len(self.clusters_buf) % 512 != 0:
			raise DirectoryEntriesException('Invalid buffer size: {}'.format(len(self.clusters_buf)))

		self.is_fat32 = is_fat32

	def entries(self, encoding = 'ascii', short_only = False):
		"""Get, decode and return directory entries in the clusters (as named tuples: FileEntry; also, if the 'short_only' argument is False: OrphanLongEntry).
		The 'encoding' argument provides the codepage for short (8.3) name entries.
		If the 'short_only' argument is False, parse long file name entries.
		"""

		def get_real_long_order_number(long_order): # Remove the LAST_LONG_ENTRY flag, if set.
			if long_order & LAST_LONG_ENTRY > 0:
				return long_order - LAST_LONG_ENTRY

			return long_order

		def are_long_names_coherent(long_order, long_checksum, prev_long_order, prev_long_checksum):
			# Check if there is no previous entry.
			if prev_long_order is None or prev_long_checksum is None:
				# Check if the only entry is allocated.
				if long_order not in [ 0x00, 0xE5 ]:
					# Check if the LAST_LONG_ENTRY flag is set and the order number is valid.
					if long_order & LAST_LONG_ENTRY > 0 and long_order - LAST_LONG_ENTRY <= MAX_LFN_ENTRIES and long_order - LAST_LONG_ENTRY > 0:
						return True
				else:
					# Nothing to check here.
					return True

			# Check if both entries are deleted.
			if long_order in [ 0x00, 0xE5 ] and prev_long_order in [ 0x00, 0xE5 ]:
				# Check if checksums match.
				if long_checksum == prev_long_checksum:
					return True

				# No need to do other checks now.
				return False

			# Check if both entries are allocated.
			if long_order not in [ 0x00, 0xE5 ] and prev_long_order is not None and prev_long_order not in [ 0x00, 0xE5 ]:
				# Check if checksums match.
				if long_checksum == prev_long_checksum:
					# Check if the LAST_LONG_ENTRY flag is not set.
					if long_order & LAST_LONG_ENTRY == 0:
						# Check if the order numbers are valid.
						if long_order <= MAX_LFN_ENTRIES and long_order > 0:
							if get_real_long_order_number(prev_long_order) == long_order + 1:
								return True

				# No need to do other checks now.
				return False

			# In any case not covered before, report long entries as not coherent.
			return False


		long_entities = []
		prev_long_order = None
		prev_long_checksum = None

		found_null = False

		pos = 0
		while pos < len(self.clusters_buf):
			previous_entry_is_file = False
			long_name = None

			attributes = self.clusters_buf[pos + 11] & 0x3F # Remove the upper two bits.

			if self.clusters_buf[pos] == 0x00: # We found a null directory entry. Now, all subsequent directory entries should be reported as unallocated (or "unknown").
				found_null = True

			if attributes & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME: # Looks like a long name entry.
				if short_only: # But we do not need it, so skip.
					pos += 32
					continue

				entry_type = self.clusters_buf[pos + 12]
				if entry_type != 0: # Not a long name entry, skip it.
					pos += 32
					continue

				long_order = self.clusters_buf[pos]
				long_checksum = self.clusters_buf[pos + 13]

				long_name_1 = self.clusters_buf[pos + 1 : pos + 11]
				long_name_2 = self.clusters_buf[pos + 14 : pos + 26]
				long_name_3 = self.clusters_buf[pos + 28 : pos + 32]

				is_long_entry_valid = are_long_names_coherent(long_order, long_checksum, prev_long_order, prev_long_checksum)

				if not is_long_entry_valid:
					if len(long_entities) > 0:
						long_name_partial = BuildLongName(long_entities)
						yield OrphanLongEntry(long_name_partial)

					# Reset the long name stash and try this entry as the first one in the set.
					long_entities = []
					prev_long_order = None
					prev_long_checksum = None

					if are_long_names_coherent(long_order, long_checksum, None, None):
						prev_long_order = long_order
						prev_long_checksum = long_checksum

						long_entities.append(long_name_3)
						long_entities.append(long_name_2)
						long_entities.append(long_name_1)

					pos += 32
					continue

				prev_long_order = long_order
				prev_long_checksum = long_checksum

				long_entities.append(long_name_3)
				long_entities.append(long_name_2)
				long_entities.append(long_name_1)

				pos += 32
				continue

			short_name_raw = self.clusters_buf[pos : pos + 11]
			ntbyte = self.clusters_buf[pos + 12]
			lowercase_base, lowercase_extension, is_encrypted, __, __ = ParseNTByte(ntbyte)

			is_deleted = short_name_raw[0] in [ 0x00, 0xE5 ] # This will be adjusted according to the 'found_null' variable later.

			if not IsVolumeLabel(attributes):
				short_name_raw_norm = ParseShortName(short_name_raw, None, lowercase_base, lowercase_extension)
				short_name = ParseShortName(short_name_raw, encoding, lowercase_base, lowercase_extension)
			else:
				# A volume label has almost no restrictions.

				if short_name_raw[0] == 0x00 or short_name_raw[0] == 0xE5:
					short_name_raw = b'_' + short_name_raw[1 : ]
				elif short_name_raw[0] == 0x05:
					short_name_raw = b'\xE5' + short_name_raw[1 : ]

				is_valid_label = True
				for char in short_name_raw:
					if char in FORBIDDEN_CHARACTERS_LABEL:
						is_valid_label = False
						break

				if is_valid_label:
					short_name = short_name_raw.rstrip(b' ').decode(encoding, errors = 'replace')
					short_name_raw_norm = short_name_raw.rstrip(b' ')
				else:
					short_name = None
					short_name_raw_norm = None

			# Build a long name (if any), validate the checksum, the order number, then reset the stash.
			# This code should be executed before any checks against a short name!

			if not is_deleted:
				# If the short name entry is not deleted, check the checksum and the long order.
				# The previous long order must be equal to 1. This also means that the long name entries are allocated.

				if prev_long_checksum is not None and prev_long_order is not None and prev_long_checksum == BuildChecksum(short_name_raw) and get_real_long_order_number(prev_long_order) == 1:
					long_name = BuildLongName(long_entities)
				else:
					if len(long_entities) > 0:
						long_name_partial = BuildLongName(long_entities)
						yield OrphanLongEntry(long_name_partial)

					long_name = None
			else:
				# Since the first byte is lost (when entries are deleted), skip the validation (the checksum and the long order).
				# The previous long name entry can be allocated, though (if the file was deleted on a system that does not support long file names).

				long_name = BuildLongName(long_entities)

			long_entities = []
			prev_long_order = None
			prev_long_checksum = None

			if short_name is None: # The short name is invalid, skip to the next entry.
				if long_name is not None:
					yield OrphanLongEntry(long_name)

				pos += 32
				continue

			if attributes & (ATTR_DIRECTORY | ATTR_VOLUME_ID) == ATTR_DIRECTORY:
				is_directory = True
			elif attributes & (ATTR_DIRECTORY | ATTR_VOLUME_ID) == 0:
				is_directory = False
			elif attributes & (ATTR_DIRECTORY | ATTR_VOLUME_ID) == ATTR_VOLUME_ID: # Is a special file (volume ID).
				is_directory = False
			else: # Not a valid entry, skip it.
				if long_name is not None:
					yield OrphanLongEntry(long_name)

				pos += 32
				continue

			if len(self.clusters_buf[pos : pos + 32].lstrip(b'\xE5')) == 0 or len(self.clusters_buf[pos : pos + 32].lstrip(b'\x00')) == 0:
				# Not a valid entry (it is the 0xE5 or 0x00 pattern), skip it.
				if long_name is not None:
					yield OrphanLongEntry(long_name)

				pos += 32
				continue

			# According to [FATGEN 1.03], this is "a count of tenths of a second". This is obviously wrong, it is a count of 10 ms increments.
			ctime_fat_tenth = self.clusters_buf[pos + 13]
			if ctime_fat_tenth > 199: # This is an invalid value, reset it to 0.
				ctime_fat_tenth = 0

			ctime_fat = DecodeFATTime(struct.unpack('<H', self.clusters_buf[pos + 14 : pos + 16])[0])
			cdate_fat = DecodeFATDate(struct.unpack('<H', self.clusters_buf[pos + 16 : pos + 18])[0])

			# According to the "rugged" FAT driver found in the Symbian operating system, the "Last access date" field is used for a different purpose.
			# In that driver, the field contains the entry ID (either 0 or 1). It is used to perform fault-tolerant updates to directory entries.
			# This meaning of the field is not supported here. The DecodeFATDate() function must return None ("no valid date set") for 0 and 1.
			#
			# Sources:
			# * https://github.com/SymbianSource/oss.FCL.sf.os.kernelhwsrv/blob/0c3208650587ac0230aed8a74e9bddb5288023eb/userlibandfileserver/fileserver/sfat/fat_dir_entry.h#L65
			# * https://github.com/SymbianSource/oss.FCL.sf.os.kernelhwsrv/blob/0c3208650587ac0230aed8a74e9bddb5288023eb/userlibandfileserver/fileserver/sfat/fat_dir_entry.h#L47
			# * https://github.com/SymbianSource/oss.FCL.sf.os.kernelhwsrv/blob/0c3208650587ac0230aed8a74e9bddb5288023eb/userlibandfileserver/fileserver/sfat/sl_scan.cpp#L599
			adate_fat = DecodeFATDate(struct.unpack('<H', self.clusters_buf[pos + 18 : pos + 20])[0])

			# This field points to an extended attribute in FAT12/16 volumes. This is not supported.
			if self.is_fat32:
				first_cluster_hi = struct.unpack('<H', self.clusters_buf[pos + 20 : pos + 22])[0]
			else:
				first_cluster_hi = 0

			mtime_fat = DecodeFATTime(struct.unpack('<H', self.clusters_buf[pos + 22 : pos + 24])[0])
			mdate_fat = DecodeFATDate(struct.unpack('<H', self.clusters_buf[pos + 24 : pos + 26])[0])

			first_cluster_lo = struct.unpack('<H', self.clusters_buf[pos + 26 : pos + 28])[0]

			size = struct.unpack('<L', self.clusters_buf[pos + 28 : pos + 32])[0]

			# Convert some of the values.

			if adate_fat is not None:
				atime = adate_fat
			else:
				atime = None

			if mdate_fat is not None and mtime_fat is not None:
				mtime = datetime(mdate_fat.year, mdate_fat.month, mdate_fat.day, mtime_fat.hour, mtime_fat.minute, mtime_fat.second)
			else:
				mtime = None

			if cdate_fat is not None and ctime_fat is not None:
				ctime = datetime(cdate_fat.year, cdate_fat.month, cdate_fat.day, ctime_fat.hour, ctime_fat.minute, ctime_fat.second) + timedelta(milliseconds = ctime_fat_tenth * 10)
			else:
				ctime = None

			first_cluster = (first_cluster_hi << 16) | first_cluster_lo

			if found_null and not is_deleted:
				# The following statement is present in [FATGEN 1.03]:
				#   "If DIR_Name[0] == 0x00, then the directory entry is free (same as for 0xE5),
				#    and there are no allocated directory entries after this one
				#    (all of the DIR_Name[0] bytes in all of the entries after this one are also set to 0).
				#
				#   The special 0 value, rather than the 0xE5 value, indicates to FAT file system driver code
				#   that the rest of the entries in this directory do not need to be examined because they are all free".
				#
				# This is not always the case. While popular implementations zero-out a newly allocated directory cluster (so nothing is found
				# after an empty (null) directory entry), at least one implementation (embedded) simply writes an empty (null) directory entry after
				# the last allocated one (without "wiping" the remaining bytes of a newly allocated directory cluster).
				#
				# This means that remnant directory entries can be present after an empty (null) directory entry. Such entries are likely to come from
				# a "previous" file system (before the format). This is why such entries should be marked as deleted even if they do not have the 0xE5 mark.
				#
				# Also, the Linux driver does not stop listing the directory once an empty (null) directory entry is found.
				# It lists such remnant entries as allocated (when no 0xE5 mark is set). So, the real status is going to be "unknown".
				#
				# The Chkdsk scan will detect such entries and set the 0x00 mark for them (so, the entries become "deleted" as expected).
				# But if we mount such a volume without the Chkdsk scan, filling an empty (null) directory entry with metadata for a newly created file
				# will bring remnant entries back (they will be shown as active files in a directory listing).

				is_deleted = None # The real status is unknown.

			yield FileEntry(is_deleted, is_directory, short_name, short_name_raw_norm, long_name, atime, mtime, ctime, size, attributes, ntbyte, first_cluster, is_encrypted)
			previous_entry_is_file = True

			pos += 32

		if pos == len(self.clusters_buf) and not previous_entry_is_file:
			# The directory buffer does not end with a file entry. There could be an orphan long name.

			if len(long_entities) > 0:
				long_name_partial = BuildLongName(long_entities)
				yield OrphanLongEntry(long_name_partial)

	def __str__(self):
		return 'DirectoryEntries'

class FileSystemParser(object):
	"""This class is used to read and parse a FAT12/16/32 file system (volume)."""

	volume_object = None
	"""A file object for a volume."""

	volume_offset = None
	"""An offset of a volume (in bytes)."""

	volume_size = None
	"""A volume size (in bytes)."""

	bsbpb = None
	"""A BSBPB object for this volume."""

	fat = None
	"""A FAT object for this volume."""

	cluster_size = None
	"""A cluster size for this volume (in bytes)."""

	data_area_offset = None
	"""Offset of data area (in bytes, relative to the first byte of the volume)."""

	fat_type = None
	"""A volume type (12, 16 or 32)."""

	def __init__(self, volume_object, volume_offset, volume_size = None):
		self.volume_object = volume_object
		self.volume_offset = volume_offset
		self.volume_size = volume_size

		if self.volume_size is not None and self.volume_size < 4096:
			raise ValueError('Volume is too small')

		self.volume_object.seek(self.volume_offset)
		bs_buf = self.volume_object.read(512)
		self.bsbpb = BSBPB(bs_buf)

		if IsFileSystem32(self.bsbpb):
			self.fat_type = 32
		elif IsFileSystem16(self.bsbpb):
			self.fat_type = 16
		elif IsFileSystem12(self.bsbpb):
			self.fat_type = 12
		else:
			raise ValueError('Unknown FAT type (not FAT12/16/32)')

		self.cluster_size = self.bsbpb.get_bpb_bytspersec() * self.bsbpb.get_bpb_secperclus()

		offset_in_bytes, size_in_bytes, last_data_cluster_plus_one = self.bsbpb.fat_offset_and_size()
		self.fat = FAT(self.volume_object, self.volume_offset + offset_in_bytes, size_in_bytes, last_data_cluster_plus_one, self.fat_type)

		if self.fat_type == 32:
			self.data_area_offset = (self.bsbpb.get_bpb_rsvdseccnt() + self.bsbpb.get_bpb_numfats() * self.bsbpb.get_bpb_fatsz32()) * self.bsbpb.get_bpb_bytspersec()
		else:
			root_sectors_count = (self.bsbpb.get_bpb_rootentcnt() * 32 + self.bsbpb.get_bpb_bytspersec() - 1) // self.bsbpb.get_bpb_bytspersec()
			self.data_area_offset = (self.bsbpb.get_bpb_rsvdseccnt() + self.bsbpb.get_bpb_numfats() * self.bsbpb.get_bpb_fatsz16() + root_sectors_count) * self.bsbpb.get_bpb_bytspersec()

	def read_chain(self, first_cluster, file_size = None):
		"""Read clusters in a chain described by its first cluster, return them (as raw bytes).
		Bad clusters are filled with null bytes.
		"""

		clusters = self.fat.chain(first_cluster)

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

	def walk(self, encoding = 'ascii', scan_reallocated = False):
		"""Walk over the file system, return tuples (FileEntry and OrphanLongEntry).
		If the 'scan_reallocated' argument is True, also scan reallocated deleted directories.
		"""

		def bufs_match(buf_1, buf_2):
			if buf_1[-96] == 0 or buf_1[-64] == 0 or buf_1[-32] == 0 or buf_2[0] == 0: # The first buffer is not fully filled or the second buffer is invalid.
				return False

			if buf_2[33 : 35] == b'. ': # The second buffer obviously belongs to another directory (it contains the dot-dot entry) or it is invalid (it contains a name with ". ").
				return False

			return True

		def process_buf(buf, parent_path, stack):
			dir_entries = DirectoryEntries(buf, self.fat_type == 32)

			prev_first_cluster = None

			for dir_entry in dir_entries.entries(encoding, False):
				if type(dir_entry) is OrphanLongEntry:
					yield ExpandPath(parent_path, dir_entry)

				elif type(dir_entry) is FileEntry:
					if prev_first_cluster is not None and prev_first_cluster in stack:
						stack.remove(prev_first_cluster)

					if dir_entry.is_directory and dir_entry.short_name not in [ '.', '..' ] and dir_entry.first_cluster != 0:
						if dir_entry.first_cluster in stack:
							# This is a loop, skip this entry.
							continue

						stack.add(dir_entry.first_cluster)
						prev_first_cluster = dir_entry.first_cluster # We will remove this entry from the stack after this iteration.

					# Here, we also report dot and dot-dot entries.
					# Many tools ignore them, but they may contain additional (not seen elsewhere) timestamps!
					# For example, macOS stores timestamps of a directory in its dot entry ("/dir/.").

					yield ExpandPath(parent_path, dir_entry)

					if dir_entry.is_directory and dir_entry.short_name not in [ '.', '..' ]: # Walk over subdirectories.
						if dir_entry.long_name is not None: # Prefer long names over short ones.
							preferred_name = dir_entry.long_name
						else:
							preferred_name = dir_entry.short_name

						is_allocated = self.fat.is_allocated(dir_entry.first_cluster)

						if is_allocated is None:
							# This is an invalid cluster.
							continue

						if (not scan_reallocated) and dir_entry.is_deleted and is_allocated:
							# Do not deal with a deleted directory having its first cluster allocated.
							continue

						try:
							new_buf = self.read_chain(dir_entry.first_cluster)
						except (FileSystemException, ValueError):
							continue

						if len(new_buf) == 0: # This directory is really empty, skip it.
							continue

						if (not scan_reallocated) and dir_entry.is_deleted and new_buf[33 : 35] != b'. ':
							# This is not the first cluster of a deleted directory.
							continue

						if dir_entry.is_deleted and len(self.fat.chain(dir_entry.first_cluster)) == 1:
							# Since FAT chains are lost for deleted files (directories), try to append the next cluster (if it is not allocated).
							# Also, validate that two clusters contain "matching" directory entries.
							# No attempt is made to read more than one "extra" cluster (appending more clusters is just guessing).

							next_cluster = dir_entry.first_cluster + 1
							next_is_allocated = self.fat.is_allocated(next_cluster)

							if next_is_allocated is not None and not next_is_allocated:
								try:
									extra_buf = self.read_chain(next_cluster)
								except (FileSystemException, ValueError):
									pass
								else:
									if bufs_match(new_buf, extra_buf):
										new_buf += extra_buf

						for item in process_buf(new_buf, parent_path + PATH_SEPARATOR + preferred_name, set(stack)):
							yield item


		if self.fat_type == 32:
			curr = self.bsbpb.get_bpb_rootclus()
			buf = self.read_chain(curr)

			stack = set([curr])
		else:
			root_offset = (self.bsbpb.get_bpb_rsvdseccnt() + self.bsbpb.get_bpb_fatsz16() * self.bsbpb.get_bpb_numfats()) * self.bsbpb.get_bpb_bytspersec()
			root_size = self.bsbpb.get_bpb_rootentcnt() * 32

			if root_size == 0:
				raise ValueError('Invalid root directory (zero length)')

			self.volume_object.seek(self.volume_offset + root_offset)
			buf = self.volume_object.read(root_size)

			if len(buf) != root_size:
				raise ValueError('Truncated root directory')

			stack = set()

		for item in process_buf(buf, '', set(stack)): # Pass a new instance of the set ('stack').
			yield item

	def __str__(self):
		return 'FileSystemParser (FAT12/16/32)'
