# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with partition tables.

import struct
import binascii
import uuid
from collections import namedtuple

# Standard partition types:
EFI_SYSTEM_PARTITION_GUID = uuid.UUID('{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}')
EFI_LEGACY_MBR_PARTITION_GUID = uuid.UUID('{024DEE41-33E7-11D3-9D69-0008C781F39F}')

# Standard attribute flags:
EFI_PARTITION_REQUIRED = 1 # This partition is required by the platform.
EFI_PARTITION_NO_BLOCK_IO = 2 # This partition does not support the block I/O protocol.
EFI_PARTITION_LEGACY_BOOTABLE = 4 # This partition is bootable by legacy BIOS firmware.

# Boot indicator values:
MBR_PARTITION_BOOTABLE = 0x80 # This partition is bootable.

# OS types:
MBR_UEFI_SYSTEM_PARTITION = 0xEF
MBR_GPT_PROTECTIVE = 0xEE

SUPPORTED_EXTENDED_PARTITION_TYPES = [ 0x5, 0xF, 0x85 ]

# Location codes for the GPT header found:
# - 0: this is a primary header;
# - 1: this is a backup header found in the last sector;
# - 2: this is a backup header as defined by a corrupt primary header (usually, in the last sector).

GPTHeader = namedtuple('GPTHeader', [ 'location', 'first_usable_lba', 'last_usable_lba', 'disk_guid', 'partition_entry_lba', 'number_of_partition_entries', 'size_of_partition_entry', 'partition_entry_crc32' ])
GPTPartition = namedtuple('GPTPartition', [ 'partition_type_guid', 'unique_partition_guid', 'starting_lba', 'ending_lba', 'attributes', 'partition_name' ])

StandardMBR = namedtuple('StandardMBR', [ 'is_boot_code_present', 'disk_signature' ])
MBRPartition = namedtuple('MBRPartition', [ 'boot_indicator', 'starting_chs', 'os_type', 'ending_chs', 'starting_lba', 'size_in_lba' ])
EBRPartition = namedtuple('EBRPartition', [ 'boot_indicator', 'os_type', 'starting_lba', 'size_in_lba' ])

class GPT(object):
	"""This class is used to work with a GUID partition table (GPT)."""

	volume_object = None
	"""A file object for a volume."""

	volume_size = None
	"""A volume size (in bytes)."""

	sector_size = None
	"""A sector size (in bytes)."""

	backup_lba = None
	"""An alternate LBA for the GPT header (if found)."""

	def __init__(self, volume_object, sector_size):
		self.volume_object = volume_object

		if sector_size < 512 or sector_size % 512 != 0:
			raise ValueError('Invalid sector size: {}'.format(sector_size))

		self.sector_size = sector_size

		self.volume_object.seek(0, 2)
		self.volume_size = self.volume_object.tell()
		self.volume_object.seek(0)

		if self.volume_size < 3 * self.sector_size + 2 * 16384: # Three sectors (one for a protective MBR, two for a GPT header and its backup) plus two copies of the smallest partition table array.
			raise ValueError('Invalid volume size (too small): {}'.format(self.volume_size))

	def read_gpt_header_internal(self, read_backup = False, backup_lba = None):
		"""Read, validate and return the GPT header as a named tuple (GPTHeader). This method is used internally."""

		if not read_backup: # Try the second LBA.
			header_offset = self.sector_size
			location = 0
		else:
			if backup_lba is None: # Try the last LBA.
				header_offset = self.volume_size - self.sector_size
				location = 1
			else: # Try the specified alternate LBA.
				header_offset = backup_lba * self.sector_size
				location = 2

		if self.volume_object.seek(header_offset) != header_offset:
			raise ValueError('Cannot seek to the GPT header')

		buf = self.volume_object.read(self.sector_size)
		if len(buf) != self.sector_size:
			raise ValueError('Cannot read the GPT header')

		signature, revision, header_size, header_crc32, reserved, my_lba, alternate_lba, first_usable_lba, last_usable_lba, disk_guid_raw, partition_entry_lba, number_of_partition_entries, size_of_partition_entry, partition_entry_crc32 = struct.unpack('<8sLLLLQQQQ16sQLLL', buf[ : 92])

		if signature != b'EFI PART':
			raise ValueError('Invalid signature: {}'.format(signature))

		self.backup_lba = alternate_lba

		if revision == 0:
			raise ValueError('Invalid revision: {}'.format(revision))

		if header_size < 92 or header_size > self.sector_size:
			raise ValueError('Invalid header size: {}'.format(header_size))

		# Prepare for the checksum calculation.
		buf = bytearray(buf[ : header_size])
		buf[16] = 0
		buf[17] = 0
		buf[18] = 0
		buf[19] = 0

		header_crc32_calculated = binascii.crc32(buf)
		if header_crc32_calculated != header_crc32:
			raise ValueError('Invalid header checksum: {} != {}'.format(header_crc32_calculated, header_crc32))

		if my_lba * self.sector_size != header_offset:
			raise ValueError('Invalid LBA of the GPT header: {}'.format(my_lba))

		if my_lba == alternate_lba or alternate_lba == 0:
			raise ValueError('Invalid LBA of the alternate GPT header: {}'.format(alternate_lba))

		# We do not perform further checks on the alternate LBA.
		# This field can point to a sector in the middle of the drive (for example, when an image was restored to a larger drive).

		if first_usable_lba < (2 * self.sector_size + 16384) // self.sector_size:
			raise ValueError('Invalid first usable LBA: {}'.format(first_usable_lba))

		if partition_entry_lba <= 1 or partition_entry_lba * self.sector_size >= self.volume_size - self.sector_size:
			raise ValueError('Invalid partition entry LBA: {}'.format(partition_entry_lba))

		if size_of_partition_entry < 128 or size_of_partition_entry % 128 != 0:
			raise ValueError('Invalid partition entry size: {}'.format(size_of_partition_entry))

		disk_guid = uuid.UUID(bytes_le = disk_guid_raw)

		# Read and validate the partition entry array (but do not use it).
		if self.volume_object.seek(partition_entry_lba * self.sector_size) != partition_entry_lba * self.sector_size:
			raise ValueError('Cannot seek to the GPT partition entry array')

		buf = self.volume_object.read(number_of_partition_entries * size_of_partition_entry)
		if len(buf) != number_of_partition_entries * size_of_partition_entry:
			raise ValueError('Cannot read the GPT partition entry array')

		partition_entry_crc32_calculated = binascii.crc32(buf)
		if partition_entry_crc32_calculated != partition_entry_crc32:
			raise ValueError('Invalid partition entry array checksum: {} != {}'.format(partition_entry_crc32_calculated, partition_entry_crc32))

		return GPTHeader(location, first_usable_lba, last_usable_lba, disk_guid, partition_entry_lba, number_of_partition_entries, size_of_partition_entry, partition_entry_crc32)

	def read_gpt_header(self):
		"""Read, validate and return the GPT header as a named tuple (GPTHeader)."""

		# Try the primary GPT header.
		try:
			return self.read_gpt_header_internal(False, None)
		except (ValueError, OverflowError):
			if self.backup_lba is not None:
				# Try the backup GPT header (in the specified location, if found).
				try:
					return self.read_gpt_header_internal(True, self.backup_lba)
				except (ValueError, OverflowError):
					# Try the backup GPT header (in the last LBA).
					return self.read_gpt_header_internal(True, None)
			else:
				# Try the backup GPT header (in the last LBA).
				return self.read_gpt_header_internal(True, None)

	def read_gpt_partitions(self, partition_entry_lba, number_of_partition_entries, size_of_partition_entry, partition_entry_crc32):
		"""Read, validate and return the GPT partitions (as a list of GPTPartition named tuples)."""

		if number_of_partition_entries == 0:
			return []

		if partition_entry_lba <= 1 or partition_entry_lba * self.sector_size >= self.volume_size - self.sector_size:
			raise ValueError('Invalid partition entry LBA: {}'.format(partition_entry_lba))

		if size_of_partition_entry < 128 or size_of_partition_entry % 128 != 0:
			raise ValueError('Invalid partition entry size: {}'.format(size_of_partition_entry))

		if self.volume_object.seek(partition_entry_lba * self.sector_size) != partition_entry_lba * self.sector_size:
			raise ValueError('Cannot seek to the GPT partition entry array')

		buf = self.volume_object.read(number_of_partition_entries * size_of_partition_entry)
		if len(buf) != number_of_partition_entries * size_of_partition_entry:
			raise ValueError('Cannot read the GPT partition entry array')

		partition_entry_crc32_calculated = binascii.crc32(buf)
		if partition_entry_crc32_calculated != partition_entry_crc32:
			raise ValueError('Invalid partition entry array checksum: {} != {}'.format(partition_entry_crc32_calculated, partition_entry_crc32))

		results = []

		i = 0
		while i < number_of_partition_entries:
			buf_part = buf[i * size_of_partition_entry : i * size_of_partition_entry + 128]

			partition_type_guid_raw, unique_partition_guid_raw, starting_lba, ending_lba, attributes, partition_name_raw = struct.unpack('<16s16sQQQ72s', buf_part)
			if partition_type_guid_raw == b'\x00' * 16: # This is an unused partition entry.
				i += 1
				continue

			partition_type_guid = uuid.UUID(bytes_le = partition_type_guid_raw)
			unique_partition_guid = uuid.UUID(bytes_le = unique_partition_guid_raw)

			try:
				partition_name = partition_name_raw.decode('utf-16le')
			except UnicodeDecodeError:
				partition_name = ''
			else:
				null_pos = partition_name.find('\x00')
				if null_pos != -1:
					partition_name = partition_name[ : null_pos]

			partition = GPTPartition(partition_type_guid, unique_partition_guid, starting_lba, ending_lba, attributes, partition_name)
			results.append(partition)

			i += 1

		return results

class MBR(object):
	"""This class is used to work with a DOS (MBR) partition table."""

	volume_object = None
	"""A file object for a volume."""

	volume_size = None
	"""A volume size (in bytes)."""

	sector_size = None
	"""A sector size (in bytes)."""

	def __init__(self, volume_object, sector_size):
		self.volume_object = volume_object

		if sector_size < 512 or sector_size % 512 != 0:
			raise ValueError('Invalid sector size: {}'.format(sector_size))

		self.sector_size = sector_size

		self.volume_object.seek(0, 2)
		self.volume_size = self.volume_object.tell()
		self.volume_object.seek(0)

		if self.volume_size < 2 * self.sector_size:
			raise ValueError('Invalid volume size (too small): {}'.format(self.volume_size))

	def read_mbr(self):
		"""Read and return the MBR code and data as a named tuple (StandardMBR)."""

		self.volume_object.seek(0)
		buf = self.volume_object.read(512)

		if len(buf) != 512:
			raise ValueError('Cannot read the MBR code and data')

		if struct.unpack('<H', buf[510 : 512])[0] != 0xAA55:
			raise ValueError('Boot signature not found')

		is_boot_code_present = buf[0] != 0 and buf[1] != 0
		disk_signature = struct.unpack('<L', buf[440 : 444])[0]

		return StandardMBR(is_boot_code_present, disk_signature)

	def read_mbr_partitions(self):
		"""Read and return the MBR partitions (as a list of MBRPartition named tuples)."""

		self.volume_object.seek(0)
		buf = self.volume_object.read(512)

		if len(buf) != 512:
			raise ValueError('Cannot read the MBR code and data')

		results = []

		i = 0
		while i < 4:
			buf_part = buf[446 + i * 16 : 446 + i * 16 + 16]
			boot_indicator, starting_chs, os_type, ending_chs, starting_lba, size_in_lba = struct.unpack('<B3sB3sLL', buf_part)

			if os_type == 0: # This is an unused partition.
				i += 1
				continue

			partition = MBRPartition(boot_indicator, starting_chs, os_type, ending_chs, starting_lba, size_in_lba)
			results.append(partition)

			i += 1

		return results

	def read_ebr_partitions(self):
		"""Read and return the EBR partitions (as a list of EBRPartition named tuples)."""

		def read_ebr(ebr_lba):
			if self.volume_object.seek(ebr_lba * self.sector_size) != ebr_lba * self.sector_size:
				return (None, None)

			buf = self.volume_object.read(512)
			if len(buf) != 512:
				return (None, None)

			if struct.unpack('<H', buf[510 : 512])[0] != 0xAA55:
				return (None, None)

			buf_part = buf[446 : 446 + 16]
			boot_indicator, __, os_type, __, starting_lba_relative, size_in_lba = struct.unpack('<B3sB3sLL', buf_part)

			starting_lba = ebr_lba + starting_lba_relative

			partition = EBRPartition(boot_indicator, os_type, starting_lba, size_in_lba)

			buf_part = buf[446 + 16 : 446 + 16 + 16]
			__, __, __, __, next_ebr_lba_relative, __ = struct.unpack('<B3sB3sLL', buf_part)

			return (partition, next_ebr_lba_relative)

		results = []
		track = set()

		for part in self.read_mbr_partitions():
			if part.os_type not in SUPPORTED_EXTENDED_PARTITION_TYPES:
				continue

			first_ebr_lba = part.starting_lba
			next_ebr_lba_relative = 0

			if first_ebr_lba == 0:
				return []

			while True:
				curr_ebr_lba = first_ebr_lba + next_ebr_lba_relative
				if curr_ebr_lba in track:
					break

				track.add(curr_ebr_lba)

				partition, next_ebr_lba_relative = read_ebr(curr_ebr_lba)

				if partition is not None and partition.os_type != 0:
					results.append(partition)

				if next_ebr_lba_relative is None or next_ebr_lba_relative == 0:
					break

		return results
