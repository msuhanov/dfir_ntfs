# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with the boot sector.

import struct

class BootSectorException(Exception):
	"""This is a top-level exception for this module."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class BootSector(object):
	"""This class is used to work with an NTFS boot sector."""

	boot_sector_data = None
	"""Data of a boot sector."""

	def __init__(self, boot_sector_buf):
		if len(boot_sector_buf) < 512 or len(boot_sector_buf) % 512 != 0:
			raise BootSectorException('Invalid boot sector size: {} bytes'.format(len(boot_sector_buf)))

		self.boot_sector_data = boot_sector_buf

		if self.get_signature() != b'NTFS    ':
			raise BootSectorException('Invalid signature (not an NTFS boot sector)')

	def get_signature(self):
		"""Get and return the volume signature (the OEM name)."""

		return self.boot_sector_data[3 : 11]

	def get_bytes_per_sector(self):
		"""Get and return the sector size in bytes."""

		if struct.unpack('B', self.boot_sector_data[11 : 12])[0] != 0:
			raise BootSectorException('Invalid sector size')

		bytes_per_sector_base = struct.unpack('B', self.boot_sector_data[12 : 13])[0]
		bytes_per_sector_real = bytes_per_sector_base * 256

		if bytes_per_sector_real < 512 or bytes_per_sector_real % 512 != 0:
			raise BootSectorException('Invalid sector size: {} bytes'.format(bytes_per_sector_real))

		return bytes_per_sector_real

	def get_sectors_per_cluster(self):
		"""Get and return the cluster size in sectors."""

		sectors_per_cluster_base = struct.unpack('B', self.boot_sector_data[13 : 14])[0]
		if sectors_per_cluster_base == 0:
			raise BootSectorException('Invalid cluster size (zero)')

		if sectors_per_cluster_base <= 0x80: # Although 0x80 is a signed value, it's used as an unsigned one.
			sectors_per_cluster_real =  sectors_per_cluster_base
		else:
			sectors_per_cluster_base = struct.unpack('b', self.boot_sector_data[13 : 14])[0] # Read this again as a signed value.
			sectors_per_cluster_real = 1 << abs(sectors_per_cluster_base)

		return sectors_per_cluster_real

	def get_total_number_of_sectors(self):
		"""Get and return the total number of sectors."""

		total_number_of_sectors = struct.unpack('<Q', self.boot_sector_data[40 : 48])[0]
		if total_number_of_sectors == 0:
			raise BootSectorException('Invalid total number of sectors (zero)')

		return total_number_of_sectors

	def get_first_mft_cluster(self):
		"""Get and return the first cluster of the $MFT file."""

		mft_cluster = struct.unpack('<Q', self.boot_sector_data[48 : 56])[0]
		if mft_cluster == 0:
			raise BootSectorException('Invalid $MFT cluster (zero)')

		return mft_cluster

	def get_first_mftmirr_cluster(self):
		"""Get and return the first cluster of the $MFTMirr file."""

		mft_cluster = struct.unpack('<Q', self.boot_sector_data[56 : 64])[0]
		if mft_cluster == 0:
			raise BootSectorException('Invalid $MFTMirr cluster (zero)')

		return mft_cluster

	def get_file_record_segment_size(self):
		"""Get and return the file record segment (FRS) size (in bytes)."""

		frs_size_base = struct.unpack('b', self.boot_sector_data[64 : 65])[0]
		if frs_size_base >= 0:
			frs_size_real = frs_size_base * self.get_sectors_per_cluster() * self.get_bytes_per_sector()
		else:
			frs_size_real = 1 << abs(frs_size_base)

		if frs_size_real == 0:
			raise BootSectorException('Invalid file record segment size (zero)')

		return frs_size_real

	def get_index_record_size(self):
		"""Get and return the index record size (in bytes)."""

		idx_size_base = struct.unpack('b', self.boot_sector_data[68 : 69])[0]
		if idx_size_base >= 0:
			idx_size_real = idx_size_base * self.get_sectors_per_cluster() * self.get_bytes_per_sector()
		else:
			idx_size_real = 1 << abs(idx_size_base)

		if idx_size_real == 0:
			raise BootSectorException('Invalid index record size (zero)')

		return idx_size_real

	def get_serial_number(self):
		"""Get and return the volume serial number (as an integer)."""

		return struct.unpack('<Q', self.boot_sector_data[72 : 80])[0]

	def is_boot_code_present(self):
		"""Check if boot code is present. This is done by checking the first instruction and the boot signature."""

		return struct.unpack('<H', self.boot_sector_data[0 : 2])[0] != 0 and struct.unpack('<H', self.boot_sector_data[510 : 512])[0] == 0xAA55

	def __str__(self):
		return 'BootSector'
