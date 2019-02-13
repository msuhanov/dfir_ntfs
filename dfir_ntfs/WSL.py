# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with some extended metadata set by the Windows Subsystem for Linux (WSL).

import struct
import datetime

def DecodeUnixtime(TimestampSeconds, TimestampNanoseconds):
	"""Decode the Unixtime timestamp and return the datetime object."""

	return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds = TimestampSeconds) + datetime.timedelta(microseconds = TimestampNanoseconds / 1000)

class LXXATTR(object):
	"""This class is used to access Linux extended attributes stored in the LXXATTR extended attribute."""

	def __init__(self, value):
		self.value = value
		if not self.validate_header():
			raise ValueError('Invalid version and/or format of the LXXATTR header')

	def validate_header(self):
		"""Validate the header of the LXXATTR extended attribute."""

		if len(self.value) < 12:
			return False

		version = struct.unpack('<H', self.value[2 : 4])[0]
		format_ = struct.unpack('<H', self.value[0 : 2])[0]
		if version != 1 or format_ != 0:
			return False

		return True

	def extended_attributes(self):
		"""This method yields (name, value) tuples for each Linux extended attribute."""

		pos_block = 4
		while pos_block < len(self.value):
			next_block_pos_relative_raw = self.value[pos_block : pos_block + 4]
			if len(next_block_pos_relative_raw) != 4:
				break

			next_block_pos_relative = struct.unpack('<L', next_block_pos_relative_raw)[0]
			if next_block_pos_relative > 0:
				block_raw = self.value[pos_block : pos_block + next_block_pos_relative]
			else:
				block_raw = self.value[pos_block : ]

			if len(block_raw) < 9:
				break

			name_length = struct.unpack('B', block_raw[6 : 7])[0]
			if name_length == 0:
				break

			value_length = struct.unpack('<H', block_raw[4 : 6])[0]

			name = block_raw[7 : 7 + name_length]
			value = block_raw[7 + name_length : 7 + name_length + value_length]

			yield (name, value)

			if next_block_pos_relative > 0:
				pos_block += next_block_pos_relative
			else:
				break

class LXATTRB(object):
	"""This class is used to access Linux metadata stored in the LXATTRB extended attribute."""

	def __init__(self, value):
		self.value = value
		if not self.validate_header():
			raise ValueError('Invalid version and/or format of the LXATTRB header')

	def validate_header(self):
		"""Validate the header of the LXATTR extended attribute."""

		if len(self.value) != 56:
			return False

		version = struct.unpack('<H', self.value[2 : 4])[0]
		format_ = struct.unpack('<H', self.value[0 : 2])[0]
		if version != 1 or format_ != 0:
			return False

		return True

	def get_mode(self):
		"""Get and return the mode (as an integer)."""

		return struct.unpack('<L', self.value[4 : 8])[0]

	def get_uid(self):
		"""Get and return the user ID."""

		return struct.unpack('<L', self.value[8 : 12])[0]

	def get_gid(self):
		"""Get and return the group ID."""

		return struct.unpack('<L', self.value[12 : 16])[0]

	def get_rdev(self):
		"""Get and return the device ID (as one integer)."""

		return struct.unpack('<L', self.value[16 : 20])[0]

	def get_atime(self):
		"""Get, decode and return the A (last accessed) timestamp."""

		ns_a = struct.unpack('<L', self.value[20 : 24])[0]
		s_a = struct.unpack('<Q', self.value[32 : 40])[0]

		return DecodeUnixtime(s_a, ns_a)

	def get_mtime(self):
		"""Get, decode and return the M (modified) timestamp."""

		ns_m = struct.unpack('<L', self.value[24 : 28])[0]
		s_m = struct.unpack('<Q', self.value[40 : 48])[0]

		return DecodeUnixtime(s_m, ns_m)

	def get_chtime(self):
		"""Get, decode and return the CH (inode changed) timestamp."""

		ns_ch = struct.unpack('<L', self.value[28 : 32])[0]
		s_ch = struct.unpack('<Q', self.value[48 : 56])[0]

		return DecodeUnixtime(s_ch, ns_ch)

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('WSL metadata:')
		print(' Mode: {}'.format(hex(self.get_mode())))
		print(' UID/GID: {}/{}'.format(self.get_uid(), self.get_gid()))
		print(' Device ID: {}'.format(hex(self.get_rdev())))
		print(' File last accessed: {}'.format(self.get_atime()))
		print(' File modified: {}'.format(self.get_mtime()))
		print(' Inode changed: {}'.format(self.get_chtime()))
