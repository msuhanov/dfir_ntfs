# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with shadow copies.

import struct
import uuid
import datetime
from collections import namedtuple
from .Attributes import DecodeFiletime

VSP_DIFF_AREA_FILE_GUID = b'\x6B\x87\x08\x38\x76\xC1\x48\x4E\xB7\xAE\x04\x04\x6E\x6C\xC7\x52' # As raw bytes.

# Shadow block types:
SHADOW_BLOCK_TYPE_UNKNOWN_NAME_1 = 1 # A start block.
SHADOW_BLOCK_TYPE_UNKNOWN_NAME_2 = 2 # A control block.
SHADOW_BLOCK_TYPE_UNKNOWN_NAME_3 = 3 # A diff area table block.
SHADOW_BLOCK_TYPE_UNKNOWN_NAME_4 = 4 # An application information block.
SHADOW_BLOCK_TYPE_UNKNOWN_NAME_5 = 5 # A location description block.
SHADOW_BLOCK_TYPE_UNKNOWN_NAME_6 = 6 # A bitmap block.

# Protection flags:
VSS_PROTECTION_FLAG_UNKNOWN_NAME_1 = 1 # The snapshot protection mode is enabled.

# Item types for a control block:
CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_1 = 1 # An unused (free) item.
CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_2 = 2 # A type 2 item.
CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_3 = 3 # A type 3 item.

CONTROL_BLOCK_ITEM_TYPES_SUPPORTED = [ CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_1, CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_2, CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_3 ]

# Store flags:
STORE_FLAG_UNKNOWN_NAME_1 = 0x1 # The revert bit.
STORE_FLAG_UNKNOWN_2 = 0x2 # ???
STORE_FLAG_UNKNOWN_4 = 0x4 # ???
STORE_FLAG_UNKNOWN_20 = 0x20 # ???
STORE_FLAG_UNKNOWN_NAME_40 = 0x40 # This snapshot is about to be written to a volume.
STORE_FLAG_UNKNOWN_NAME_80 = 0x80 # The copy-on-write cache is enabled.
STORE_FLAG_UNKNOWN_100 = 0x100 # This snapshot is offline (deleted).
STORE_FLAG_UNKNOWN_200 = 0x200 # ???
STORE_FLAG_UNKNOWN_NAME_400 = 0x400 # When unset, data blocks marked in the bitmap (unused blocks) point to original data (instead of being filled with null bytes).

# Diff area table entry flags:
DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_1 = 0x1 # This entry is a forwarder: the 'data_block_offset_in_store' field contains the offset to be resolved using the next store (the forward offset). This entry also affects a subsequent (not necessary the next one) regular entry (from the same store, if any) having its original volume offset equal to the forward offset: the original volume offset of such an entry is replaced with the original volume offset of the forwarder entry (this affects only one regular entry).
DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_2 = 0x2 # This entry is an overlay: this entry has the allocation bitmap set to describe which 512-byte blocks are used in the data block, these 512-byte blocks take precedence over data blocks from entries with this flag unset; this entry should be ignored when a read request is redirected (from another store) to this store.
DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_4 = 0x4 # This entry should be ignored.
DIFF_AREA_TABLE_ENTRY_UNKNOWN_8 = 0x8 # A regular entry with an unknown flag.
DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_10 = 0x10 # A regular entry: a used pre-copy.
DIFF_AREA_TABLE_ENTRY_UNKNOWN_20 = 0x20 # A regular entry with an unknown flag.
DIFF_AREA_TABLE_ENTRY_UNKNOWN_40 = 0x40 # A regular entry with an unknown flag.
DIFF_AREA_TABLE_ENTRY_UNKNOWN_80 = 0x80 # A regular entry with an unknown flag.

ShadowCopyInformation = namedtuple('ShadowCopyInformation', [ 'stack_position', 'timestamp', 'store_guid', 'volume_size' ])
LocationDescriptionItems = namedtuple('LocationDescriptionItems', [ 'volume_offset', 'store_offset', 'size' ])
OnDiskTableEntry = namedtuple('OnDiskTableEntry', [ 'original_volume_offset', 'data_block_offset_in_store', 'data_block_volume_offset', 'flags', 'allocation_bitmap' ])

class ShadowCopyException(Exception):
	"""This is a top-level exception for this module."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class InvalidVolume(Exception):
	"""This is another top-level exception for this module: the volume is invalid (not supported)."""

	def __init__(self, value):
		self._value = value

	def __str__(self):
		return repr(self._value)

class ShadowCopyNotFoundException(ShadowCopyException):
	"""This exception is raised when a shadow copy is not found."""

	pass

class ShadowBlockException(ShadowCopyException):
	"""This exception is raised when a shadow block is invalid."""

	pass

class StartBlockException(ShadowBlockException):
	"""This exception is raised when a start block is invalid."""

	pass

class ShadowCopiesDisabledException(StartBlockException):
	"""This exception is raised when shadow copies are disabled."""

	pass

class ControlBlockException(ShadowBlockException):
	"""This exception is raised when a control block is invalid."""

	pass

class ControlBlockItemException(ControlBlockException):
	"""This exception is raised when a control block item is invalid."""

	pass

class ShadowBlock(object):
	"""This class is used to work with a shadow block."""

	shadow_block_data = None
	"""Data of this shadow block (as raw bytes)."""

	def __init__(self, shadow_block_data):
		self.shadow_block_data = shadow_block_data

		if self.get_diff_area_guid_raw() != VSP_DIFF_AREA_FILE_GUID:
			raise ShadowCopyException('Invalid diff area GUID')

	def get_diff_area_guid_raw(self):
		"""Get and return the diff area GUID (as raw bytes)."""

		return self.shadow_block_data[ : 16]

	def get_diff_area_guid(self):
		""""Get, parse and return the diff area GUID."""

		return uuid.UUID(bytes_le = self.get_diff_area_guid_raw())

	def get_version(self):
		"""Get and return the version number for this shadow block."""

		return struct.unpack('<L', self.shadow_block_data[16 : 20])[0]

	def get_type(self):
		"""Get and return the type of this shadow block."""

		return struct.unpack('<L', self.shadow_block_data[20 : 24])[0]

	def get_offset_1(self):
		"""Get and return the first offset stored in this shadow block (its meaning depends on the type)."""

		return struct.unpack('<Q', self.shadow_block_data[24 : 32])[0]

	def get_offset_2(self):
		"""Get and return the second offset stored in this shadow block (its meaning depends on the type)."""

		return struct.unpack('<Q', self.shadow_block_data[32 : 40])[0]

	def get_offset_3(self):
		"""Get and return the third offset stored in this shadow block (its meaning depends on the type)."""

		return struct.unpack('<Q', self.shadow_block_data[40 : 48])[0]

	def __str__(self):
		return 'ShadowBlock'

class StartBlock(ShadowBlock):
	"""This class is used to work with a start block."""

	volume_start_data = None
	"""The first 8192 bytes of a volume (as raw bytes)."""

	start_block_offset = 7680
	"""An offset of a start block (in bytes)."""

	def __init__(self, volume_start_buf):
		if len(volume_start_buf) != 8192:
			raise StartBlockException('Invalid volume start data size: {} bytes'.format(len(volume_start_buf)))

		self.volume_start_data = volume_start_buf
		if not self.is_supported_volume():
			raise InvalidVolume('No supported file system signature found')

		super(StartBlock, self).__init__(self.volume_start_data[self.start_block_offset : ])

		if self.get_offset_1() != self.start_block_offset:
			raise StartBlockException('Invalid offset #1: {}'.format(self.get_offset_1()))

		if self.get_offset_2() != self.start_block_offset:
			raise StartBlockException('Invalid offset #2: {}'.format(self.get_offset_2()))

		if self.get_offset_3() != 0:
			raise StartBlockException('Invalid offset #3: {}'.format(self.get_offset_3()))

		if self.get_type() != SHADOW_BLOCK_TYPE_UNKNOWN_NAME_1:
			raise StartBlockException('Invalid type: {}'.format(self.get_type()))

	def get_first_control_block_offset(self):
		"""Get and return the offset of the first control block (in bytes; it can be zero, if no control block is present)."""

		offset = struct.unpack('<Q', self.volume_start_data[7728 : 7736])[0]
		if offset > 0 and offset % 0x4000 != 0:
			raise StartBlockException('Invalid diff area offset: {}'.format(offset))

		return offset

	def get_max_diff_area_size(self):
		"""Get and return the maximum diff area size (in bytes)."""

		return struct.unpack('<Q', self.volume_start_data[7736 : 7744])[0]

	def get_volume_guid_raw(self):
		"""Get and return the volume GUID (as raw bytes)."""

		return self.volume_start_data[7744 : 7760]

	def get_volume_guid(self):
		"""Get, parse and return the volume GUID."""

		return uuid.UUID(bytes_le = self.get_volume_guid_raw())

	def get_storage_guid_raw(self):
		"""Get and return the storage GUID (as raw bytes)."""

		return self.volume_start_data[7760 : 7776]

	def get_storage_guid(self):
		"""Get, parse and return the storage GUID."""

		return uuid.UUID(bytes_le = self.get_storage_guid_raw())

	def is_storage_local(self):
		"""Check if the storage area is on the same volume."""

		return self.get_volume_guid_raw() == self.get_storage_guid_raw()

	def get_application_flags(self):
		"""Get and return application flags (as an integer)."""

		return struct.unpack('<Q', self.volume_start_data[7776 : 7784])[0]

	def get_free_space_precopy_percentage(self):
		"""Get and return the percentage for free space precopy."""

		return struct.unpack('<Q', self.volume_start_data[7784 : 7792])[0]

	def get_hot_blocks_precopy_percentage(self):
		"""Get and return the percentage for hot blocks precopy."""

		return struct.unpack('<Q', self.volume_start_data[7792 : 7800])[0]

	def get_hot_blocks_days(self):
		"""Get and return the hot blocks days."""

		return struct.unpack('<L', self.volume_start_data[7800 : 7804])[0]

	def get_protection_flags(self):
		"""Get and return protection flags (as an integer)."""

		return struct.unpack('<L', self.volume_start_data[7804 : 7808])[0]

	def is_supported_volume(self):
		"""Check if the volume contains a supported file system signature (NTFS, ReFS)."""

		signature = self.volume_start_data[3 : 7]
		return signature in [ b'NTFS', b'ReFS' ] # This is a relaxed check.

	def __str__(self):
		return 'StartBlock'

class ControlBlock(ShadowBlock):
	"""This class is used to work with a control block."""

	def __init__(self, control_block_buf):
		if len(control_block_buf) != 0x4000:
			raise ControlBlockException('Invalid control block size: {} bytes'.format(len(control_block_buf)))

		super(ControlBlock, self).__init__(control_block_buf)

		if self.get_type() != SHADOW_BLOCK_TYPE_UNKNOWN_NAME_2:
			raise ControlBlockException('Invalid type: {}'.format(self.get_type()))

		offset_relative = self.get_relative_offset()
		if offset_relative > 0 and offset_relative % 0x4000 != 0:
			raise ControlBlockException('Invalid relative offset: {}'.format(offset_relative))

	def get_relative_offset(self):
		"""Get and return the relative offset (in bytes) of this control block in the control block file."""

		return self.get_offset_1()

	def get_volume_offset(self):
		"""Get and return the volume offset (in bytes) of this control block."""

		return self.get_offset_2()

	def get_next_control_block_volume_offset(self):
		"""Get and return the volume offset (in bytes) of the next control block (zero, if there is no next control block)."""

		return self.get_offset_3()

	def items(self):
		"""This method yields items found in this control block (ControlBlockItem2 and ControlBlockItem3 objects)."""

		offset = 0x80
		while offset < 0x4000:
			item_type_raw = self.shadow_block_data[offset : offset + 4]
			if len(item_type_raw) != 4:
				break

			item_type = struct.unpack('<L', item_type_raw)[0]
			if item_type == 0: # No more entries.
				break

			if item_type not in CONTROL_BLOCK_ITEM_TYPES_SUPPORTED:
				raise ControlBlockException('Invalid item type: {}'.format(item_type))

			if item_type != CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_1:
				item_raw = self.shadow_block_data[offset : offset + 0x80]
				if len(item_raw) != 0x80:
					raise ControlBlockException('Truncated control block item')

				if item_type == CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_2:
					yield ControlBlockItem2(item_raw)
				elif item_type == CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_3:
					yield ControlBlockItem3(item_raw)

			offset += 0x80

	def __str__(self):
		return 'ControlBlock'

class ControlBlockItem2(object):
	"""This class is used to work with a control block item (type 2)."""

	item_raw = None
	"""Data of this item (as raw bytes)."""

	def __init__(self, item_raw):
		self.item_raw = item_raw

		if len(self.item_raw) != 0x80:
			raise ControlBlockItemException('Invalid control block item size')

		if self.get_item_type() != CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_2:
			raise ControlBlockItemException('Invalid control block type')

		if self.get_volume_size() == 0:
			raise ControlBlockItemException('Invalid volume size')

	def get_item_type(self):
		"""Get and return the item type."""

		return struct.unpack('<L', self.item_raw[0 : 4])[0]

	def get_snapshot_priority(self):
		"""Get and return the snapshot priority."""

		return struct.unpack('B', self.item_raw[4 : 5])[0]

	def get_volume_size(self):
		"""Get and return the volume size (in bytes)."""

		return struct.unpack('<Q', self.item_raw[8 : 16])[0]

	def get_store_guid_raw(self):
		"""Get and return the store GUID (as raw bytes)."""

		return self.item_raw[16 : 32]

	def get_store_guid(self):
		"""Get and return the store GUID."""

		return uuid.UUID(bytes_le = self.get_store_guid_raw())

	def get_flags(self):
		"""Get and return store flags (as an integer)."""

		return struct.unpack('<Q', self.item_raw[40 : 48])[0]

	def get_timestamp(self):
		"""Get and return the commit timestamp."""

		timestamp = struct.unpack('<Q', self.item_raw[48 : 56])[0]
		return DecodeFiletime(timestamp)

	def get_stack_position(self):
		"""Get and return the stack position of this store."""

		return struct.unpack('<Q', self.item_raw[32 : 40])[0]

	def get_unknown_56(self):
		return struct.unpack('<H', self.item_raw[56 : 58])[0] # ???

	def __str__(self):
		return 'ControlBlockItem2, store GUID: {}, volume size: {}'.format(self.get_store_guid(), self.get_volume_size())

class ControlBlockItem3(object):
	"""This class is used to work with a control block item (type 3)."""

	item_raw = None
	"""Data of this item (as raw bytes)."""

	def __init__(self, item_raw):
		self.item_raw = item_raw

		if len(self.item_raw) != 0x80:
			raise ControlBlockItemException('Invalid control block item size')

		if self.get_item_type() != CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_3:
			raise ControlBlockItemException('Invalid control block type')

	def get_item_type(self):
		"""Get and return the item type."""

		return struct.unpack('<L', self.item_raw[0 : 4])[0]

	def get_diff_area_block_offset(self):
		"""Get and return the diff area block offset (in bytes)."""

		return struct.unpack('<Q', self.item_raw[8 : 16])[0]

	def get_store_guid_raw(self):
		"""Get and return the store GUID (as raw bytes)."""

		return self.item_raw[16 : 32]

	def get_store_guid(self):
		"""Get and return the store GUID."""

		return uuid.UUID(bytes_le = self.get_store_guid_raw())

	def get_application_information_block_offset(self):
		"""Get and return the application information block offset (in bytes)."""

		return struct.unpack('<Q', self.item_raw[32 : 40])[0]

	def get_location_description_block_offset(self):
		"""Get and return the location description block offset (in bytes)."""

		return struct.unpack('<Q', self.item_raw[40 : 48])[0]

	def get_bitmap_offset(self):
		"""Get and return the bitmap offset (in bytes)."""

		return struct.unpack('<Q', self.item_raw[48 : 56])[0]

	def get_file_reference(self):
		"""Get and return the file reference (of the diff area allocation file)."""

		return struct.unpack('<Q', self.item_raw[56 : 64])[0]

	def get_allocation_size(self):
		"""Get and return the allocation size (in bytes) of the diff area."""

		return struct.unpack('<Q', self.item_raw[64 : 72])[0]

	def get_previous_bitmap_offset(self):
		"""Get and return the the previous bitmap offset (in bytes)."""

		return struct.unpack('<Q', self.item_raw[72 : 80])[0]

	def get_unknown_80(self):
		return struct.unpack('<L', self.item_raw[80 : 84])[0] # ???

	def __str__(self):
		return 'ControlBlockItem3, store GUID: {}'.format(self.get_store_guid())

class ApplicationInformation(ShadowBlock):
	"""This class is used to work with an application information block."""

	def __init__(self, block_data):
		if len(block_data) != 0x4000:
			raise ShadowBlockException('Invalid application information block size: {} bytes'.format(len(block_data)))

		super(ApplicationInformation, self).__init__(block_data)

		if self.get_type() != SHADOW_BLOCK_TYPE_UNKNOWN_NAME_4:
			raise ShadowBlockException('Invalid type: {}'.format(self.get_type()))

		offset = self.get_offset_2()
		if offset == 0 and offset % 0x4000 != 0:
			raise ShadowBlockException('Invalid offset: {}'.format(offset))

	def get_application_information(self):
		"""Get and return application information (as raw bytes)."""

		return self.shadow_block_data[0x80 : ]

	def get_volume_offset(self):
		"""Get and return the volume offset (in bytes) of this block."""

		return self.get_offset_2()

	def __str__(self):
		return 'ApplicationInformation'

class Bitmap(ShadowBlock):
	"""This class is used to work with a bitmap block."""

	def __init__(self, block_data):
		if len(block_data) != 0x4000:
			raise ShadowBlockException('Invalid bitmap block size: {} bytes'.format(len(block_data)))

		super(Bitmap, self).__init__(block_data)

		if self.get_type() != SHADOW_BLOCK_TYPE_UNKNOWN_NAME_6:
			raise ShadowBlockException('Invalid type: {}'.format(self.get_type()))

		offset = self.get_offset_2()
		if offset == 0 and offset % 0x4000 != 0:
			raise ShadowBlockException('Invalid offset: {}'.format(offset))

	def get_bitmap(self):
		"""Get and return a bitmap chunk (as raw bytes)."""

		return self.shadow_block_data[0x80 : ]

	def get_volume_offset(self):
		"""Get and return the volume offset (in bytes) of this block."""

		return self.get_offset_2()

	def get_next_volume_offset(self):
		"""Get and return the volume offset (in bytes) of the next block (zero, if there is no next block)."""

		return self.get_offset_3()

	def __str__(self):
		return 'Bitmap'

class DiffAreaTable(ShadowBlock):
	"""This class is used to work with a diff area table block."""

	def __init__(self, block_data):
		if len(block_data) != 0x4000:
			raise ShadowBlockException('Invalid diff area table block size: {} bytes'.format(len(block_data)))

		super(DiffAreaTable, self).__init__(block_data)

		if self.get_type() != SHADOW_BLOCK_TYPE_UNKNOWN_NAME_3:
			raise ShadowBlockException('Invalid type: {}'.format(self.get_type()))

		offset = self.get_offset_2()
		if offset == 0 and offset % 0x4000 != 0:
			raise ShadowBlockException('Invalid offset: {}'.format(offset))

	def get_diff_area(self):
		"""Get, parse and return diff area table entries (as a list of OnDiskTableEntry objects)."""

		items = []

		curr_offset = 0x80
		while curr_offset + 32 <= len(self.shadow_block_data):
			buf = self.shadow_block_data[curr_offset : curr_offset + 32]
			original_volume_offset, data_block_offset_in_store, data_block_volume_offset, flags, allocation_bitmap = struct.unpack('<QQQLL', buf)

			if original_volume_offset % 0x4000 != 0 or data_block_volume_offset % 0x4000 != 0 or flags & 0xFFFFFF00 != 0:
				raise ShadowBlockException('Invalid item')

			if flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_1 > 0 and flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_2 > 0:
				raise ShadowBlockException('Invalid item flags (both 0x1 and 0x2 are set)')

			if data_block_volume_offset == 0 and flags == 0:
				break

			if flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_4 == 0:
				items.append(OnDiskTableEntry(original_volume_offset, data_block_offset_in_store, data_block_volume_offset, flags, allocation_bitmap))

			curr_offset += 32

		return items

	def get_volume_offset(self):
		"""Get and return the volume offset (in bytes) of this block."""

		return self.get_offset_2()

	def get_next_volume_offset(self):
		"""Get and return the volume offset (in bytes) of the next block (zero, if there is no next block)."""

		return self.get_offset_3()

	def __str__(self):
		return 'DiffAreaTable'

class LocationDescription(ShadowBlock):
	"""This class is used to work with a location description block."""

	def __init__(self, block_data):
		if len(block_data) != 0x4000:
			raise ShadowBlockException('Invalid location description block size: {} bytes'.format(len(block_data)))

		super(LocationDescription, self).__init__(block_data)

		if self.get_type() != SHADOW_BLOCK_TYPE_UNKNOWN_NAME_5:
			raise ShadowBlockException('Invalid type: {}'.format(self.get_type()))

		offset = self.get_offset_2()
		if offset == 0 and offset % 0x4000 != 0:
			raise ShadowBlockException('Invalid offset: {}'.format(offset))

	def get_location_description_items(self):
		"""Get, parse and return location description items (as a list of LocationDescriptionItems objects)."""

		items = []

		curr_offset = 0x80
		while curr_offset + 24 <= len(self.shadow_block_data):
			buf = self.shadow_block_data[curr_offset : curr_offset + 24]
			volume_offset, store_offset, size = struct.unpack('<QQQ', buf)
			if volume_offset == 0:
				break

			if size == 0:
				raise ShadowBlockException('Invalid item size')

			items.append(LocationDescriptionItems(volume_offset, store_offset, size))

			curr_offset += 24

		return items

	def get_volume_offset(self):
		"""Get and return the volume offset (in bytes) of this block."""

		return self.get_offset_2()

	def get_next_volume_offset(self):
		"""Get and return the volume offset (in bytes) of the next block (zero, if there is no next block)."""

		return self.get_offset_3()

	def __str__(self):
		return 'LocationDescription'

class ShadowParser(object):
	"""This class is used to work with shadow copies stored on a volume. This class is used to provide a file-like object for a selected virtual volume."""

	volume_object = None
	"""A file object for a volume."""

	volume_offset = None
	"""An offset of a volume (in bytes)."""

	volume_size = None
	"""A volume size (in bytes)."""

	start_block = None
	"""A start block (StartBlock)."""

	control_blocks = None
	"""A list of ControlBlock objects."""

	current_cbi2 = None
	"""A current ControlBlockItem2 object."""

	current_cbi3 = None
	"""A current ControlBlockItem3 object."""

	current_volume_size = None
	"""A current volume size (in bytes)."""

	current_bitmap = None
	"""A current bitmap (as raw bytes)."""

	current_previous_bitmap = None
	"""A current previous bitmap (as raw bytes)."""

	current_location_description_items = None
	"""A list of current location description items (LocationDescriptionItems objects)."""

	current_application_information = None
	"""Current application information (as raw bytes)."""

	current_diff_area = None
	"""A list of current diff area items (OnDiskTableEntry objects) sorted by original volume offsets."""

	current_diff_area_index = None
	"""An index of current diff area items."""

	current_possible_null_targets = None
	"""A set with volume offsets of possible null targets for forwarder entries (these targets are possible empty blocks)."""

	current_next_parser = None
	"""A ShadowParser object for next store in the stack."""

	current_offset = None
	"""A current offset in an image file."""

	def __init__(self, volume_object, volume_offset = 0, volume_size = None):
		"""Create a ShadowParser object from a file object for a volume.
		The 'volume_offset' argument can be used to specify the volume offset (in bytes).
		The 'volume_size' argument can used used to specify the volume size (in bytes).
		"""

		self.shadow_selected = False

		self.volume_object = volume_object
		self.volume_offset = volume_offset
		self.volume_size = volume_size

		self.volume_object.seek(self.volume_offset)
		start_block_buf = self.volume_object.read(8192)

		try:
			self.start_block = StartBlock(start_block_buf)
		except ShadowCopyException: # Raise this as another exception.
			raise ShadowCopiesDisabledException('Shadow copies are disabled on this volume')

		if not self.start_block.is_storage_local():
			raise NotImplementedError('Only local volume shadow copies are supported')

		self.control_blocks = []

		curr_offset = self.start_block.get_first_control_block_offset()
		while curr_offset != 0:
			self.volume_object.seek(self.volume_offset + curr_offset)
			control_block_buf = self.volume_object.read(0x4000)

			control_block = ControlBlock(control_block_buf)
			if control_block.get_volume_offset() != curr_offset:
				break

			self.control_blocks.append(control_block)

			curr_offset = control_block.get_next_control_block_volume_offset()

	def shadows(self):
		"""This method yields information about each shadow copy (ShadowCopyInformation)."""

		for control_block in self.control_blocks:
			for control_block_item in control_block.items():
				if type(control_block_item) is ControlBlockItem2:
					stack_position = control_block_item.get_stack_position()
					timestamp = control_block_item.get_timestamp()
					store_guid = control_block_item.get_store_guid()
					volume_size = control_block_item.get_volume_size()

					yield ShadowCopyInformation(stack_position, timestamp, store_guid, volume_size)

	def select_shadow(self, store_guid_or_stack_position):
		"""Select a shadow copy by its store GUID or its stack position."""

		store_guid = None
		if type(store_guid_or_stack_position) is uuid.UUID:
			store_guid = store_guid_or_stack_position
		else:
			stack_position = store_guid_or_stack_position

			for control_block in self.control_blocks:
				for control_block_item in control_block.items():
					if type(control_block_item) is ControlBlockItem2 and control_block_item.get_stack_position() == stack_position:
						store_guid = control_block_item.get_store_guid()
						break

		cnt_3 = 0
		cnt_2 = 0
		for control_block in self.control_blocks:
			for control_block_item in control_block.items():
				if type(control_block_item) is ControlBlockItem3 and control_block_item.get_store_guid() == store_guid:
					self.current_cbi3 = control_block_item
					cnt_3 += 1

				if type(control_block_item) is ControlBlockItem2 and control_block_item.get_store_guid() == store_guid:
					self.current_cbi2 = control_block_item
					cnt_2 += 1

		if cnt_3 != cnt_2:
			raise ShadowCopyException('Cannot select a shadow copy (invalid control block items)')

		cnt = cnt_3
		if cnt == 0:
			raise ShadowCopyNotFoundException('Cannot select a shadow copy (not found)')
		elif cnt > 1:
			raise ShadowCopyException('Cannot select a shadow copy (more than one found)')

		# Read the metadata for the shadow copy selected.
		self.current_volume_size = self.current_cbi2.get_volume_size()
		self.current_bitmap = self.read_bitmap()
		self.current_previous_bitmap = self.read_previous_bitmap()
		self.current_location_description_items = self.read_location_description_items()
		self.current_application_information = self.read_application_information()
		self.current_diff_area = self.read_diff_area()

		self.current_diff_area_index = dict()

		item_pos = 0
		for item in self.current_diff_area:
			if item.original_volume_offset not in self.current_diff_area_index.keys():
				self.current_diff_area_index[item.original_volume_offset] = item_pos

			item_pos += 1

		stack_position = self.current_cbi2.get_stack_position()
		self.current_next_parser = ShadowParser(self.volume_object, self.volume_offset, self.volume_size)
		try:
			self.current_next_parser.select_shadow(stack_position + 1)
		except ShadowCopyNotFoundException:
			self.current_next_parser = None

		self.current_possible_null_targets = set()
		for item in self.current_diff_area:
			if item.flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_1 > 0:
				if not self.check_bitmap(item.data_block_offset_in_store):
					continue

				self.current_possible_null_targets.add(item.data_block_offset_in_store)

		self.return_null_blocks = self.current_cbi2.get_flags() & STORE_FLAG_UNKNOWN_NAME_400 > 0

		self.shadow_selected = True
		self.current_offset = 0

	def read_bitmap(self):
		"""Read and return the bitmap (as raw bytes)."""

		bitmap_chunks = []

		volume_size = self.current_cbi2.get_volume_size()
		if volume_size % 0x4000 != 0: # Keep this value aligned.
			volume_size = volume_size + 0x4000 - volume_size % 0x4000

		bits_count = volume_size // 0x4000
		if bits_count % 8 != 0: # Keep this value aligned.
			bits_count = bits_count + 8 - bits_count % 8

		bytes_count = bits_count // 8

		curr_offset = self.current_cbi3.get_bitmap_offset()
		while curr_offset != 0:
			self.volume_object.seek(self.volume_offset + curr_offset)
			bitmap_block_buf = self.volume_object.read(0x4000)

			bitmap_block = Bitmap(bitmap_block_buf)
			if bitmap_block.get_volume_offset() != curr_offset:
				break

			bitmap_chunk = bitmap_block.get_bitmap()
			bitmap_chunks.append(bitmap_chunk)

			curr_offset = bitmap_block.get_next_volume_offset()

		return b''.join(bitmap_chunks)[ : bytes_count]

	def read_previous_bitmap(self):
		"""Read and return the previous bitmap (as raw bytes)."""

		bitmap_chunks = []

		volume_size = self.current_cbi2.get_volume_size()
		if volume_size % 0x4000 != 0: # Keep this value aligned.
			volume_size = volume_size + 0x4000 - volume_size % 0x4000

		bits_count = volume_size // 0x4000
		if bits_count % 8 != 0: # Keep this value aligned.
			bits_count = bits_count + 8 - bits_count % 8

		bytes_count = bits_count // 8

		curr_offset = self.current_cbi3.get_previous_bitmap_offset()
		while curr_offset != 0:
			self.volume_object.seek(self.volume_offset + curr_offset)
			bitmap_block_buf = self.volume_object.read(0x4000)

			bitmap_block = Bitmap(bitmap_block_buf)
			if bitmap_block.get_volume_offset() != curr_offset:
				break

			bitmap_chunk = bitmap_block.get_bitmap()
			bitmap_chunks.append(bitmap_chunk)

			curr_offset = bitmap_block.get_next_volume_offset()

		return b''.join(bitmap_chunks)[ : bytes_count]

	def read_location_description_items(self):
		"""Read, parse and return the location description items (as a list of LocationDescriptionItems objects)."""

		items = []

		curr_offset = self.current_cbi3.get_location_description_block_offset()
		while curr_offset != 0:
			self.volume_object.seek(self.volume_offset + curr_offset)
			location_description_block_buf = self.volume_object.read(0x4000)

			location_description_block = LocationDescription(location_description_block_buf)
			if location_description_block.get_volume_offset() != curr_offset:
				break

			curr_items = location_description_block.get_location_description_items()
			items.extend(curr_items)

			curr_offset = location_description_block.get_next_volume_offset()

		return items

	def read_application_information(self):
		"""Read and return the application information (as raw bytes)."""

		offset = self.current_cbi3.get_application_information_block_offset()
		if offset > 0:
			self.volume_object.seek(self.volume_offset + offset)
			application_information_block_buf = self.volume_object.read(0x4000)

			application_information_block = ApplicationInformation(application_information_block_buf)
			if application_information_block.get_volume_offset() != offset:
				return b''

			return application_information_block.get_application_information()

		return b''

	def read_diff_area(self):
		"""Read, parse and return the diff area table entries (as a list of OnDiskTableEntry objects)."""

		items = []

		forward_context = dict()

		curr_offset = self.current_cbi3.get_diff_area_block_offset()
		while curr_offset != 0:
			self.volume_object.seek(self.volume_offset + curr_offset)
			diff_area_block_buf = self.volume_object.read(0x4000)

			diff_area_block_buf = DiffAreaTable(diff_area_block_buf)
			if diff_area_block_buf.get_volume_offset() != curr_offset:
				break

			curr_items = diff_area_block_buf.get_diff_area()
			for curr_item in curr_items:
				if curr_item.original_volume_offset in forward_context.keys() and curr_item.flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_2 == 0: # Replace the original volume offset.
					new_volume_offset = forward_context[curr_item.original_volume_offset]
					old_volume_offset = curr_item.original_volume_offset

					curr_item = OnDiskTableEntry(new_volume_offset, curr_item.data_block_offset_in_store, curr_item.data_block_volume_offset, curr_item.flags, curr_item.allocation_bitmap)
					del forward_context[old_volume_offset]

				if curr_item.flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_1 > 0:
					if curr_item.original_volume_offset != curr_item.data_block_offset_in_store: # Expand the forward context.
						forward_context[curr_item.data_block_offset_in_store] = curr_item.original_volume_offset
					else: # Delete the regular entry.
						for item_to_delete in items[:]:
							if item_to_delete.flags & (DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_1 | DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_2) != 0:
								continue

							if item_to_delete.original_volume_offset == curr_item.original_volume_offset:
								items.remove(item_to_delete)

				items.append(curr_item)

			curr_offset = diff_area_block_buf.get_next_volume_offset()

		items.sort(key = lambda x: x.original_volume_offset) # This sorting operation must be stable.

		return items

	def check_bitmap(self, offset, check_previous_bitmap = True):
		"""Check if a given offset is set in the bitmap (in the current one and in the previous one, if requested), return True if it is."""

		bit_pos = offset // 0x4000
		byte_pos = bit_pos // 8
		bit_shift = bit_pos % 8

		try:
			result_1 = (self.current_bitmap[byte_pos] >> bit_shift) & 1 > 0
		except IndexError:
			result_1 = False

		if (not check_previous_bitmap) or self.current_previous_bitmap is None:
			return result_1

		try:
			result_2 = (self.current_previous_bitmap[byte_pos] >> bit_shift) & 1 > 0
		except IndexError:
			return result_1

		if result_1 and result_2:
			return True
		else:
			return False

	def translate_exact_offset(self, offset, ignore_overlay_entries = False, do_forward_lookup = False):
		"""Translate a given aligned volume offset of a data block to a list of offsets describing the same data block in a shadow copy, this list is then returned.
		The list is empty if a given volume offset is not found. Each offset in the list points to a 512-byte block. The offset can be None for a 512-byte block filled with null bytes.
		If the 'ignore_overlay_entries' argument is True, ignore data from overlays (used internally when switching to the next store from the current one).
		If the 'do_forward_lookup' argument is True, do the forward lookup (used internally).
		"""

		def lookup_in_next_store(offset, do_forward_lookup):
			if self.current_next_parser is None:
				if not self.check_bitmap(offset): # Return the original offsets of data blocks.
					offsets = []

					for i in range(0, 32):
						offsets.append(offset + i * 512)
				elif self.return_null_blocks and not do_forward_lookup: # Return the dummy offsets.
					offsets = [ None ] * 32
				else: # Return the original offsets of data blocks.
					offsets = []

					for i in range(0, 32):
						offsets.append(offset + i * 512)

				return offsets

			return self.current_next_parser.translate_exact_offset(offset, True, do_forward_lookup)

		def can_switch_to_next_store(offset):
			next_parser = self.current_next_parser
			if next_parser is None:
				return 2 # Switch to the original volume (there is no next store).

			while next_parser is not None:
				if offset in next_parser.current_diff_area_index.keys():
					pos = next_parser.current_diff_area_index[offset]

					while True:
						try:
							table_entry = next_parser.current_diff_area[pos]
						except IndexError:
							break

						if table_entry.original_volume_offset != offset:
							break

						if table_entry.flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_2 == 0:
							return 1 # Switch to the next store.

						pos += 1

				next_parser = next_parser.current_next_parser

			return 0 # No switch to the next store.

		if offset % 0x4000 != 0:
			raise ValueError('Invalid offset: {}'.format(offset))

		if self.volume_size is not None and offset >= self.volume_size:
			raise ValueError('Offset too large: {} >= {}'.format(offset, self.volume_size))

		if not self.shadow_selected:
			raise ValueError('No shadow copy selected')

		if offset >= self.current_volume_size and self.volume_size is not None and self.current_volume_size > self.volume_size:
			# If the volume was resized and the original offset is too large for the new size, give up.
			return []

		new_offsets = []

		forwarder_entry_found = False
		regular_entry_found = False
		overlay_entry_found = False

		switch_mode = can_switch_to_next_store(offset)
		bitmap_check_result = self.check_bitmap(offset)

		if offset in self.current_diff_area_index.keys(): # The offset was found.
			pos = self.current_diff_area_index[offset]

			cumulative_allocation_bitmap = 0

			while True:
				try:
					table_entry = self.current_diff_area[pos]
				except IndexError:
					break

				if table_entry.original_volume_offset != offset:
					break

				pos += 1

				new_offset = table_entry.data_block_volume_offset

				if table_entry.flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_1 > 0: # Save the forward offset (if valid), it is used later (a forwarder entry).
					if table_entry.original_volume_offset != table_entry.data_block_offset_in_store:
						forwarder_entry_found = True
						forward_offset = table_entry.data_block_offset_in_store
						continue

				if table_entry.flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_2 > 0: # The data block is used partially (an overlay entry).
					overlay_entry_found = True

					if not ignore_overlay_entries:
						if len(new_offsets) == 0: # Fill the list with offsets.
							if switch_mode == 1: # Use offsets from the next store.
								new_offsets = lookup_in_next_store(offset, False)
							elif not bitmap_check_result: # Use the original offsets.
								for i in range(0, 32):
									new_offsets.append(offset + i * 512)
							else:
								if self.return_null_blocks: # Use the dummy offsets.
									new_offsets = [ None ] * 32
								else: # Use the original offsets.
									for i in range(0, 32):
										new_offsets.append(offset + i * 512)

						cumulative_allocation_bitmap |= table_entry.allocation_bitmap # Extend the cumulative allocation bitmap.

						for i in range(0, 32):
							if (table_entry.allocation_bitmap >> i) & 1 > 0: # Overwrite an existing (used) 512-byte block.
								new_offsets[i] = new_offset + i * 512

					continue

				if table_entry.flags & DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_2 == 0: # The entire data block is used (a regular entry).
					regular_entry_found = True

					if len(new_offsets) == 0: # Use the entire block.
						for i in range(0, 32):
							new_offsets.append(new_offset + i * 512)
					else: # Account for previously seen partially used data blocks (overlays).
						for i in range(0, 32):
							if (cumulative_allocation_bitmap >> i) & 1 == 0: # Overwrite an unused block.
								new_offsets[i] = new_offset + i * 512

		if forwarder_entry_found and not regular_entry_found:
			if overlay_entry_found and not ignore_overlay_entries: # Offsets from the forward lookup should be used partially.
				forward_offsets = lookup_in_next_store(forward_offset, True)
				for i in range(0, 32):
					if (cumulative_allocation_bitmap >> i) & 1 == 0: # Overwrite a block marked as unused.
						new_offsets[i] = forward_offsets[i]
			else: # Offsets from the forward lookup should be used entirely.
				return lookup_in_next_store(forward_offset, True)

		if (not regular_entry_found) and (not do_forward_lookup) and offset in self.current_possible_null_targets and \
		 switch_mode == 0 and self.return_null_blocks: # This is a null target of a forwarder block.
			return [ None ] * 32

		if (not forwarder_entry_found) and (not regular_entry_found) and (not overlay_entry_found) and \
		 bitmap_check_result and switch_mode == 0 and self.return_null_blocks: # This is an unused block.
			return [ None ] * 32

		if len(new_offsets) == 0: # Switch to the next store (or to the original volume).
			return lookup_in_next_store(offset, False)

		return new_offsets

	def read_at_exact_offset(self, offset):
		"""Read a block at a given aligned volume offset."""

		new_offsets = self.translate_exact_offset(offset)
		if len(new_offsets) == 0:
			return b''

		data = b''
		for new_offset in new_offsets:
			if new_offset is None: # An empty block.
				data += b'\x00' * 512

			else: # A block with data.
				self.volume_object.seek(self.volume_offset + new_offset)
				new_data = self.volume_object.read(512)

				data += new_data

				if len(new_data) != 512: # Truncated data.
					break

		return data

	def seek(self, offset, whence = 0):
		"""The seek() method for a virtual volume."""

		if not self.shadow_selected:
			raise ValueError('No shadow copy selected')

		old_offset = self.current_offset

		if whence == 0:
			self.current_offset = offset
		elif whence == 1:
			self.current_offset += offset
		elif whence == 2:
			volume_size = self.current_volume_size
			if self.volume_size is not None and volume_size > self.volume_size:
				volume_size = self.volume_size

			self.current_offset = volume_size + offset
		else:
			raise ValueError('Invalid whence')

		if self.current_offset < 0:
			self.current_offset = old_offset # Restore the old offset.
			raise ValueError('Negative seek value')

		return self.current_offset

	def tell(self):
		"""The tell() method for a virtual volume."""

		if not self.shadow_selected:
			raise ValueError('No shadow copy selected')

		return self.current_offset

	def read(self, size = None):
		"""The read() method for a virtual volume."""

		if not self.shadow_selected:
			raise ValueError('No shadow copy selected')

		volume_size = self.current_volume_size
		if self.volume_size is not None and volume_size > self.volume_size:
			volume_size = self.volume_size

		if size is None or size < 0:
			size = volume_size - self.current_offset

		if size <= 0 or self.current_offset >= volume_size: # Nothing to read.
			return b''

		block_offset = self.current_offset // 0x4000 * 0x4000
		offset_in_block = self.current_offset % 0x4000

		data = self.read_at_exact_offset(block_offset)[offset_in_block : offset_in_block + size]
		self.current_offset += len(data)

		bytes_left = size - len(data)
		while bytes_left > 0:
			if self.current_offset >= volume_size:
				break

			block_offset = self.current_offset // 0x4000 * 0x4000
			offset_in_block = self.current_offset % 0x4000

			new_data = self.read_at_exact_offset(block_offset)[offset_in_block : offset_in_block + bytes_left]
			self.current_offset += len(new_data)

			data += new_data
			bytes_left = size - len(data)

			if len(new_data) != 0x4000:
				break

		return data

	def close(self):
		"""The close() method for a virtual volume. This method does nothing."""

		if not self.shadow_selected:
			raise ValueError('No shadow copy selected')

		pass

	def __str__(self):
		return 'ShadowParser'
