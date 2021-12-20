# coding: utf-8

# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov

import pytest
import os
import hashlib
import datetime
import re
import io
import gzip
import tarfile
import pickle
from dfir_ntfs import MFT, WSL, USN, Attributes, LogFile, BootSector, ShadowCopy, PartitionTable, MoveTable
from dfir_ntfs.addons import FAT

TEST_DATA_DIR = 'test_data'

LXATTRB_WSL_1 = os.path.join(TEST_DATA_DIR, 'lxattrb_wsl_1.bin')
LXATTRB_WSL_2 = os.path.join(TEST_DATA_DIR, 'lxattrb_wsl_2.bin')

LXXATTR_WSL_1 = os.path.join(TEST_DATA_DIR, 'lxxattr_wsl_1.bin')
EA_WSL_1 = os.path.join(TEST_DATA_DIR, 'ea-1.bin')
EA_WSL_2 = os.path.join(TEST_DATA_DIR, 'ea-2.bin')
FRS_EA_WSL = os.path.join(TEST_DATA_DIR, 'frs-81151.bin')
FRS_RP = os.path.join(TEST_DATA_DIR, 'rp.bin')
FRS_EA = os.path.join(TEST_DATA_DIR, 'frs_ea.bin')

ATTR_SI = os.path.join(TEST_DATA_DIR, 'standard_information.bin')
ATTR_FN = os.path.join(TEST_DATA_DIR, 'file_name.bin')
ATTR_OBJID = os.path.join(TEST_DATA_DIR, 'object_id.bin')
FRS = os.path.join(TEST_DATA_DIR, 'frs.bin')

MFT_UNICODE = os.path.join(TEST_DATA_DIR, 'unicode.mft')
MFT_UNICODE_PARSED = os.path.join(TEST_DATA_DIR, 'unicode.fls')

MFT_NHC = os.path.join(TEST_DATA_DIR, 'nist-hacking-case.mft')
MFT_NHC_PARSED = os.path.join(TEST_DATA_DIR, 'nist-hacking-case.fls')

MFT_4K = os.path.join(TEST_DATA_DIR, '4k-large.mft')
MFT_4K_PARSED = os.path.join(TEST_DATA_DIR, '4k-large.fls')

MFT_ORPHAN = os.path.join(TEST_DATA_DIR, 'orphan.mft')
MFT_ORPHAN_PARSED = os.path.join(TEST_DATA_DIR, 'orphan.fls')

MFT_ALLOCATED_TEST_LIST = [ (MFT_UNICODE, MFT_UNICODE_PARSED), (MFT_4K, MFT_4K_PARSED), (MFT_ORPHAN, MFT_ORPHAN_PARSED), (MFT_NHC, MFT_NHC_PARSED) ]

MFT_COMPRESSED_SPARSE = os.path.join(TEST_DATA_DIR, 'compressed_sparse.mft')
MFT_DIFFERENT_LA = os.path.join(TEST_DATA_DIR, 'different_la.mft')
MFT_DELETED = os.path.join(TEST_DATA_DIR, 'deleted.mft')
MFT_SLACK = os.path.join(TEST_DATA_DIR, 'slack.mft')
MFT_SLACK_2 = os.path.join(TEST_DATA_DIR, 'slack-2.mft')

MFT_MIRR = os.path.join(TEST_DATA_DIR, 'boot.mftmirr')
MFT_MIRR_4K = os.path.join(TEST_DATA_DIR, '4k-large.mftmirr')

MFT_MAPPING_PAIRS_1 = os.path.join(TEST_DATA_DIR, 'mapping_pairs_1.mft')
MFT_MAPPING_PAIRS_2 = os.path.join(TEST_DATA_DIR, 'mapping_pairs_2.mft')
MFT_MAPPING_PAIRS_TEST_LIST = [ MFT_MAPPING_PAIRS_1, MFT_MAPPING_PAIRS_2, MFT_UNICODE, MFT_4K, MFT_ORPHAN, MFT_NHC, MFT_MIRR, MFT_MIRR_4K, MFT_COMPRESSED_SPARSE, MFT_DIFFERENT_LA, MFT_DELETED, MFT_SLACK ]

USN_1 = os.path.join(TEST_DATA_DIR, 'usn_1170953448.bin')
USN_2 = os.path.join(TEST_DATA_DIR, 'usn_1170990440.bin')
USN_3 = os.path.join(TEST_DATA_DIR, 'usn_1170989584.bin')
USN_4 = os.path.join(TEST_DATA_DIR, 'usn_1170955904.bin')

USNJOURNAL_1 = os.path.join(TEST_DATA_DIR, 'usnjrnlj.bin')
USNJOURNAL_1_PARSED = os.path.join(TEST_DATA_DIR, 'usnjrnlj.fsutil.txt')

LOGFILE_RCRD_DAX = os.path.join(TEST_DATA_DIR, 'rcrd_dax.bin')
LOGFILE_7 = os.path.join(TEST_DATA_DIR, 'LogFile_7.bin')
LOGFILE_10 = os.path.join(TEST_DATA_DIR, 'LogFile_10.bin')
LOGFILE_10_DG = os.path.join(TEST_DATA_DIR, 'LogFile_10_downgraded.bin')
LOGFILE_10_4K = os.path.join(TEST_DATA_DIR, 'LogFile_10_large.bin')
LOGFILE_empty = os.path.join(TEST_DATA_DIR, 'LogFile_empty.bin')

BOOT_4K = os.path.join(TEST_DATA_DIR, '4k.boot')
BOOT_64K = os.path.join(TEST_DATA_DIR, '64k.boot')
BOOT_128K = os.path.join(TEST_DATA_DIR, '128k.boot')
BOOT_4Kn = os.path.join(TEST_DATA_DIR, '4kn.boot')
BOOT_512 = os.path.join(TEST_DATA_DIR, '512.boot')
BOOT_NOBOOTCODE = os.path.join(TEST_DATA_DIR, 'nobootcode.boot')

NTFS_FILE_4k = os.path.join(TEST_DATA_DIR, 'file_4k.bin')
NTFS_FRAGMENTED_MFT = os.path.join(TEST_DATA_DIR, 'ntfs_frag_mft.bin')
NTFS_EXTREMELY_FRAGMENTED_MFT = os.path.join(TEST_DATA_DIR, 'ntfs_extremely_fragmented_mft.raw') # This file is too large to be included into the repository.
NTFS_EXTREMELY_FRAGMENTED_MFT_INDX_DATA_RUNS = os.path.join(TEST_DATA_DIR, 'data_runs.pickle')
NTFS_INDEX_GZ = os.path.join(TEST_DATA_DIR, 'ntfs_index.raw.gz')

VOLUME_START_VSS_1 = os.path.join(TEST_DATA_DIR, 'volume_start.bin')
VOLUME_START_VSS_2 = os.path.join(TEST_DATA_DIR, 'volume_start_2.bin')
VOLUME_START_VSS_3 = os.path.join(TEST_DATA_DIR, 'volume_start_3.bin')
VOLUME_START_VSS_4 = os.path.join(TEST_DATA_DIR, 'volume_start_nosc_2003.bin')
VOLUME_START_VSS_5 = os.path.join(TEST_DATA_DIR, 'volume_start_nosc_10.bin')

VOLUME_CONTROL_BLOCK_FILE_1 = os.path.join(TEST_DATA_DIR, 'control_block_file.bin')
VOLUME_CONTROL_BLOCK_FILE_2 = os.path.join(TEST_DATA_DIR, 'control_block_file_2.bin')

VOLUME_VSS_10 = os.path.join(TEST_DATA_DIR, 'vss_10.tgz')
VOLUME_VSS_10_HASHES = os.path.join(TEST_DATA_DIR, 'vss_10_hashes.txt')
VOLUME_VSS_10_ALL_HASHES = os.path.join(TEST_DATA_DIR, 'vss_10_all_hashes.txt')
VOLUME_VSS_2003 = os.path.join(TEST_DATA_DIR, 'vss_2003.tgz')
VOLUME_VSS_2003_HASHES = os.path.join(TEST_DATA_DIR, 'vss_2003_hashes.txt')
VOLUME_VSS_2003_ALL_HASHES = os.path.join(TEST_DATA_DIR, 'vss_2003_all_hashes.txt')

VOLUME_VSS_TWO_1 = os.path.join(TEST_DATA_DIR, 'vss_1_vol.tar.gz')
VOLUME_VSS_TWO_2 = os.path.join(TEST_DATA_DIR, 'vss_2_stor.tar.gz')
VOLUME_VSS_TWO_1_BM = os.path.join(TEST_DATA_DIR, 'vss_1_vol_bm.bin')
VOLUME_VSS_TWO_3 = os.path.join(TEST_DATA_DIR, 'vss_3_volstor.tar.gz')

NTFS_LONE_WOLF = os.path.join(TEST_DATA_DIR, 'dc_lonewolf.raw') # This file is too large to be included into the repository. This is a raw image from the 2018 Lone Wolf Scenario.
VOLUME_VSS_LONE_WOLF_ALL_HASHES = os.path.join(TEST_DATA_DIR, 'vss_lw_all_hashes.txt') # This file is too large to be included into the repository.
VOLUME_VSS_LONE_WOLF_OFFSETS = os.path.join(TEST_DATA_DIR, 'vss_lw_offsets.txt')

PT_GPT_3_GZ = os.path.join(TEST_DATA_DIR, 'gpt-512-3p.raw.gz')
PT_GPT_0_GZ = os.path.join(TEST_DATA_DIR, 'gpt-512-0p.raw.gz')

PT_MBR_0 = os.path.join(TEST_DATA_DIR, 'mbr-512-p0.bin')
PT_MBR_1 = os.path.join(TEST_DATA_DIR, 'mbr-512-p1.bin')
PT_MBR_4 = os.path.join(TEST_DATA_DIR, 'mbr-512-p4.bin')
PT_MBR_1_1_4k_GZ = os.path.join(TEST_DATA_DIR, 'mbr-4096-p1e1.bin.gz')
PT_MBR_1_0_4k_GZ = os.path.join(TEST_DATA_DIR, 'mbr-4096-p1e0.bin.gz')
PT_MBR_1_2_GZ_1 = os.path.join(TEST_DATA_DIR, 'mbr-512-p1e2.bin.gz')
PT_MBR_1_2_GZ_2 = os.path.join(TEST_DATA_DIR, 'mbr-512-p1e2_2.bin.gz')
PT_MBR_WIN = os.path.join(TEST_DATA_DIR, 'mbr-win-512.raw.tgz')

FCB = os.path.join(TEST_DATA_DIR, 'fcb.bin')

TRACKING_4Kn = os.path.join(TEST_DATA_DIR, 'tracking_4kn.bin')
TRACKING_512 = os.path.join(TEST_DATA_DIR, 'tracking_3_move_to.bin')
TRACKING_512_LARGE = os.path.join(TEST_DATA_DIR, 'tracking_512_large.log')

FAT_BS = os.path.join(TEST_DATA_DIR, 'fat32_bs.bin')
FAT_BS_DIRTY = os.path.join(TEST_DATA_DIR, 'fat32_bs_dirty.bin')
FAT12_BS = os.path.join(TEST_DATA_DIR, 'fat12_bs.bin')
FAT_FS_LSN = os.path.join(TEST_DATA_DIR, 'fat_lfn_test.raw.gz')
FAT_DIRENT_1 = os.path.join(TEST_DATA_DIR, 'fat32_dirent.bin')
FAT_DIRENT_2 = os.path.join(TEST_DATA_DIR, 'fat32_dirent_2.bin')
FAT_DIRENT_3 = os.path.join(TEST_DATA_DIR, 'fat32_dirent_3.bin')
FAT_DIRENT_ORPHAN = os.path.join(TEST_DATA_DIR, 'fat32_dirent_orphan_lfn.bin')
FAT_DIRENT_VERYLONG = os.path.join(TEST_DATA_DIR, 'fat32_dirent_verylong.bin')
FAT_FULL_TEST = os.path.join(TEST_DATA_DIR, 'fat32_full_test.tgz')
FAT_FULL_TEST_RESULTS = os.path.join(TEST_DATA_DIR, 'fat32_full_test.txt')

def test_lxattrb():
	with open(LXATTRB_WSL_1, 'rb') as f:
		lxattrb_blob = f.read()

	with pytest.raises(ValueError):
		WSL.LXATTRB(lxattrb_blob[:-1])

	with pytest.raises(ValueError):
		WSL.LXATTRB(lxattrb_blob + b'\x00')

	lxattrb = WSL.LXATTRB(lxattrb_blob)
	atime = lxattrb.get_atime()
	mtime = lxattrb.get_mtime()
	chtime = lxattrb.get_chtime()

	assert lxattrb.get_mode() & 0x8000 > 0 and lxattrb.get_uid() == 0 and lxattrb.get_gid() == 0 and lxattrb.get_rdev() == 0
	assert atime.year == 2017 and atime.month == 12 and atime.day == 31 and atime.hour == 23 and atime.minute == 0 and atime.second == 0 and atime.microsecond == 0
	assert mtime.year == 2019 and mtime.month == 1 and mtime.day == 17 and mtime.hour == 20 and mtime.minute == 39 and mtime.second == 21 and mtime.microsecond == 914738
	assert chtime.year == 2019 and chtime.month == 1 and chtime.day == 17 and chtime.hour == 20 and chtime.minute == 40 and chtime.second == 54 and chtime.microsecond == 269339

	with open(LXATTRB_WSL_2, 'rb') as f:
		lxattrb_blob = f.read()

	lxattrb = WSL.LXATTRB(lxattrb_blob)
	atime = lxattrb.get_atime()
	mtime = lxattrb.get_mtime()
	chtime = lxattrb.get_chtime()

	assert lxattrb.get_mode() & 0x8000 > 0 and lxattrb.get_uid() == 1000 and lxattrb.get_gid() == 114 and lxattrb.get_rdev() == 0
	assert atime.year == 2019 and atime.month == 1 and atime.day == 16 and atime.hour == 20 and atime.minute == 12 and atime.second == 22 and atime.microsecond == 6046
	assert mtime.year == 2019 and mtime.month == 1 and mtime.day == 16 and mtime.hour == 20 and mtime.minute == 11 and mtime.second == 28 and mtime.microsecond == 37288
	assert chtime.year == 2019 and chtime.month == 1 and chtime.day == 18 and chtime.hour == 20 and chtime.minute == 13 and chtime.second == 4 and chtime.microsecond == 22041

def test_lxxattr():
	with pytest.raises(ValueError):
		WSL.LXXATTR(b'\x00\x00')

	with open(LXXATTR_WSL_1, 'rb') as f:
		lxxattr_blob = f.read()

	lxxattr = WSL.LXXATTR(lxxattr_blob)

	xattr_list = []
	for name, value in lxxattr.extended_attributes():
		xattr_list.append((name, value))

	xattr_list.remove((b'user.test', b'test_value'))
	xattr_list.remove((b'user.another_test', b'another_value'))
	assert len(xattr_list) == 0

	with open(EA_WSL_1, 'rb') as f:
		ea_blob = f.read()

	ea = Attributes.EA(ea_blob)
	c = 0
	for name, flags, value in ea.data_parsed():
		c += 1

		assert flags == 0

		if name == b'LXATTRB\x00':
			lxattrb = WSL.LXATTRB(value)

			chtime = lxattrb.get_chtime()
			assert chtime.year == 2019 and chtime.month == 1 and chtime.day == 21
		elif name == b'LXXATTR\x00':
			lxxattr = WSL.LXXATTR(value)

			xattr_list = []
			for xname, xvalue in lxxattr.extended_attributes():
				xattr_list.append((xname, xvalue))

			xattr_list.remove((b'user.1', b'11'))
			assert len(xattr_list) == 0
		else:
			assert False

	assert c == 2

	with open(EA_WSL_2, 'rb') as f:
		ea_blob = f.read()

	ea = Attributes.EA(ea_blob)
	c = 0
	for name, flags, value in ea.data_parsed():
		c += 1

		assert flags == 0

		if name == b'LXATTRB\x00':
			lxattrb = WSL.LXATTRB(value)

			chtime = lxattrb.get_chtime()
			assert chtime.year == 2019 and chtime.month == 1 and chtime.day == 21
		elif name == b'LXXATTR\x00':
			lxxattr = WSL.LXXATTR(value)

			xattr_list = []
			for xname, xvalue in lxxattr.extended_attributes():
				xattr_list.append((xname, xvalue))

			xattr_list.remove((b'user.1', b'11'))
			xattr_list.remove((b'user.2', b'22'))
			xattr_list.remove((b'user.3', b'33'))
			assert len(xattr_list) == 0
		else:
			assert False

	assert c == 2

def test_wsl_in_frs():
	with open(FRS_EA_WSL, 'rb') as f:
		frs_raw = f.read()

	frs = MFT.FileRecordSegment(frs_raw)
	for attribute in frs.attributes():
		assert type(attribute) is MFT.AttributeRecordResident

		v = attribute.value_decoded()

		if type(v) is not Attributes.EA:
			continue

		c = 0
		for name, flags, value in v.data_parsed():
			c += 1

			assert flags == 0

			if name == b'LXATTRB\x00':
				lxattrb = WSL.LXATTRB(value)

				mtime = lxattrb.get_mtime()
				assert mtime.year == 2019 and mtime.month == 1 and mtime.day == 21
			elif name == b'LXXATTR\x00':
				lxxattr = WSL.LXXATTR(value)

				xattr_list = []
				for xname, xvalue in lxxattr.extended_attributes():
					xattr_list.append((xname, xvalue))

				xattr_list.remove((b'user.1', b'11'))
				xattr_list.remove((b'user.2', b'22'))
				xattr_list.remove((b'user.3', b'33'))
				xattr_list.remove((b'user.4444', b'attrval'))
				assert len(xattr_list) == 0
			else:
				assert False

		assert c == 2

def test_rp_in_frs():
	with open(FRS_RP, 'rb') as f:
		frs_raw = f.read()

	frs = MFT.FileRecordSegment(frs_raw)
	for attribute in frs.attributes():
		assert type(attribute) is MFT.AttributeRecordResident

		v = attribute.value_decoded()

		if type(v) is not Attributes.ReparsePoint:
			continue

		assert v.is_reparse_tag_microsoft()

		rp_buf = v.get_reparse_buffer()

		md5 = hashlib.md5()
		md5.update(rp_buf)
		assert md5.hexdigest() == 'a8ac63b71e1af29121c6d3c3c438926b'

def test_standard_information():
	with open(ATTR_SI, 'rb') as f:
		si_raw = f.read()

	si = Attributes.StandardInformation(si_raw)
	atime = si.get_atime()
	mtime = si.get_mtime()
	ctime = si.get_ctime()
	etime = si.get_etime()

	assert atime.year == 2004 and atime.month == 8 and atime.day == 26 and atime.hour == 15 and atime.minute == 11 and atime.second == 12 and atime.microsecond == 682956
	assert mtime.year == 2004 and mtime.month == 8 and mtime.day == 20 and mtime.hour == 15 and mtime.minute == 9 and mtime.second == 2 and mtime.microsecond == 792578
	assert ctime.year == 2004 and ctime.month == 8 and ctime.day == 20 and ctime.hour == 15 and ctime.minute == 9 and ctime.second == 2 and ctime.microsecond == 782564
	assert etime.year == 2004 and etime.month == 8 and etime.day == 20 and etime.hour == 15 and etime.minute == 11 and etime.second == 35 and etime.microsecond == 422048

	si = Attributes.StandardInformationPartial(si_raw, 0)
	atime = si.get_atime()
	mtime = si.get_mtime()
	ctime = si.get_ctime()
	etime = si.get_etime()

	assert atime.year == 2004 and atime.month == 8 and atime.day == 26 and atime.hour == 15 and atime.minute == 11 and atime.second == 12 and atime.microsecond == 682956
	assert mtime.year == 2004 and mtime.month == 8 and mtime.day == 20 and mtime.hour == 15 and mtime.minute == 9 and mtime.second == 2 and mtime.microsecond == 792578
	assert ctime.year == 2004 and ctime.month == 8 and ctime.day == 20 and ctime.hour == 15 and ctime.minute == 9 and ctime.second == 2 and ctime.microsecond == 782564
	assert etime.year == 2004 and etime.month == 8 and etime.day == 20 and etime.hour == 15 and etime.minute == 11 and etime.second == 35 and etime.microsecond == 422048

def test_file_name():
	with open(ATTR_FN, 'rb') as f:
		fn_raw = f.read()

	fn = Attributes.FileName(fn_raw)

	assert fn.get_file_name() == 'sseriffr.fon'

	atime = fn.get_atime()
	mtime = fn.get_mtime()
	ctime = fn.get_ctime()
	etime = fn.get_etime()

	assert ctime.year == 2004 and ctime.month == 8 and ctime.day == 19 and ctime.hour == 17 and ctime.minute == 1 and ctime.second == 3 and ctime.microsecond == 331068
	assert mtime.year == 2001 and mtime.month == 8 and mtime.day == 23 and mtime.hour == 18 and mtime.minute == 0 and mtime.second == 0 and mtime.microsecond == 0
	assert atime.year == 2004 and atime.month == 8 and atime.day == 19 and atime.hour == 17 and atime.minute == 1 and atime.second == 3 and atime.microsecond == 341082
	assert etime == atime

def test_object_id():
	with open(ATTR_OBJID, 'rb') as f:
		objid_raw = f.read()

	objid = Attributes.ObjectID(objid_raw)
	gtime = objid.get_timestamp()

	assert gtime.year == 2004 and gtime.month == 8 and gtime.day == 20 and gtime.hour == 15 and gtime.minute == 5 and gtime.second == 9 and gtime.microsecond == 158068
	assert str(objid.get_object_id()) == '53d29f0e-f2ba-11d8-b0f9-0010a4933e09'

	assert len(objid.get_extra_data()) == 0

def test_frs():
	with open(FRS, 'rb') as f:
		frs_raw = f.read()

	frs = MFT.FileRecordSegment(frs_raw)

	assert frs.is_in_use()
	assert frs.get_sequence_number() == 2
	assert frs.get_reference_count() == 1
	assert frs.is_base_file_record_segment()
	assert frs.get_logfile_sequence_number() == 31832129
	assert frs.get_master_file_table_number() == 11072

	i = 0
	for attr in frs.attributes():
		if i == 0:
			assert type(attr.value_decoded()) is Attributes.StandardInformation
		elif i == 1:
			assert type(attr.value_decoded()) is Attributes.AttributeList
			attr_list = attr.value_decoded()
		elif i == 2:
			assert type(attr.value_decoded()) is Attributes.FileName
		elif i == 3:
			assert type(attr.value_decoded()) is Attributes.ObjectID
		else:
			assert False

		i += 1

	assert i == 4

	i = 0
	for attr_entry in attr_list.entries():
		assert attr_entry.attribute_name is None

		if i == 0:
			assert attr_entry.attribute_type_code == 0x10
		elif i == 1:
			assert attr_entry.attribute_type_code == 0x30
		elif i == 2:
			assert attr_entry.attribute_type_code == 0x40
		else:
			assert attr_entry.attribute_type_code == 0x80

		i += 1

	assert i == 6

def test_first_pass():
	f = open(MFT_UNICODE, 'rb')
	mft_1 = MFT.MasterFileTableParser(f)
	assert mft_1.first_pass_done

	mft_2 = MFT.MasterFileTableParser(f, False)
	assert not mft_2.first_pass_done
	mft_2.execute_first_pass()
	assert mft_2.first_pass_done

	f.close()

def test_mft_unicode_file_names():
	f = open(MFT_UNICODE, 'rb')
	mft = MFT.MasterFileTableParser(f)

	cnt = 0
	for fr in mft.file_records():
		paths = mft.build_full_paths(fr)
		assert len(paths) == 0 or len(paths) == 1

		if len(paths) > 0:
			path = paths[0]
			if path == '/Привет' or path == '/Привет/привет.txt':
				cnt += 1

	assert cnt == 2

	f.close()

def test_mft_4k_resident_data():
	f = open(MFT_4K, 'rb')
	mft = MFT.MasterFileTableParser(f)

	cnt = 0
	for fr in mft.file_records():
		if mft.build_full_paths(fr) == [ '/1.txt' ]:
			cnt += 1

			for attr in fr.attributes():
				v = attr.value_decoded()
				if type(v) is Attributes.Data:
					data = v.value

					md5 = hashlib.md5()
					md5.update(data)
					assert md5.hexdigest() == 'a75a25c964f50df4ea9398d8ccf6afbd'

					assert data.replace(b'ABC', b'') == b''

		elif mft.build_full_paths(fr) == [ '/2.txt' ]:
			cnt += 1

			for attr in fr.attributes():
				v = attr.value_decoded()
				if type(v) is Attributes.Data:
					md5 = hashlib.md5()
					md5.update(v.value)
					assert md5.hexdigest() == 'd6fbed685c98416fb7388dad7503811c'

	assert cnt == 2

	f.close()

def test_mft_unicode_volume_name():
	f = open(MFT_ORPHAN, 'rb')
	mft = MFT.MasterFileTableParser(f)

	volume_name = None
	fr_vol = mft.get_file_record_by_number(MFT.FILE_NUMBER_VOLUME)
	for attr in fr_vol.attributes():
		v = attr.value_decoded()
		if type(v) is Attributes.VolumeName:
			volume_name = v.get_name()
			break

	assert volume_name == 'тест-test'

	f.close()

def test_mft_orphan_files():
	f = open(MFT_ORPHAN, 'rb')
	mft = MFT.MasterFileTableParser(f)

	cnt = 0
	orphans_seen = []
	for fr in mft.file_records():
		paths = mft.build_full_paths(fr)
		if len(paths) == 0:
			continue

		assert len(paths) == 1
		path = paths[0]

		if path.startswith('<Orphan>/'):
			cnt += 1
			orphans_seen.append(path)

	assert cnt == 4
	assert sorted(orphans_seen) == [ '<Orphan>/2.txt', '<Orphan>/3.txt', '<Orphan>/4.txt', '<Orphan>/5.txt' ]

	f.close()

def test_mft_allocated_files():

	def compare_against_fls_line(fr, path, fls_line):
		# This function must return False if a file record and its path do not apply to an FLS line.
		# If they do, an assertion error (or another exception) must be raised if something is invalid.
		# If everything is okay, this function must return True.

		fls_entries = fls_line.split('\t')

		file_name_fls = fls_entries[1]
		if '/' + file_name_fls != path and not ('/' + file_name_fls).startswith(path + ':$'): # A file record and its path do not apply to this FLS line.
			return False

		# Run the checks.
		file_type_fls, inode_fls = fls_entries[0].rstrip(':').split(' ')

		if fr.get_flags() & MFT.FILE_FILE_NAME_INDEX_PRESENT > 0:
			assert file_type_fls == 'd/d'
		else:
			assert file_type_fls == 'r/r'

		assert inode_fls.startswith(str(fr.get_master_file_table_number()) + '-')

		mod_time_fls, acc_time_fls, chg_time_fls, cre_time_fls = fls_entries[2 : 6]
		if mod_time_fls.endswith(' (UTC)'):
			use_msk = False
		elif mod_time_fls.endswith(' (MSK)'):
			use_msk = True
		else:
			assert False

		for attr in fr.attributes():
			if type(attr) is MFT.AttributeRecordNonresident:
				continue

			v = attr.value_decoded()
			if type(v) is Attributes.StandardInformation:
				if not use_msk:
					mod_time = v.get_mtime().strftime('%Y-%m-%d %H:%M:%S (UTC)')
				else:
					mod_time = (v.get_mtime() + datetime.timedelta(hours = 3)).strftime('%Y-%m-%d %H:%M:%S (MSK)')

				assert mod_time == mod_time_fls

				if not use_msk:
					acc_time = v.get_atime().strftime('%Y-%m-%d %H:%M:%S (UTC)')
				else:
					acc_time = (v.get_atime() + datetime.timedelta(hours = 3)).strftime('%Y-%m-%d %H:%M:%S (MSK)')

				assert acc_time == acc_time_fls

				if not use_msk:
					chg_time = v.get_etime().strftime('%Y-%m-%d %H:%M:%S (UTC)')
				else:
					chg_time = (v.get_etime() + datetime.timedelta(hours = 3)).strftime('%Y-%m-%d %H:%M:%S (MSK)')

				assert chg_time == chg_time_fls

				if not use_msk:
					cre_time = v.get_ctime().strftime('%Y-%m-%d %H:%M:%S (UTC)')
				else:
					cre_time = (v.get_ctime() + datetime.timedelta(hours = 3)).strftime('%Y-%m-%d %H:%M:%S (MSK)')

				assert cre_time == cre_time_fls

		size_fls, uid_fls, gid_fls = fls_entries[6 : 9]
		assert int(size_fls) >= 0 and int(uid_fls) >= 0 and int(gid_fls) >= 0

		return True


	for mft_filename, mft_parsed_filename in MFT_ALLOCATED_TEST_LIST:
		f = open(mft_filename, 'rb')
		mft = MFT.MasterFileTableParser(f)

		with open(mft_parsed_filename, 'rb') as fls:
			fls_output = fls.read().decode('utf-8').splitlines()

		not_found_list = []
		for fr in mft.file_records(True):
			paths = mft.build_full_paths(fr)
			if len(paths) == 0: # A file with no name, skip it.
				continue

			i_paths = []
			for i_path, i_file_name in mft.build_full_paths(fr, True):
				i_paths.append(i_path)
				assert i_path.endswith('/' + i_file_name.get_file_name())

			assert sorted(paths) == sorted(i_paths)

			for path in paths:
				found = False
				for fls_line in fls_output[:]:
					if compare_against_fls_line(fr, path, fls_line):
						found = True
						fls_output.remove(fls_line)

				if not found:
					not_found_list.append(path)

		assert len(fls_output) == 1 # A virtual directory ("$OrphanFiles") is left.

		not_found_list.remove('/.') # This is not present in FLS lines.
		for path in not_found_list:
			# Check that we did not find short file names only.
			try:
				file_name, file_extension = path.split('/')[-1].split('.')
			except ValueError:
				file_name = path.split('/')[-1]
				assert len(file_name) <= 8 and file_name.upper() == file_name
			else:
				assert len(file_name) <= 8 and file_name.upper() == file_name
				assert len(file_extension) <= 3 and file_extension.upper() == file_extension

		f.close()

def test_file_attributes():
	s = Attributes.ResolveFileAttributes(0x200)
	assert s == 'SPARSE'

	s = Attributes.ResolveFileAttributes(0x201)
	assert s == 'READ_ONLY | SPARSE'

	s = Attributes.ResolveFileAttributes(0x2201)
	assert s == 'READ_ONLY | SPARSE | NOT_CONTENT_INDEXED'

	s = Attributes.ResolveFileAttributes(0x80201)
	assert s == 'READ_ONLY | SPARSE | PINNED'

	s = Attributes.ResolveFileAttributes(0x80000)
	assert s == 'PINNED'

	s = Attributes.ResolveFileAttributes(0x80004)
	assert s == 'SYSTEM | PINNED'

	s = Attributes.ResolveFileAttributes(0)
	assert s == ''

def test_usn_source_codes():
	s = USN.ResolveSourceCodes(4)
	assert s == 'USN_SOURCE_REPLICATION_MANAGEMENT'

	s = USN.ResolveSourceCodes(2)
	assert s == 'USN_SOURCE_AUXILIARY_DATA'

	s = USN.ResolveSourceCodes(1)
	assert s == 'USN_SOURCE_DATA_MANAGEMENT'

	s = USN.ResolveSourceCodes(16)
	assert s == '0x10'

	s = USN.ResolveSourceCodes(17)
	assert s == 'USN_SOURCE_DATA_MANAGEMENT | 0x10'

	s = USN.ResolveSourceCodes(0)
	assert s == ''

def test_usn_reason_codes():
	s = USN.ResolveReasonCodes(0x800)
	assert s == 'USN_REASON_SECURITY_CHANGE'

	s = USN.ResolveReasonCodes(0x801)
	assert s == 'USN_REASON_DATA_OVERWRITE | USN_REASON_SECURITY_CHANGE'

	s = USN.ResolveReasonCodes(0x800)
	assert s == 'USN_REASON_SECURITY_CHANGE'

	s = USN.ResolveReasonCodes(0x01800000)
	assert s == 'USN_REASON_INTEGRITY_CHANGE | 0x1000000'

	s = USN.ResolveReasonCodes(0x03800001)
	assert s == 'USN_REASON_DATA_OVERWRITE | USN_REASON_INTEGRITY_CHANGE | 0x3000000'

	s = USN.ResolveReasonCodes(0x01800001)
	assert s == 'USN_REASON_DATA_OVERWRITE | USN_REASON_INTEGRITY_CHANGE | 0x1000000'

	s = USN.ResolveReasonCodes(0x01000000)
	assert s == '0x1000000'

	s = USN.ResolveReasonCodes(0)
	assert s == ''

def test_usn_records():
	with open(USN_1, 'rb') as f:
		usn_raw = f.read()

	usn = USN.GetUsnRecord(usn_raw)
	assert type(usn) == USN.USN_RECORD_V2_OR_V3
	assert usn.get_major_version() == 2

	assert usn.get_file_name() == 'large_file.txt'
	assert usn.get_usn() == 1170953448
	assert usn.get_file_attributes() == 0x20
	assert Attributes.ResolveFileAttributes(usn.get_file_attributes()) == 'ARCHIVE'
	assert usn.get_reason() == 0x80000001
	assert USN.ResolveReasonCodes(usn.get_reason()) == 'USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE'
	assert usn.get_file_reference_number() == 0x0000000000000000000d000000013252
	assert usn.get_parent_file_reference_number() == 0x000000000000000000060000000009eb
	assert usn.get_source_info() == 0
	assert usn.get_security_id() == 0

	timestamp = usn.get_timestamp()
	assert timestamp.year == 2019 and timestamp.month == 1 and timestamp.day == 21 and timestamp.hour == 22 and timestamp.minute == 36 and timestamp.second == 5 and timestamp.microsecond != 0

	with open(USN_2, 'rb') as f:
		usn_raw = f.read()

	usn = USN.GetUsnRecord(usn_raw)
	assert type(usn) == USN.USN_RECORD_V2_OR_V3
	assert usn.get_major_version() == 2

	assert usn.get_file_name() == 'mpasbase.vdm'
	assert usn.get_usn() == 1170990440
	assert usn.get_file_attributes() == 0x20
	assert Attributes.ResolveFileAttributes(usn.get_file_attributes()) == 'ARCHIVE'
	assert usn.get_reason() == 0x80010800
	assert USN.ResolveReasonCodes(usn.get_reason()) == 'USN_REASON_SECURITY_CHANGE | USN_REASON_HARD_LINK_CHANGE | USN_REASON_CLOSE'
	assert usn.get_file_reference_number() == 0x00000000000000000002000000013424
	assert usn.get_parent_file_reference_number() == 0x000000000000000000010000000006b7
	assert usn.get_source_info() == 0
	assert usn.get_security_id() == 0

	timestamp = usn.get_timestamp()
	assert timestamp.year == 2019 and timestamp.month == 1 and timestamp.day == 21 and timestamp.hour == 22 and timestamp.minute == 41 and timestamp.second == 17 and timestamp.microsecond != 0

	with open(USN_3, 'rb') as f:
		usn_raw = f.read()

	usn = USN.GetUsnRecord(usn_raw)
	assert type(usn) == USN.USN_RECORD_V4
	assert usn.get_major_version() == 4

	assert usn.get_usn() == 1170989584
	assert usn.get_reason() == 0x80000102
	assert USN.ResolveReasonCodes(usn.get_reason()) == 'USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE | USN_REASON_CLOSE'
	assert usn.get_file_reference_number() == 0x00000000000000000004000000013de8
	assert usn.get_parent_file_reference_number() == 0x00000000000000000004000000001076
	assert usn.get_source_info() == 0
	assert usn.get_remaining_extents() == 0
	assert usn.get_number_of_extents() == 1

	c = 0
	for offset, length in usn.extents():
		c += 1
		assert offset == 0
		assert length == 2162688

	assert c == 1

	with open(USN_4, 'rb') as f:
		usn_raw = f.read()

	usn = USN.GetUsnRecord(usn_raw)
	assert type(usn) == USN.USN_RECORD_V4
	assert usn.get_major_version() == 4

	assert usn.get_usn() == 1170955904
	assert usn.get_reason() == 0x80000001
	assert USN.ResolveReasonCodes(usn.get_reason()) == 'USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE'
	assert usn.get_file_reference_number() == 0x000000000000000000020000000051c0
	assert usn.get_parent_file_reference_number() == 0x00000000000000000004000000001066
	assert usn.get_source_info() == 0
	assert usn.get_remaining_extents() == 0
	assert usn.get_number_of_extents() == 2

	c = 0
	for offset, length in usn.extents():
		c += 1
		if c == 1:
			assert offset == 0 and length == 16384
		elif c == 2:
			assert offset == 6242304 and length == 32768

	assert c == 2

def test_usn_journal():
	f = open(USNJOURNAL_1, 'rb')

	journal = USN.ChangeJournalParser(f)

	usn_numbers = []
	for usn_record in journal.usn_records():
		usn_numbers.append(usn_record.get_usn())

	f.close()

	usn_cnt = len(usn_numbers)

	with open(USNJOURNAL_1_PARSED, 'rb') as f:
		fsutil_lines = f.read().decode('utf-8').splitlines()

	for fsutil_line in fsutil_lines:
		match_obj = re.match('^Usn\s+:\s+(\d+)$', fsutil_line)
		if match_obj:
			usn_number = int(match_obj.group(1))
			usn_numbers.remove(usn_number)

	assert sorted(usn_numbers) == [29792, 29880, 29968] # These USN numbers were allocated after the fsutil tool has finished the parsing.

	def test_larger_file(gap_length, expect_success):
		with open(USNJOURNAL_1, 'rb') as f:
			source_bytes = f.read()

		f = io.BytesIO(b'\x00' * gap_length + source_bytes)

		journal = USN.ChangeJournalParser(f)

		c = 0
		for usn_record in journal.usn_records():
			c += 1

		f.close()

		if expect_success:
			assert c == usn_cnt

	for gap_length in [1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 4095, 4096, 4097, 8190, 8191, 8192, 8193, 8194, 8195, 511, 512, 513, 100000000, 4096008]:
		expect_success = gap_length % 8 == 0

		test_larger_file(gap_length, expect_success)

	def test_even_more_larger_file(gap_length_1, gap_length_2):
		with open(USNJOURNAL_1, 'rb') as f:
			source_bytes = f.read()

		f = io.BytesIO(b'\x00' * gap_length_1 + source_bytes + b'\x00' * gap_length_2 + source_bytes)

		journal = USN.ChangeJournalParser(f)

		c = 0
		for usn_record in journal.usn_records():
			c += 1

		f.close()

		if expect_success:
			assert c == usn_cnt * 2

	test_even_more_larger_file(0, 512)
	test_even_more_larger_file(512, 1024)
	test_even_more_larger_file(4096, 4096)
	test_even_more_larger_file(4096, 8192)
	test_even_more_larger_file(4096, 8200)

def test_compressed_sparse():
	f = open(MFT_COMPRESSED_SPARSE, 'rb')

	tested_cnt = 0
	mft = MFT.MasterFileTableParser(f)

	for file_record in mft.file_records():
		paths = mft.build_full_paths(file_record)

		if len(paths) == 0:
			continue

		assert len(paths) == 1
		path = paths[0]

		if path.endswith('/compressed.txt'):
			tested_cnt += 1

			c = 0
			for attr in file_record.attributes():
				if type(attr) is MFT.AttributeRecordResident:
					continue

				c += 1
				assert attr.type_code == 0x80 and attr.name is None and attr.file_size == 22308

			assert c == 1

		elif path.endswith('/sparse'):
			tested_cnt += 1

			c = 0
			for attr in file_record.attributes():
				if type(attr) is MFT.AttributeRecordResident:
					continue

				c += 1
				assert attr.type_code == 0x80 and attr.name is None and attr.file_size == 1048582

			assert c == 1

	assert tested_cnt == 2

	f.close()

def test_different_la():
	f = open(MFT_DIFFERENT_LA, 'rb')

	c_1 = 0
	c_2 = 0

	mft = MFT.MasterFileTableParser(f)
	for file_record in mft.file_records():
		paths = mft.build_full_paths(file_record)

		if len(paths) == 0:
			continue

		assert len(paths) == 1
		path = paths[0]

		if path == '/ts_la/test_la.txt':
			for attr in file_record.attributes():
				attr_value = attr.value_decoded()

				if type(attr_value) is not Attributes.StandardInformation:
					continue

				c_1 += 1
				ts_m_1 = attr_value.get_mtime()
				ts_a_1 = attr_value.get_atime()
				ts_c_1 = attr_value.get_ctime()
				ts_e_1 = attr_value.get_etime()

		elif path == '/ts_la':
			for attr in file_record.attributes():
				attr_value = attr.value_decoded()

				if type(attr_value) is not Attributes.IndexRoot:
					continue

				for index_entry in attr_value.index_entries():
					attr_value = Attributes.FileName(index_entry.get_attribute())

					c_2 += 1
					ts_m_2 = attr_value.get_mtime()
					ts_a_2 = attr_value.get_atime()
					ts_c_2 = attr_value.get_ctime()
					ts_e_2 = attr_value.get_etime()

	assert c_1 == 1 and c_2 == 1
	assert ts_m_1 == ts_m_2 and ts_c_1 == ts_c_2 and ts_e_1 == ts_e_2 and ts_a_1 != ts_a_2
	assert ts_a_2 < ts_a_1

	f.close()

def test_deleted():
	f = open(MFT_DELETED, 'rb')

	found = False

	mft = MFT.MasterFileTableParser(f)
	for file_record in mft.file_records():
		paths = mft.build_full_paths(file_record)

		if len(paths) > 0 and paths[0] == '/1/2/3/4/file.txt' and not file_record.is_in_use():
			found = True

	f.close()

	assert found

def test_ea_sizes():
	f = open(FRS_EA, 'rb')
	frs_raw = f.read()

	frs = MFT.FileRecordSegment(frs_raw)
	for attribute in frs.attributes():
		attribute_value = attribute.value_decoded()
		if type(attribute_value) is Attributes.EA:
			assert len(attribute_value.value) == 160

		if type(attribute_value) is Attributes.EAInformation:
			assert attribute_value.get_packed_ea_size() == 149 and attribute_value.get_unpacked_ea_size() == 160

		elif type(attribute_value) is Attributes.FileName:
			assert attribute_value.get_packed_ea_size() == 149 and attribute_value.get_unpacked_ea_size_difference() == 11

	f.close()

def test_open_file_by_child_frs():
	f = open(MFT_NHC, 'rb')
	mft = MFT.MasterFileTableParser(f)

	for file_number in [8508, 8533, 8535, 8553]:
		file_record = mft.get_file_record_by_number(file_number)
		assert file_record.get_master_file_table_number() == 8508

	with pytest.raises(MFT.MasterFileTableException):
		file_record = mft.get_file_record_by_number(8533, None, False)

	f.close()

def test_logfile_rcrd_dax():
	f = open(LOGFILE_RCRD_DAX, 'rb')

	data = f.read()
	data += b'\x00' * (4096 - len(data))
	data = bytearray(data)

	data_unprotected = LogFile.UnprotectSectors(data)

	data[520] = 255
	with pytest.raises(LogFile.UpdateSequenceArrayException):
		data_unprotected = LogFile.UnprotectSectors(data)

	data[520] = 0
	data_unprotected = LogFile.UnprotectSectors(data)

	f.close()

def test_logfile_11():
	f = open(LOGFILE_7, 'rb')

	restart_page_1 = f.read(4096)
	restart_page_2 = f.read(4096)
	assert restart_page_1 == restart_page_2

	rp = LogFile.RestartPage(restart_page_1)
	assert rp.get_major_version() == 1 and rp.get_minor_version() == 1

	ra = rp.get_restart_area()
	assert ra.get_log_clients() == 1

	c = 0
	for client in ra.clients():
		c += 1
		assert client.get_client_name() == 'NTFS'

		client_restart_lsn = client.get_client_restart_lsn()
		assert client_restart_lsn > 0

	assert c == 1

	lsn_list_f = []
	lsn_list_t = []

	lf = LogFile.LogFileParser(f)

	found_client_restart_lsn = False
	highest_lsn = 0
	for log_record in lf.parse_ntfs_records(False):
		lsn_list_f.append(log_record.lsn)

		if log_record.lsn == client_restart_lsn:
			found_client_restart_lsn = True

		if log_record.lsn > highest_lsn:
			highest_lsn = log_record.lsn

	assert not found_client_restart_lsn
	assert len(lsn_list_f) == len(set(lsn_list_f))
	lsn_set_f = set(lsn_list_f)

	c = 0
	find_me = 'find_me.txt'.encode('utf-16le')

	found_client_restart_lsn = False
	for log_record in lf.parse_ntfs_records(True):
		lsn_list_t.append(log_record.lsn)

		if log_record.lsn == client_restart_lsn:
			found_client_restart_lsn = True

		if type(log_record) is LogFile.NTFSRestartArea:
			assert log_record.get_major_version() == 0 and log_record.get_minor_version() == 0
			assert log_record.get_bytes_per_cluster() == 4096

		elif type(log_record) is LogFile.NTFSLogRecord:
			undo = log_record.get_undo_data()
			redo = log_record.get_undo_data()

			if find_me in undo:
				if log_record.calculate_mft_target_number() is not None:
					assert log_record.calculate_mft_target_number() == 40

				elif log_record.calculate_mft_target_reference_and_name() is not None:
					assert log_record.calculate_mft_target_reference_and_name()[0] & 0xFFFFFFFFFFFF == 5
					assert log_record.calculate_mft_target_reference_and_name()[1] == '$I30'

				else:
					assert False

				c += 1

			if find_me in redo:
				if log_record.calculate_mft_target_number() is not None:
					assert log_record.calculate_mft_target_number() == 40

				elif log_record.calculate_mft_target_reference_and_name() is not None:
					assert log_record.calculate_mft_target_reference_and_name()[0] & 0xFFFFFFFFFFFF == 5
					assert log_record.calculate_mft_target_reference_and_name()[1] == '$I30'

				else:
					assert False

				c += 1

	assert c == 4
	assert found_client_restart_lsn
	assert len(lsn_list_t) == len(set(lsn_list_t))
	lsn_set_t = set(lsn_list_t)

	diff = lsn_set_t - lsn_set_f
	assert len(diff) > 0

	for lsn in diff:
		assert lsn > highest_lsn

	f.close()

def test_logfile_20():
	for log_file in [ LOGFILE_10, LOGFILE_10_DG ]:
		f = open(log_file, 'rb')

		if log_file == LOGFILE_10:
			major_version_expected = 2
			minor_version_expected = 0
		elif log_file == LOGFILE_10_DG:
			major_version_expected = 1
			minor_version_expected = 1
		else:
			assert False

		restart_page_1 = f.read(4096)
		restart_page_2 = f.read(4096)
		assert restart_page_1 != restart_page_2

		rp = LogFile.RestartPage(restart_page_1)
		assert rp.get_major_version() == major_version_expected and rp.get_minor_version() == minor_version_expected

		ra = rp.get_restart_area()
		assert ra.get_log_clients() == 1

		c = 0
		for client in ra.clients():
			c += 1
			assert client.get_client_name() == 'NTFS'

			client_restart_lsn_1 = client.get_client_restart_lsn()
			assert client_restart_lsn_1 > 0

		assert c == 1

		rp = LogFile.RestartPage(restart_page_2)
		assert rp.get_major_version() == major_version_expected and rp.get_minor_version() == minor_version_expected

		ra = rp.get_restart_area()
		assert ra.get_log_clients() == 1

		c = 0
		for client in ra.clients():
			c += 1
			assert client.get_client_name() == 'NTFS'

			client_restart_lsn_2 = client.get_client_restart_lsn()
			assert client_restart_lsn_2 > 0

		assert c == 1

		if client_restart_lsn_1 > client_restart_lsn_2:
			client_restart_lsn = client_restart_lsn_1
		else:
			client_restart_lsn = client_restart_lsn_2

		lsn_list_f = []
		lsn_list_t = []

		lf = LogFile.LogFileParser(f)

		found_client_restart_lsn = False
		highest_lsn = 0
		for log_record in lf.parse_ntfs_records(False):
			lsn_list_f.append(log_record.lsn)

			if log_record.lsn == client_restart_lsn:
				found_client_restart_lsn = True

			if log_record.lsn > highest_lsn:
				highest_lsn = log_record.lsn

		if log_file == LOGFILE_10:
			assert not found_client_restart_lsn
		elif log_file == LOGFILE_10_DG:
			assert found_client_restart_lsn
		else:
			assert False

		assert len(lsn_list_f) == len(set(lsn_list_f))
		lsn_set_f = set(lsn_list_f)

		c = 0
		find_me = 'find_me.txt'.encode('utf-16le')

		found_client_restart_lsn = False
		for log_record in lf.parse_ntfs_records(True):
			lsn_list_t.append(log_record.lsn)

			if log_record.lsn == client_restart_lsn:
				found_client_restart_lsn = True

			if type(log_record) is LogFile.NTFSRestartArea:
				assert log_record.get_major_version() == 1 and log_record.get_minor_version() == 0
				assert log_record.get_bytes_per_cluster() == 4096

			elif type(log_record) is LogFile.NTFSLogRecord:
				undo = log_record.get_undo_data()
				redo = log_record.get_undo_data()

				if find_me in undo:
					if log_record.calculate_mft_target_number() is not None:
						assert log_record.calculate_mft_target_number() == 43

					elif log_record.calculate_mft_target_reference_and_name() is not None:
						assert log_record.calculate_mft_target_reference_and_name()[0] & 0xFFFFFFFFFFFF == 5
						assert log_record.calculate_mft_target_reference_and_name()[1] == '$I30'

					else:
						assert False

					c += 1

				if find_me in redo:
					if log_record.calculate_mft_target_number() is not None:
						assert log_record.calculate_mft_target_number() == 43

					elif log_record.calculate_mft_target_reference_and_name() is not None:
						assert log_record.calculate_mft_target_reference_and_name()[0] & 0xFFFFFFFFFFFF == 5
						assert log_record.calculate_mft_target_reference_and_name()[1] == '$I30'

					else:
						assert False

					c += 1

		assert c == 4
		assert found_client_restart_lsn
		assert len(lsn_list_t) == len(set(lsn_list_t))
		lsn_set_t = set(lsn_list_t)

		diff = lsn_set_t - lsn_set_f

		if log_file == LOGFILE_10:
			assert len(diff) > 0
		elif log_file == LOGFILE_10_DG:
			assert len(diff) == 0
		else:
			assert False

		for lsn in diff:
			assert lsn > highest_lsn

		f.close()

def test_logfile_20_4k():
	f = open(LOGFILE_10_4K, 'rb')

	restart_page_1 = f.read(4096)
	restart_page_2 = f.read(4096)
	assert restart_page_1 != restart_page_2

	rp = LogFile.RestartPage(restart_page_1)
	assert rp.get_major_version() == 2 and rp.get_minor_version() == 0

	ra = rp.get_restart_area()
	assert ra.get_log_clients() == 1

	c = 0
	for client in ra.clients():
		c += 1
		assert client.get_client_name() == 'NTFS'

		client_restart_lsn_1 = client.get_client_restart_lsn()
		assert client_restart_lsn_1 > 0

	assert c == 1

	rp = LogFile.RestartPage(restart_page_2)
	assert rp.get_major_version() == 2 and rp.get_minor_version() == 0

	ra = rp.get_restart_area()
	assert ra.get_log_clients() == 1

	c = 0
	for client in ra.clients():
		c += 1
		assert client.get_client_name() == 'NTFS'

		client_restart_lsn_2 = client.get_client_restart_lsn()
		assert client_restart_lsn_2 > 0

	assert c == 1

	if client_restart_lsn_1 > client_restart_lsn_2:
		client_restart_lsn = client_restart_lsn_1
	else:
		client_restart_lsn = client_restart_lsn_2

	lsn_list_f = []
	lsn_list_t = []

	lf = LogFile.LogFileParser(f)

	found_client_restart_lsn = False
	highest_lsn = 0
	for log_record in lf.parse_ntfs_records(False):
		lsn_list_f.append(log_record.lsn)

		if log_record.lsn == client_restart_lsn:
			found_client_restart_lsn = True

		if log_record.lsn > highest_lsn:
			highest_lsn = log_record.lsn

	assert not found_client_restart_lsn

	assert len(lsn_list_f) == len(set(lsn_list_f))
	lsn_set_f = set(lsn_list_f)

	c = 0
	c_add_to_ir = 0
	c_add_attr = 0
	find_me = 'find_me.txt'.encode('utf-16le')

	found_client_restart_lsn = False
	for log_record in lf.parse_ntfs_records(True):
		lsn_list_t.append(log_record.lsn)

		if log_record.lsn == client_restart_lsn:
			found_client_restart_lsn = True

		if type(log_record) is LogFile.NTFSRestartArea:
			assert log_record.get_major_version() == 1 and log_record.get_minor_version() == 0
			assert log_record.get_bytes_per_cluster() == 4096

		elif type(log_record) is LogFile.NTFSLogRecord:
			undo = log_record.get_undo_data()
			redo = log_record.get_undo_data()

			if find_me in undo:
				if log_record.calculate_mft_target_number() is not None:
					assert log_record.get_target_block_size() == 8

					if log_record.get_undo_operation() == LogFile.AddIndexEntryRoot:
						assert log_record.calculate_mft_target_number() == 5
						c_add_to_ir += 1
					else:
						assert log_record.get_undo_operation() == LogFile.CreateAttribute
						assert log_record.calculate_mft_target_number() == 39
						c_add_attr += 1

				elif log_record.calculate_mft_target_reference_and_name() is not None:
					assert log_record.calculate_mft_target_reference_and_name()[0] & 0xFFFFFFFFFFFF == 5
					assert log_record.calculate_mft_target_reference_and_name()[1] == '$I30'

				else:
					assert False

				c += 1

			if find_me in redo:
				if log_record.calculate_mft_target_number() is not None:
					assert log_record.get_target_block_size() == 8

					if log_record.get_undo_operation() == LogFile.AddIndexEntryRoot:
						assert log_record.calculate_mft_target_number() == 5
						c_add_to_ir += 1
					else:
						assert log_record.get_undo_operation() == LogFile.CreateAttribute
						assert log_record.calculate_mft_target_number() == 39
						c_add_attr += 1

				elif log_record.calculate_mft_target_reference_and_name() is not None:
					assert log_record.calculate_mft_target_reference_and_name()[0] & 0xFFFFFFFFFFFF == 5
					assert log_record.calculate_mft_target_reference_and_name()[1] == '$I30'

				else:
					assert False

				c += 1

	assert c == 4 and c_add_to_ir == 2 and c_add_attr == 2
	assert found_client_restart_lsn
	assert len(lsn_list_t) == len(set(lsn_list_t))
	lsn_set_t = set(lsn_list_t)

	diff = lsn_set_t - lsn_set_f

	assert len(diff) > 0

	for lsn in diff:
		assert lsn > highest_lsn

	f.close()

def test_logfile_empty():
	f = open(LOGFILE_empty, 'rb')

	with pytest.raises(LogFile.EmptyLogFileException):
		lf = LogFile.LogFileParser(f)

	f.close()

def test_mft_mirr():
	f = open(MFT_MIRR, 'rb')

	file_names = [ '$MFT', '$MFTMirr', '$LogFile', '$Volume' ]

	mft = MFT.MasterFileTableParser(f)
	for file_record in mft.file_records():
		for attribute in file_record.attributes():
			if type(attribute) is MFT.AttributeRecordNonresident:
				continue

			value = attribute.value_decoded()
			if type(value) is not Attributes.FileName:
				continue

			assert value.get_file_name() == file_names.pop(0)

	assert len(file_names) == 0
	f.close()

	f = open(MFT_MIRR_4K, 'rb')

	file_names = [ '$MFT', '$MFTMirr', '$LogFile', '$Volume' ]

	mft = MFT.MasterFileTableParser(f)
	for file_record in mft.file_records():
		for attribute in file_record.attributes():
			if type(attribute) is MFT.AttributeRecordNonresident:
				continue

			value = attribute.value_decoded()
			if type(value) is not Attributes.FileName:
				continue

			assert value.get_file_name() == file_names.pop(0)

	assert len(file_names) == 0
	f.close()

def test_mft_slack():
	f = open(MFT_SLACK, 'rb')

	mft = MFT.MasterFileTableParser(f)
	file_record = mft.get_file_record_by_number(39)

	file_names_expected = [ 'New Text Document - Copy (3).txt', 'New Text Document - Copy.txt', 'New Text Document.txt' ]

	c = 0
	for slack in file_record.slack():
		c += 1
		assert len(slack.value) == 508

		for file_name in slack.carve():
			assert type(file_name) is Attributes.FileName

			file_name_str = file_name.get_file_name()
			assert file_name_str == file_names_expected.pop(0)

	assert c == 1
	assert len(file_names_expected) == 0

	f.close()

	f = open(MFT_NHC, 'rb')

	mft = MFT.MasterFileTableParser(f)
	file_record = mft.get_file_record_by_number(8508)

	c = 0
	for slack in file_record.slack():
		c += 1
		assert len(slack.value) > 0

	assert c == 4

	f.close()

	f = open(MFT_SLACK_2, 'rb')

	mft = MFT.MasterFileTableParser(f)
	file_record = mft.get_file_record_by_number(39)

	file_names_expected = [ 't3.txt', 't3.txt', 't2.txt' ]

	c = 0
	for slack in file_record.slack():
		c += 1

		for file_name in slack.carve(True):
			assert type(file_name) is Attributes.FileName or type(file_name) is str

			if type(file_name) is Attributes.FileName:
				file_name_str = file_name.get_file_name()
			else:
				file_name_str = file_name

			assert file_name_str == file_names_expected.pop(0)

	assert c == 1
	assert len(file_names_expected) == 0

	f.close()

def test_path_resolution():
	f = open(MFT_NHC, 'rb')

	mft = MFT.MasterFileTableParser(f)

	def resolve_and_validate(path, file_number):
		file_record = mft.get_file_record_by_path(path, False)
		if file_number is not None:
			assert file_record is not None
			assert file_record.base_frs.get_master_file_table_number() == file_number
		else:
			assert file_record is None

		file_record = mft.get_file_record_by_path(path, True)
		if file_number is not None:
			assert file_record is not None
			assert file_record.base_frs.get_master_file_table_number() == file_number
		else:
			assert file_record is None

		if path != path.lower():
			file_record = mft.get_file_record_by_path(path.lower(), False)
			if file_number is not None:
				assert file_record is not None
				assert file_record.base_frs.get_master_file_table_number() == file_number
			else:
				assert file_record is None

		if path != path.upper():
			file_record = mft.get_file_record_by_path(path.upper(), False)
			if file_number is not None:
				assert file_record is not None
				assert file_record.base_frs.get_master_file_table_number() == file_number
			else:
				assert file_record is None

	resolve_and_validate('/WINDOWS/Installer/{6C31E111-96BB-4ADC-9C81-E6D3EEDDD8D3}/PowerCalc.exe', 10182)
	resolve_and_validate('/WINDOWS/system32/usrvoica.dll', 2244)
	resolve_and_validate('/WINDOWS/PCHEALTH/HELPCTR/OfflineCache/Professional_32#0409/0000018b.query', 6919)
	resolve_and_validate('/Program Files/MSN/MSNCoreFiles/dw.exe', 5369)
	resolve_and_validate('/Program Files/Anonymizer/Toolbar/Images/software-D.bmp', 9896)

	resolve_and_validate('/Documents and Settings/All Users/Application Data/Microsoft/Crypto/DSS/MachineKeys', 3713)
	resolve_and_validate('/Documents and Settings/All Users/Application Data/Microsoft/Crypto/DSS/MachineKeys/', 3713)
	resolve_and_validate('/WINDOWS/PCHEALTH/HELPCTR/Logs', 6337)
	resolve_and_validate('/WINDOWS/PCHEALTH/HELPCTR/Logs/', 6337)
	resolve_and_validate('/WINDOWS', 458)
	resolve_and_validate('/WINDOWS/', 458)

	resolve_and_validate('/', 5)

	resolve_and_validate('/boot.ini', 3664)
	resolve_and_validate('/CONFIG.SYS', 129)
	resolve_and_validate('/$MFT', 0)
	resolve_and_validate('/$MFTMirr', 1)
	resolve_and_validate('/$LogFile', 2)

	with pytest.raises(MFT.MasterFileTableException):
		mft.get_file_record_by_path('')

	with pytest.raises(MFT.MasterFileTableException):
		mft.get_file_record_by_path('pagefile.sys')

	with pytest.raises(MFT.MasterFileTableException):
		mft.get_file_record_by_path('//')

	with pytest.raises(MFT.MasterFileTableException):
		mft.get_file_record_by_path('///')

	with pytest.raises(MFT.MasterFileTableException):
		mft.get_file_record_by_path('//a/')

	resolve_and_validate('/$mftmirr1', None)
	resolve_and_validate('/windows1/', None)
	resolve_and_validate('/WINDOWS/system32/usrvoica.dll1', None)
	resolve_and_validate('/WINDOWS/system32/1/usrvoica.dll1', None)
	resolve_and_validate('/WINDOWS/system32/ / /usrvoica.dll', None)
	resolve_and_validate('/WINDOWS/system32/WINDOWS/usrvoica.dll', None)
	resolve_and_validate('/Anonymizer/Program Files/Anonymizer/Toolbar/Images/software-D.bmp', None)
	resolve_and_validate('/Program Files/Program Files/Anonymizer/Toolbar/Images/software-D.bmp', None)

	assert mft.get_file_record_by_path('/$mftmirr', True) is None
	assert mft.get_file_record_by_path('/Program FILES', True) is None
	assert mft.get_file_record_by_path('/Program FILES/', True) is None
	assert mft.get_file_record_by_path('/WINDOWS/System32', True) is None
	assert mft.get_file_record_by_path('/WINDOWS/System32/', True) is None

	assert mft.get_file_record_by_path('/WINDOWS/system32/', True).get_master_file_table_number() == 459
	assert mft.get_file_record_by_path('/WINDOWS/system32', True).get_master_file_table_number() == 459

	assert mft.get_file_record_by_path('/$mftmirr', False).get_master_file_table_number() == 1
	assert mft.get_file_record_by_path('/$mftmirr/', False) is None
	assert mft.get_file_record_by_path('/Program Files/MSN/MSNCoreFiles/dw.exe/', False) is None

	assert mft.get_file_record_by_path('/$mftmirr/test', False) is None
	assert mft.get_file_record_by_path('/$mftmirr/test/', False) is None

	f.close()

def test_mapping_pairs():
	for mft_filename in MFT_MAPPING_PAIRS_TEST_LIST:
		f = open(mft_filename, 'rb')

		mft = MFT.MasterFileTableParser(f)
		for fr in mft.file_records():
			data_runs = fr.get_data_runs()

		f.close()

	f = open(MFT_DIFFERENT_LA, 'rb')
	mft = MFT.MasterFileTableParser(f)

	c = 0
	for fr in mft.file_records():
		data_runs = fr.get_data_runs('$Verify')
		if data_runs is not None:
			c += 1
			assert len(data_runs) > 0

	assert c == 1

	fr = mft.get_file_record_by_path('/$Extend/$RmMetadata/$Repair')
	data_runs = fr.get_data_runs('$Corrupt')
	assert len(data_runs) > 0

	f.close()

	f = open(MFT_NHC, 'rb')
	mft = MFT.MasterFileTableParser(f)
	for fr in mft.file_records():
		data_runs = fr.get_data_runs('$Verify')
		assert data_runs is None

	f.close()

	f = open(MFT_MAPPING_PAIRS_1, 'rb')
	mft = MFT.MasterFileTableParser(f)

	fr = mft.get_file_record_by_path('/test_dir/empty.txt')
	assert fr.get_data_runs() is None

	fr = mft.get_file_record_by_path('/test_dir/entirely_sparse')
	data_runs = fr.get_data_runs()
	assert data_runs == [ (None, 32) ]

	fr = mft.get_file_record_by_path('/test_dir/partially_sparse')
	data_runs = fr.get_data_runs()
	assert data_runs == [ (None, 10), (1216, 1), (None, 9), (1226, 1), (None, 9), (1236, 1) ]

	fr = mft.get_file_record_by_path('/test_dir/simple')
	data_runs = fr.get_data_runs()
	assert data_runs == [ (154, 1) ]

	fr = mft.get_file_record_by_path('/test_dir/partially_sparse_2') # No sparse ranges.
	data_runs = fr.get_data_runs()
	assert data_runs == [ (137, 16) ]

	fr = mft.get_file_record_by_path('/test_dir/partially_sparse_3')
	data_runs = fr.get_data_runs()
	assert data_runs == [ (1278, 1), (None, 3), (1282, 1) ]

	fr = mft.get_file_record_by_path('/test_dir/fragmented.txt')
	data_runs = fr.get_data_runs()
	assert data_runs == [ (1222, 4), (1227, 9), (1897, 150), (1237, 41) ]

	f.close()

	f = open(MFT_MAPPING_PAIRS_2, 'rb')
	mft = MFT.MasterFileTableParser(f)

	fr = mft.get_file_record_by_path('/$Extend/$RmMetadata/$Repair')
	data_runs = fr.get_data_runs('$Corrupt')
	assert data_runs == [ (38, 512) ]

	fr = mft.get_file_record_by_path('/$Extend/$RmMetadata/$Repair')
	data_runs = fr.get_data_runs('$Verify')
	assert data_runs == [ (550, 75) ]

	fr = mft.get_file_record_by_path('/test_dir/test_file.txt')
	data_runs = fr.get_data_runs('')
	assert data_runs == [ (2004, 16) ] # No sparse ranges.

	f.close()

def test_boot_sectors():
	with pytest.raises(BootSector.BootSectorException):
		bs = BootSector.BootSector(b'')

	with pytest.raises(BootSector.BootSectorException):
		bs = BootSector.BootSector(b'\x00')

	with pytest.raises(BootSector.BootSectorException):
		bs = BootSector.BootSector(b'\x00' * 512)

	with pytest.raises(BootSector.BootSectorException):
		bs = BootSector.BootSector(b'\x00' * 513)

	f = open(BOOT_4K, 'rb')
	buf = f.read()

	bs = BootSector.BootSector(buf)
	assert bs.get_bytes_per_sector() == 512
	assert bs.get_sectors_per_cluster() == 8
	assert bs.get_file_record_segment_size() == 1024
	assert bs.get_index_record_size() == 4096
	assert bs.get_total_number_of_sectors() == 124700671
	assert bs.get_first_mft_cluster() == 786432
	assert bs.get_first_mftmirr_cluster() == 2
	assert bs.get_serial_number() == 0x7EFEEEDBFEEE8B2B
	assert bs.is_boot_code_present()

	f.close()

	f = open(BOOT_64K, 'rb')
	buf = f.read()

	bs = BootSector.BootSector(buf)
	assert bs.get_bytes_per_sector() == 512
	assert bs.get_sectors_per_cluster() == 128
	assert bs.get_file_record_segment_size() == 1024
	assert bs.get_index_record_size() == 4096
	assert bs.is_boot_code_present()

	f.close()

	f = open(BOOT_128K, 'rb')
	buf = f.read()

	bs = BootSector.BootSector(buf)
	assert bs.get_bytes_per_sector() == 512
	assert bs.get_sectors_per_cluster() == 256
	assert bs.get_file_record_segment_size() == 1024
	assert bs.get_index_record_size() == 4096
	assert bs.get_total_number_of_sectors() == 67102719
	assert bs.get_first_mft_cluster() == 24576

	f.close()

	f = open(BOOT_4Kn, 'rb')
	buf = f.read()

	bs = BootSector.BootSector(buf)
	assert bs.get_bytes_per_sector() == 4096
	assert bs.get_sectors_per_cluster() == 1
	assert bs.get_file_record_segment_size() == 4096
	assert bs.get_index_record_size() == 4096
	assert bs.get_total_number_of_sectors() == 14335
	assert bs.get_first_mft_cluster() == 4778
	assert bs.get_first_mftmirr_cluster() == 2
	assert bs.get_serial_number() == 0x187EB6507EB62682
	assert bs.is_boot_code_present()

	f.seek(2)
	buf = b'\x00\x00' + f.read() # Wipe the first two bytes.

	bs = BootSector.BootSector(buf)
	assert not bs.is_boot_code_present()

	f.close()

	f = open(BOOT_512, 'rb')
	buf = f.read()

	bs = BootSector.BootSector(buf)
	assert bs.get_bytes_per_sector() == 512
	assert bs.get_sectors_per_cluster() == 1
	assert bs.get_file_record_segment_size() == 1024
	assert bs.get_index_record_size() == 4096
	assert bs.get_serial_number() == 0xA6EE1E1BEE1DE479
	assert bs.is_boot_code_present()

	f.seek(2)
	buf = b'\x00\x00' + f.read() # Wipe the first two bytes.

	bs = BootSector.BootSector(buf)
	assert not bs.is_boot_code_present()

	f.close()

	f = open(BOOT_NOBOOTCODE, 'rb')
	buf = f.read()

	bs = BootSector.BootSector(buf)
	assert bs.get_bytes_per_sector() == 512
	assert bs.get_file_record_segment_size() == 1024
	assert bs.get_index_record_size() == 4096
	assert not bs.is_boot_code_present()

	f.close()

def test_file_system():
	f = open(NTFS_FRAGMENTED_MFT, 'rb')

	with pytest.raises(BootSector.BootSectorException):
		fs = MFT.FileSystemParser(f, 0)

	fs = MFT.FileSystemParser(f, 128 * 512)

	assert fs.boot.is_boot_code_present()
	assert fs.boot.get_serial_number() == 0x98E46DB5E46D9672

	assert fs.boot.get_bytes_per_sector() == 512
	assert fs.boot.get_sectors_per_cluster() == 8

	assert fs.boot.get_first_mft_cluster() == 597
	assert fs.boot.get_first_mftmirr_cluster() == 2

	assert fs.boot.get_file_record_segment_size() == 1024
	assert fs.boot.get_index_record_size() == 4096

	assert fs.boot.get_total_number_of_sectors() == 14335

	assert len(fs.data_runs) == 5
	assert fs.data_runs[0] == (597, 235)
	assert fs.data_runs[1] == (1164, 116)
	assert fs.data_runs[2] == (1304, 136)
	assert fs.data_runs[3] == (1456, 112)
	assert fs.data_runs[4] == (1616, 169)

	assert fs.file_size == 3145728

	mft_md5 = '3a75da5a96eeab4850b811df1c6b6ec9'

	md5 = hashlib.md5()
	md5.update(fs.read())
	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(8192)
		md5.update(buf)
		if len(buf) != 8192:
			break

	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(4096)
		md5.update(buf)
		if len(buf) != 4096:
			break

	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(512)
		md5.update(buf)
		if len(buf) != 512:
			break

	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(128)
		md5.update(buf)
		if len(buf) != 128:
			break

	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(17)
		md5.update(buf)
		if len(buf) != 17:
			break

	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(3)
		md5.update(buf)
		if len(buf) != 3:
			break

	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(2)
		md5.update(buf)
		if len(buf) != 2:
			break

	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(1)
		md5.update(buf)
		if len(buf) != 1:
			break

	assert md5.hexdigest() == mft_md5

	md5 = hashlib.md5()
	fs.seek(0)
	while True:
		buf = fs.read(8193)
		md5.update(buf)
		if len(buf) != 8193:
			break

	assert md5.hexdigest() == mft_md5

	assert fs.seek(33333) == 33333
	assert fs.tell() == 33333
	assert len(fs.read(0)) == 0
	assert fs.read(1) == b'\x00'

	fs.seek(0x81D5)
	assert len(fs.read(0)) == 0
	assert fs.read(1) == b'\x79'

	md5 = hashlib.md5()
	fs.seek(0)
	buf = fs.read(8194)
	md5.update(buf)
	assert md5.hexdigest() != mft_md5

	md5 = hashlib.md5()

	fs.seek(33333)
	buf_2 = fs.read(-1)

	fs.seek(0)
	buf_1 = fs.read(33333)
	assert len(buf_1) == 33333

	fs.seek(0)
	buf_t = fs.read(33333+81920)

	md5.update(buf_1)
	md5.update(buf_2)

	assert md5.hexdigest() == mft_md5
	assert buf_t[-81920 : ] == buf_2[ : 81920]

	md5 = hashlib.md5()

	fs.seek(1003520)
	buf_2 = fs.read(-1)

	fs.seek(0)
	buf_1 = fs.read(1003520)
	assert len(buf_1) == 1003520

	md5.update(buf_1)
	md5.update(buf_2)

	assert md5.hexdigest() == mft_md5

	assert fs.seek(-1, 2) == fs.file_size - 1
	assert fs.tell() == fs.file_size - 1

	assert fs.seek(1, 2) == fs.file_size + 1
	assert fs.tell() == fs.file_size + 1

	assert fs.seek(0, 2) == fs.file_size
	assert fs.tell() == fs.file_size

	assert fs.seek(0) == 0
	assert fs.tell() == 0

	fs.seek(0)
	assert len(fs.read(9999999999999999)) == fs.file_size

	fs.seek(4096 + 33)
	assert len(fs.read(9999999999999999)) == fs.file_size - 4096 - 33

	mft = MFT.MasterFileTableParser(fs)
	fr = mft.get_file_record_by_path('/2857')
	assert fr.get_master_file_table_number() == 2900
	assert fr.get_logfile_sequence_number() > 0

	lsn = fr.get_logfile_sequence_number()

	c = 0
	for fr in mft.file_records():
		if fr.get_master_file_table_number() == 2900:
			assert fr.get_logfile_sequence_number() == lsn
			c += 1

	assert c == 1

	fs.seek(1024 * 50 + 1025)
	assert fs.read(1) == b'I'
	assert fs.read(2) == b'LE'

	fs.close()

	f.close()

	f = open(NTFS_FILE_4k, 'rb')

	fs = MFT.FileSystemParser(f)
	mft = MFT.MasterFileTableParser(fs)
	fr = mft.get_file_record_by_number(34)
	assert fr.get_data_runs() == [ (755, 1) ]

	f.close()

def test_file_system_extremely_fragmented_mft():
	try:
		f = open(NTFS_EXTREMELY_FRAGMENTED_MFT, 'rb')
	except Exception:
		pytest.skip('No test file found')

	fs = MFT.FileSystemParser(f, 2048 * 512)
	md5 = hashlib.md5()

	bytes_read = 0
	while True:
		buf = fs.read(16384)

		md5.update(buf)
		bytes_read += len(buf)

		if len(buf) != 16384:
			break

	assert bytes_read == 52166656000
	assert md5.hexdigest() == 'ed9c202405fd9a28b7e0ee96e3f07b33'

	f.close()

def test_file_system_index_allocation():
	f = gzip.open(NTFS_INDEX_GZ, 'rb')

	fs = MFT.FileSystemParser(f, 128 * 512)
	mft = MFT.MasterFileTableParser(fs)

	fr_root = mft.get_file_record_by_path('/')
	fr_dir = mft.get_file_record_by_path('/test_dir/')

	assert fr_root is not None
	assert fr_dir is not None

	file_names_dir = [ '111111111111111.txt', '222222222222222.txt', '333333333333333.txt', '444444444444444.txt', '555555555555555.txt', '666666666666666.txt', '777777777777777.txt',
		'999999999999999.txt', 'AAAAAAAAAAA.txt' ]

	file_names_root = [ '$AttrDef', '$BadClus', '$Bitmap', '$Boot', '$Extend', '$LogFile', '$MFT', '$MFTMirr', '$RECYCLE.BIN', '$Secure', '$UpCase',
		'$Volume', '.',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (10).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (11).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (12).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (13).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (14).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (15).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (2).txt',
		'test_dir',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (4).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (5).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (6).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (7).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (8).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (9).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy.txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.txt',
		'System Volume Information',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (3).txt',
		'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (16).txt' ]

	file_names_slack_dir = [ 'AAAAAAAAAAA.txt', 'AAAAAAAAAAA.txt', 'BBBBBBBBBBBBB-del.txt' ]

	slack_root = []
	slack_dir = []

	c = 0
	for attr in fr_root.attributes():
		if type(attr) is MFT.AttributeRecordResident:
			continue

		v = attr.value_decoded(f, 128 * 512, 2048)
		assert type(v) is Attributes.IndexAllocation
		assert v.index_buffer_size == 4096

		cc = 0
		for index_buf in v.index_buffers():
			assert index_buf.get_logfile_sequence_number() > 0
			assert index_buf.get_this_block() == cc * v.index_buffer_size // 2048

			for index_entry in index_buf.index_entries():
				attr_value = Attributes.FileName(index_entry.get_attribute())

				assert attr_value.get_parent_directory() == 1407374883553285
				file_names_root.remove(attr_value.get_file_name())

			cc += 1

		assert cc == 4

		slack_root.extend(v.get_slack())

		c += 1

	assert c == 1
	assert len(file_names_root) == 0

	c = 0
	for attr in fr_dir.attributes():
		if type(attr) is MFT.AttributeRecordResident:
			continue

		v = attr.value_decoded(f, 128 * 512, 2048)
		assert type(v) is Attributes.IndexAllocation
		assert v.index_buffer_size == 4096

		cc = 0
		for index_buf in v.index_buffers():
			assert index_buf.get_logfile_sequence_number() > 0
			assert index_buf.get_this_block() == 0

			for index_entry in index_buf.index_entries():
				attr_value = Attributes.FileName(index_entry.get_attribute())

				assert attr_value.get_parent_directory() == 281474976710695
				file_names_dir.remove(attr_value.get_file_name())

			cc += 1

		assert cc == 1

		slack_dir.extend(v.get_slack())

		c += 1

	assert c == 1
	assert len(file_names_dir) == 0

	for file_name in MFT.SlackSpace(slack_dir).carve():
		file_names_slack_dir.remove(file_name.get_file_name())

	assert len(file_names_slack_dir) == 0

	file_names_root_dir = []
	for file_name in MFT.SlackSpace(slack_root).carve():
		file_names_root_dir.append(file_name.get_file_name())

	assert len(file_names_root_dir) > 0
	assert 'test_dir' in file_names_root_dir
	assert 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA - Copy (11).txt' in file_names_root_dir

	f.close()

def test_merged_index():
	try:
		f = open(NTFS_EXTREMELY_FRAGMENTED_MFT, 'rb')
	except Exception:
		pytest.skip('No test file found')

	fs = MFT.FileSystemParser(f, 2048 * 512)
	mft = MFT.MasterFileTableParser(fs, False)

	frs = mft.get_file_record_segment_by_number(39)

	child_frs_list_n = [ 10138606, 10344102, 10549520, 1065768, 10755037, 10960570, 11165969, 11371458, 11576904, 11782374, 11987783, 12193225, 12398725, 12604204, 12809756, 1281989, 13015208, 13220823, 13426241, 13631641, 13837158, 14042644, 14248135, 14453614, 14659193, 14864638, 1498280, 15070092, 15275463, 15480864, 15686424, 15891824, 16097357, 16302709, 16508227, 16713806, 16919359, 17124909, 1714541, 17330391, 17535879, 17741369, 17946905, 18152382, 18357936, 18563559, 18768985, 18974511, 19180110, 1930652, 19385624, 19591132, 19796603, 20002108, 201464, 20207579, 20413068, 20618639, 20824145, 21029627, 21235115, 21440523, 2146862, 21646022, 21851464, 22057018, 22262568, 22468042, 22673647, 22879166, 23084671, 23290170, 23495631, 2362862, 23701121, 23906446, 24112016, 24317612, 24523228, 24728637, 24934073, 25139625, 25345248, 25550736, 25756137, 2579154, 25961574, 26167126, 26242, 26372568, 26578077, 26783629, 26989074, 27194607, 27400105, 27605610, 27810968, 2795325, 28016383, 28221872, 28427450, 28632896, 28838233, 29043881, 29249408, 29454869, 29660303, 29865705, 30071230, 3011556, 30276736, 30482260, 30687688, 30893212, 31098763, 31304236, 31509790, 31715294, 31920766, 32126298, 3227797, 32331751, 32537135, 32742703, 32948185, 33153627, 33359019, 33564410, 33769971, 33975341, 34180921, 34386276, 3444078, 34591819, 34797373, 35002873, 35208264, 35413708, 35619208, 35824795, 36030367, 36235611, 36441082, 3660379, 36646624, 36852196, 37057746, 37263219, 37468673, 37674278, 37879795, 38085453, 38290881, 38496352, 38701741, 3876490, 38907337, 39112901, 39318344, 39523833, 39729304, 39934875, 40140360, 40345914, 40551520, 40757009, 4092681, 40962481, 41168078, 41373612, 41579085, 417565, 41784583, 41990081, 42195577, 42401038, 42606546, 42811985, 43017444, 4308742, 43222968, 43428547, 43634137, 43839464, 44045097, 44250666, 44456129, 44661600, 44867018, 45072524, 4524843, 45277951, 45483530, 45688975, 45894482, 46099989, 46305530, 46511126, 46716518, 46921864, 47127434, 47332958, 4741094, 47538512, 47743857, 47949472, 48155069, 48360548, 48566011, 48771455, 48976955, 49182424, 49387886, 4957295, 49593332, 49798832, 50004352, 50209897, 50415358, 50620832, 50826400, 5173417, 5389557, 5605808, 5821899, 6038070, 6254191, 633666, 6470362, 6686613, 6902934, 7119155, 7335386, 7551607, 7767628, 7983649, 8199910, 8416021, 849617, 8632182, 8848643, 9064944, 9281096, 9497187, 9713297, 9929498 ]
	child_frs_list = []
	for i in child_frs_list_n:
		child_frs = mft.get_file_record_segment_by_number(i)
		child_frs_list.append(child_frs)

	fr = MFT.FileRecord(frs, child_frs_list)

	c = 0
	for attr in fr.attributes(True):
		if type(attr) is not MFT.AttributeRecordNonresident:
			continue

		if attr.type_code != 0xA0:
			continue

		assert attr.lowest_vcn == 0 and attr.highest_vcn == 10998527 and attr.file_size == 11262492672 and attr.name == '$I30'
		c += 1

	assert c == 1

	with open(NTFS_EXTREMELY_FRAGMENTED_MFT_INDX_DATA_RUNS, 'rb') as f:
		data_runs_expected = pickle.load(f)

	assert attr.data_runs == fr.get_data_runs('$I30', True)
	assert attr.data_runs == data_runs_expected

	total_length = 0
	for offset, length in attr.data_runs:
		total_length += length

	assert total_length * 1024 == 11262492672

def test_start_block():
	f = open(VOLUME_START_VSS_1, 'rb')

	sb = ShadowCopy.StartBlock(f.read())

	assert '3808876b-c176-4e48-b7ae-04046e6cc752' in str(sb.get_diff_area_guid())
	assert sb.get_version() == 1
	assert sb.get_type() == 1

	assert str(sb.get_max_diff_area_size() / (1024*1024*1024)).startswith('14.8')
	assert sb.get_application_flags() == 1
	assert sb.get_free_space_precopy_percentage() == sb.get_hot_blocks_precopy_percentage() == sb.get_hot_blocks_days() == 0
	assert sb.get_protection_flags() == 0
	assert sb.get_volume_guid() == sb.get_storage_guid()
	assert sb.is_storage_local()
	assert sb.get_first_control_block_offset() > 0

	f.close()

	f = open(VOLUME_START_VSS_2, 'rb')

	sb = ShadowCopy.StartBlock(f.read())

	assert '3808876b-c176-4e48-b7ae-04046e6cc752' in str(sb.get_diff_area_guid())
	assert sb.get_version() == 1
	assert sb.get_type() == 1

	assert sb.get_free_space_precopy_percentage() == sb.get_hot_blocks_precopy_percentage() == sb.get_hot_blocks_days() == 0
	assert sb.get_protection_flags() == 0
	assert sb.get_volume_guid() != sb.get_storage_guid()
	assert not sb.is_storage_local()
	assert sb.get_first_control_block_offset() > 0

	f.close()

	f = open(VOLUME_START_VSS_3, 'rb')

	sb = ShadowCopy.StartBlock(f.read())

	assert '3808876b-c176-4e48-b7ae-04046e6cc752' in str(sb.get_diff_area_guid())
	assert sb.get_version() == 1
	assert sb.get_type() == 1

	assert sb.get_free_space_precopy_percentage() == sb.get_hot_blocks_precopy_percentage() == sb.get_hot_blocks_days() == 0
	assert sb.get_protection_flags() == 0
	assert sb.get_volume_guid() == sb.get_storage_guid()
	assert sb.is_storage_local()
	assert sb.get_first_control_block_offset() > 0

	f.close()

	f = open(VOLUME_START_VSS_4, 'rb')

	sb = ShadowCopy.StartBlock(f.read())

	assert '3808876b-c176-4e48-b7ae-04046e6cc752' in str(sb.get_diff_area_guid())
	assert sb.get_first_control_block_offset() == 0

	f.close()

	f = open(VOLUME_START_VSS_5, 'rb')

	sb = ShadowCopy.StartBlock(f.read())

	assert '3808876b-c176-4e48-b7ae-04046e6cc752' in str(sb.get_diff_area_guid())
	assert sb.get_first_control_block_offset() == 0

	f.close()

def test_control_blocks():
	f = open(VOLUME_CONTROL_BLOCK_FILE_1, 'rb')

	c = 0
	cc = 0
	ccc = 0
	last_guid = None

	relative_offset = 0
	volume_offset = 5079040

	guid_list_t2 = []
	guid_list_t3 = []

	while True:
		buf = f.read(0x4000)
		assert len(buf) == 0x4000

		c += 1
		cb = ShadowCopy.ControlBlock(buf)

		assert cb.get_relative_offset() == relative_offset
		relative_offset += 0x4000

		assert cb.get_volume_offset() == volume_offset
		if cb.get_next_control_block_volume_offset() == 0:
			break

		assert cb.get_next_control_block_volume_offset() == volume_offset + 0x4000
		volume_offset += 0x4000

		for item in cb.items():
			if type(item) is ShadowCopy.ControlBlockItem2:
				cc += 1
				guid_list_t2.append(item.get_store_guid())

				assert item.get_volume_size() in [ 51853131776, 63846744064 ]

				ts = item.get_timestamp()
				assert ts.year == 2019 and ts.month == 5 and ts.day in [ 19, 20, 22 ]
				last_guid = item.get_store_guid()

			if type(item) is ShadowCopy.ControlBlockItem2:
				ccc += 1
				guid_list_t3.append(item.get_store_guid())

	assert c == 4
	assert cc == 7 and cc == ccc
	assert 'b02a9bea-7ceb-11e9-be0a-525400123456' in str(last_guid)

	assert sorted(guid_list_t2) == sorted(guid_list_t3)

	f.close()

	f = open(VOLUME_CONTROL_BLOCK_FILE_2, 'rb')

	c = 0
	cc = 0
	ccc = 0
	relative_offset = 0
	volume_offset = 278528

	guid_list_t2 = []
	guid_list_t3 = []

	while True:
		buf = f.read(0x4000)
		assert len(buf) == 0x4000

		c += 1
		cb = ShadowCopy.ControlBlock(buf)

		assert cb.get_relative_offset() == relative_offset
		relative_offset += 0x4000

		assert cb.get_volume_offset() == volume_offset
		if cb.get_next_control_block_volume_offset() == 0:
			break

		assert cb.get_next_control_block_volume_offset() == volume_offset + 0x4000
		volume_offset += 0x4000

		for item in cb.items():
			if type(item) is ShadowCopy.ControlBlockItem2:
				cc += 1
				guid_list_t2.append(item.get_store_guid())

				assert '06ca047e-8501-11e9-a212-525400123456' in str(item.get_store_guid()) or '06ca047f-8501-11e9-a212-525400123456' in str(item.get_store_guid())
				assert item.get_volume_size() == 137427945984

				ts = item.get_timestamp()
				assert ts.year == 2019 and ts.month == 6 and ts.day == 2 and ts.hour == 10
				assert (ts.minute == 40 and ts.second == 18) or (ts.minute == 41 and ts.second == 21)

			if type(item) is ShadowCopy.ControlBlockItem2:
				ccc += 1
				guid_list_t3.append(item.get_store_guid())

	assert cc == 2 and cc == ccc
	assert c == 4
	assert sorted(guid_list_t2) == sorted(guid_list_t3)

	f.close()

def test_shadow_parser_1():
	f = tarfile.open(VOLUME_VSS_10, 'r').extractfile('vss_10.raw')

	vss = ShadowCopy.ShadowParser(f, 2048 * 512, 268406783 * 512)
	lines_hashes = open(VOLUME_VSS_10_HASHES, 'rb').read().decode().splitlines()

	with pytest.raises(ValueError):
		vss.translate_exact_offset(16 * 1024)

	with pytest.raises(ShadowCopy.ShadowCopyNotFoundException):
		vss.select_shadow(16)

	c = 0
	for shadow in vss.shadows():
		c += 1
		vss.select_shadow(shadow.store_guid)

	assert c == 6

	prev_stack_position = None
	for line_hash in lines_hashes:
		stack_position, offset, flags, md5_list = line_hash.split('\t')

		stack_position = int(stack_position)
		offset = int(offset)
		flags = int(flags)

		md5_list = md5_list.split(' ')
		assert len(md5_list) == 32

		if prev_stack_position is None or prev_stack_position != stack_position:
			vss.select_shadow(stack_position)
			prev_stack_position = stack_position

		try:
			new_offsets = vss.translate_exact_offset(offset)
		except ValueError:
			assert md5_list == [ 'invalid' ] * 32
			continue

		assert len(new_offsets) == 32
		assert flags & 1 == 0

		md5_list_calculated = []
		i = 0
		while True:
			f.seek(2048 * 512 + new_offsets[i])
			buf = f.read(512)

			md5 = hashlib.md5()
			md5.update(buf)
			md5_list_calculated.append(md5.hexdigest() + '_' + str(len(buf)))

			if len(md5_list_calculated) == 32:
				break

			i += 1

		assert md5_list_calculated == md5_list

	f.close()

	f = tarfile.open(VOLUME_VSS_2003, 'r').extractfile('vss_2003.raw')
	lines_hashes = open(VOLUME_VSS_2003_HASHES, 'rb').read().decode().splitlines()

	vss = ShadowCopy.ShadowParser(f, 63 * 512)

	c = 0
	for shadow in vss.shadows():
		c += 1
		vss.select_shadow(shadow.store_guid)

	assert c == 6

	prev_stack_position = None
	for line_hash in lines_hashes:
		stack_position, offset, flags, md5_list = line_hash.split('\t')

		stack_position = int(stack_position)
		offset = int(offset)
		flags = int(flags)

		assert flags == 0

		md5_list = md5_list.split(' ')
		assert len(md5_list) == 32

		if prev_stack_position is None or prev_stack_position != stack_position:
			vss.select_shadow(stack_position)
			prev_stack_position = stack_position

		new_offsets = vss.translate_exact_offset(offset)
		assert len(new_offsets) == 32
		assert offset != new_offsets[0]

		md5_list_calculated = []
		i = 0
		while True:
			f.seek(63 * 512 + new_offsets[i])
			buf = f.read(512)
			assert len(buf) == 512

			md5 = hashlib.md5()
			md5.update(buf)
			md5_list_calculated.append(md5.hexdigest())

			if len(md5_list_calculated) == 32:
				break

			i += 1

		assert md5_list_calculated == md5_list

	f.close()

def test_shadow_parser_2():
	f = tarfile.open(VOLUME_VSS_2003, 'r').extractfile('vss_2003.raw')
	lines_hashes = open(VOLUME_VSS_2003_ALL_HASHES, 'rb').read().decode().splitlines()

	vss = ShadowCopy.ShadowParser(f, 63 * 512)

	prev_stack_position = None
	for line_hash in lines_hashes:
		stack_position, offset, md5_list = line_hash.split('\t')

		stack_position = int(stack_position)
		offset = int(offset)

		md5_list = md5_list.split(' ')
		assert len(md5_list) == 32

		if prev_stack_position is None or prev_stack_position != stack_position:
			vss.select_shadow(stack_position)
			prev_stack_position = stack_position

		new_offsets = vss.translate_exact_offset(offset)
		assert len(new_offsets) == 32

		md5_list_calculated = []
		i = 0
		while True:
			f.seek(63 * 512 + new_offsets[i])
			buf = f.read(512)
			assert len(buf) == 512

			md5 = hashlib.md5()
			md5.update(buf)
			md5_list_calculated.append(md5.hexdigest())

			if len(md5_list_calculated) == 32:
				break

			i += 1

		assert md5_list_calculated == md5_list

	f.close()

	f = tarfile.open(VOLUME_VSS_10, 'r').extractfile('vss_10.raw')
	lines_hashes = open(VOLUME_VSS_10_ALL_HASHES, 'rb').read().decode().splitlines()

	vss = ShadowCopy.ShadowParser(f, 2048 * 512)

	prev_stack_position = None
	for line_hash in lines_hashes:
		stack_position, offset, md5_list = line_hash.split('\t')

		stack_position = int(stack_position)
		offset = int(offset)

		md5_list = md5_list.split(' ')
		assert len(md5_list) == 32

		if 'invalid' in md5_list[0] or md5_list[0].endswith('_0'):
			assert offset == 137435791360

			new_offsets = vss.translate_exact_offset(137435791360)
			continue

		if prev_stack_position is None or prev_stack_position != stack_position:
			vss.select_shadow(stack_position)
			prev_stack_position = stack_position

		new_offsets = vss.translate_exact_offset(offset)
		assert len(new_offsets) == 32

		if len(new_offsets) > 0:
			md5_list_calculated = []
			i = 0
			while True:
				f.seek(2048 * 512 + new_offsets[i])
				buf = f.read(512)
				assert len(buf) == 512

				md5 = hashlib.md5()
				md5.update(buf)
				md5_list_calculated.append(md5.hexdigest() + '_' + str(len(buf)))

				if len(md5_list_calculated) == 32:
					break

				i += 1

			assert md5_list_calculated == md5_list

	f.close()

def test_shadow_parser_vbr():
	f = tarfile.open(VOLUME_VSS_2003, 'r').extractfile('vss_2003.raw')
	vss = ShadowCopy.ShadowParser(f, 63 * 512)

	for stack_position in [ 1, 2, 3, 5 ]:
		vss.select_shadow(stack_position)

		new_offsets = vss.translate_exact_offset(0)
		assert len(new_offsets) == 32

		f.seek(63 * 512 + new_offsets[0])
		buf = f.read(512)
		assert len(buf) == 512

		md5 = hashlib.md5()
		md5.update(buf)
		md5_hash = md5.hexdigest()

		assert md5_hash == 'a316a167c7b099014f7a20d89fb09f73'

	f.close()

	f = tarfile.open(VOLUME_VSS_10, 'r').extractfile('vss_10.raw')
	vss = ShadowCopy.ShadowParser(f, 2048 * 512)

	c1 = 0
	c2 = 0
	for stack_position in [ 1, 2, 3, 5 ]:
		vss.select_shadow(stack_position)

		new_offsets = vss.translate_exact_offset(0)
		assert len(new_offsets) == 32

		f.seek(2048 * 512 + new_offsets[0])
		buf = f.read(512)
		assert len(buf) == 512

		md5 = hashlib.md5()
		md5.update(buf)
		md5_hash = md5.hexdigest()

		if stack_position in [ 1, 2 ]:
			c1 += 1
			assert md5_hash == '9923f57389c97301c01b89b43922e042'
		else:
			c2 += 1
			assert md5_hash == '47ae0418a26d06e9b8dc781177f14d13'

	assert c1 == c2 == 2

	f.close()

def test_shadow_parser_3():
	try:
		f = open(NTFS_LONE_WOLF, 'rb')
		lines_hashes = open(VOLUME_VSS_LONE_WOLF_ALL_HASHES, 'rb').read().decode().splitlines()
	except Exception:
		pytest.skip('No test file found')

	lines_offsets = open(VOLUME_VSS_LONE_WOLF_OFFSETS, 'rb').read().decode().splitlines()

	vss = ShadowCopy.ShadowParser(f, 1259520 * 512)

	vss.select_shadow(1)
	l1 = vss.translate_exact_offset(9632907264)
	vss.select_shadow(2)
	l2 = vss.translate_exact_offset(9632907264)
	assert l1 == l2 == [ None ] * 32

	vss.select_shadow(1)
	l1 = vss.translate_exact_offset(1152303104)
	vss.select_shadow(2)
	l2 = vss.translate_exact_offset(1152303104)
	assert l1 == l2

	ll = []
	for i in range(0, 32):
		ll.append(1152303104 + i * 512)

	assert l2 == ll

	prev_stack_position = None
	for line_offset in lines_offsets:
		stack_position, offset, flags = line_offset.split('\t')

		stack_position = int(stack_position)
		offset = int(offset)
		flags = int(flags)

		if prev_stack_position is None or prev_stack_position != stack_position:
			vss.select_shadow(stack_position)
			prev_stack_position = stack_position

		md5_list_found = False
		for line_hashes in lines_hashes:
			if line_hashes.startswith('{}\t{}\t'.format(stack_position, offset)):
				md5_list = line_hashes.split('\t')[2].split(' ')
				md5_list_found = True
				break

		assert md5_list_found

		new_offsets = vss.translate_exact_offset(offset)
		assert len(new_offsets) == 32

		if len(new_offsets) > 0:
			md5_list_calculated = []
			i = 0
			while True:
				if new_offsets[i] is None:
					md5_list_calculated.append('bf619eac0cdf3f68d496ea9344137e8b') # A block of 512 null bytes.
				else:
					f.seek(1259520 * 512 + new_offsets[i])
					buf = f.read(512)
					assert len(buf) == 512

					md5 = hashlib.md5()
					md5.update(buf)
					md5_list_calculated.append(md5.hexdigest())

				if len(md5_list_calculated) == 32:
					break

				i += 1

			assert md5_list_calculated == md5_list

	prev_stack_position = None
	for line_offset in lines_offsets:
		stack_position, offset, flags = line_offset.split('\t')

		stack_position = int(stack_position)
		if stack_position == 1:
			stack_position = 2
		elif stack_position == 2:
			stack_position = 1
		else:
			assert False

		offset = int(offset)
		flags = int(flags)

		if '{}\t{}\t{}'.format(stack_position, offset, 1) in lines_offsets:
			continue

		if prev_stack_position is None or prev_stack_position != stack_position:
			vss.select_shadow(stack_position)
			prev_stack_position = stack_position

		md5_list_found = False
		for line_hashes in lines_hashes:
			if line_hashes.startswith('{}\t{}\t'.format(stack_position, offset)):
				md5_list = line_hashes.split('\t')[2].split(' ')
				md5_list_found = True
				break

		assert md5_list_found

		new_offsets = vss.translate_exact_offset(offset)
		assert len(new_offsets) == 32

		if len(new_offsets) > 0:
			md5_list_calculated = []
			i = 0
			while True:
				if new_offsets[i] is None:
					md5_list_calculated.append('bf619eac0cdf3f68d496ea9344137e8b') # A block of 512 null bytes.
				else:
					f.seek(1259520 * 512 + new_offsets[i])
					buf = f.read(512)
					assert len(buf) == 512

					md5 = hashlib.md5()
					md5.update(buf)
					md5_list_calculated.append(md5.hexdigest())

				if len(md5_list_calculated) == 32:
					break

				i += 1

			assert md5_list_calculated == md5_list

	f.close()

def test_shadow_parser_file_like():
	f = tarfile.open(VOLUME_VSS_10, 'r').extractfile('vss_10.raw')
	lines_hashes = open(VOLUME_VSS_10_ALL_HASHES, 'rb').read().decode().splitlines()

	vss = ShadowCopy.ShadowParser(f, 2048 * 512)
	vss.select_shadow(1)

	c = 0

	for line_hash in lines_hashes:
		offset = line_hash.split('\t')[1]
		offset = int(offset)

		if offset == 137435791360:
			continue

		new_offsets = vss.translate_exact_offset(offset)
		assert len(new_offsets) == 32
		c += 1

		i = 0
		buf = b''
		while i < 32:
			f.seek(2048 * 512 + new_offsets[i])
			buf += f.read(512)
			assert len(buf) % 512 == 0

			i += 1

		assert vss.seek(offset) == offset
		assert vss.read(0x4000) == buf

		assert vss.seek(offset) == offset
		buf_large = vss.read(0x8000)
		assert len(buf_large) == 0x8000 and buf_large.startswith(buf)

		assert vss.seek(offset) == offset
		buf_200 = vss.read(0x4200)
		assert len(buf_200) == 0x4200
		assert buf_200[ : 0x4000] == buf and buf_200[0x4000 : ] == buf_large[0x4000 : 0x4200]

		assert vss.seek(offset) == offset
		buf_1 = vss.read(0x4001)
		assert len(buf_1) == 0x4001
		assert buf_1[ : 0x4000] == buf and buf_1[0x4000 : ] == buf_large[0x4000 : 0x4001]

		assert vss.seek(offset) == offset
		buf_4001 = vss.read(0x8001)
		assert len(buf_4001) == 0x8001
		assert buf_4001[ : 0x4000] == buf and buf_large == buf_4001[ : 0x8000]

		assert vss.seek(offset) == offset
		assert vss.read(0x4000-1) == buf[: 0x4000-1]
		assert vss.seek(offset) == offset
		assert vss.read(5) == buf[: 5]
		assert vss.seek(offset) == offset
		assert vss.read(1) == buf[: 1]
		assert vss.seek(offset) == offset

		if c == 25:
			break

	f.close()

def test_shadow_invalid_offsets():
	f = tarfile.open(VOLUME_VSS_10, 'r').extractfile('vss_10.raw')

	with pytest.raises(ShadowCopy.InvalidVolume):
		vss = ShadowCopy.ShadowParser(f, 0)

	with pytest.raises(ShadowCopy.InvalidVolume):
		vss = ShadowCopy.ShadowParser(f, 1)

	with pytest.raises(ShadowCopy.InvalidVolume):
		vss = ShadowCopy.ShadowParser(f, 2049 * 512)

	vss = ShadowCopy.ShadowParser(f, 2048 * 512)

	f.close()

def test_gpt():
	f = gzip.open(PT_GPT_0_GZ, 'rb')

	gpt = PartitionTable.GPT(f, 512)
	h = gpt.read_gpt_header()

	assert h.location == 0 and '1156C30A-F330-47F5-BEC9-C85B0F186736' in str(h.disk_guid).upper() and h.number_of_partition_entries > 0 and h.size_of_partition_entry == 128

	for part in gpt.read_gpt_partitions(h.partition_entry_lba, h.number_of_partition_entries, h.size_of_partition_entry, h.partition_entry_crc32):
		assert False

	f.close()

	f = gzip.open(PT_GPT_3_GZ, 'rb')

	gpt = PartitionTable.GPT(f, 512)
	h = gpt.read_gpt_header()

	assert h.location == 0 and '4A57F82F-3B54-45B7-9135-C1D4A9ADDF69' in str(h.disk_guid).upper() and h.number_of_partition_entries > 0 and h.size_of_partition_entry == 128

	c = 0
	for part in gpt.read_gpt_partitions(h.partition_entry_lba, h.number_of_partition_entries, h.size_of_partition_entry, h.partition_entry_crc32):
		if c == 0:
			assert '0FC63DAF-8483-4772-8E79-3D69D8477DE4' in str(part.partition_type_guid).upper() and '0C4A2A68-C2C3-441A-8757-1F888ED2715D' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 34 and part.ending_lba == 64 and part.attributes == 0
		elif c == 1:
			assert '0FC63DAF-8483-4772-8E79-3D69D8477DE4' in str(part.partition_type_guid).upper() and '127D7584-B1A0-48D7-9444-B63BF6AC3FCB' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 65 and part.ending_lba == 128 and part.attributes == 0
		elif c == 2:
			assert part.partition_type_guid == PartitionTable.EFI_SYSTEM_PARTITION_GUID and '8BD51A24-3053-4849-B987-E5BB05EAFE51' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 129 and part.ending_lba == 2014 and part.attributes == 0 and part.partition_name == 'EFI System'

		c += 1

	assert c == 3

	f.seek(0)
	d = bytearray(f.read())
	f.close()

	d[512 + 16] = 0
	d[512 + 17] = 0
	d[512 + 18] = 1
	d[512 + 19] = 2

	f = io.BytesIO(d)
	gpt = PartitionTable.GPT(f, 512)
	h = gpt.read_gpt_header()

	assert h.location == 2 and '4A57F82F-3B54-45B7-9135-C1D4A9ADDF69' in str(h.disk_guid).upper() and h.number_of_partition_entries > 0 and h.size_of_partition_entry == 128

	c = 0
	for part in gpt.read_gpt_partitions(h.partition_entry_lba, h.number_of_partition_entries, h.size_of_partition_entry, h.partition_entry_crc32):
		if c == 0:
			assert '0FC63DAF-8483-4772-8E79-3D69D8477DE4' in str(part.partition_type_guid).upper() and '0C4A2A68-C2C3-441A-8757-1F888ED2715D' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 34 and part.ending_lba == 64 and part.attributes == 0
		elif c == 1:
			assert '0FC63DAF-8483-4772-8E79-3D69D8477DE4' in str(part.partition_type_guid).upper() and '127D7584-B1A0-48D7-9444-B63BF6AC3FCB' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 65 and part.ending_lba == 128 and part.attributes == 0
		elif c == 2:
			assert part.partition_type_guid == PartitionTable.EFI_SYSTEM_PARTITION_GUID and '8BD51A24-3053-4849-B987-E5BB05EAFE51' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 129 and part.ending_lba == 2014 and part.attributes == 0 and part.partition_name == 'EFI System'

		c += 1

	assert c == 3

	f.close()

	d[512 + 32] = 0
	d[512 + 33] = 0
	d[512 + 34] = 0
	d[512 + 35] = 0
	d[512 + 36] = 0
	d[512 + 37] = 0
	d[512 + 38] = 0
	d[512 + 39] = 1

	f = io.BytesIO(d)
	gpt = PartitionTable.GPT(f, 512)
	h = gpt.read_gpt_header()

	assert h.location == 1 and '4A57F82F-3B54-45B7-9135-C1D4A9ADDF69' in str(h.disk_guid).upper() and h.number_of_partition_entries > 0 and h.size_of_partition_entry == 128

	c = 0
	for part in gpt.read_gpt_partitions(h.partition_entry_lba, h.number_of_partition_entries, h.size_of_partition_entry, h.partition_entry_crc32):
		if c == 0:
			assert '0FC63DAF-8483-4772-8E79-3D69D8477DE4' in str(part.partition_type_guid).upper() and '0C4A2A68-C2C3-441A-8757-1F888ED2715D' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 34 and part.ending_lba == 64 and part.attributes == 0
		elif c == 1:
			assert '0FC63DAF-8483-4772-8E79-3D69D8477DE4' in str(part.partition_type_guid).upper() and '127D7584-B1A0-48D7-9444-B63BF6AC3FCB' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 65 and part.ending_lba == 128 and part.attributes == 0
		elif c == 2:
			assert part.partition_type_guid == PartitionTable.EFI_SYSTEM_PARTITION_GUID and '8BD51A24-3053-4849-B987-E5BB05EAFE51' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 129 and part.ending_lba == 2014 and part.attributes == 0 and part.partition_name == 'EFI System'

		c += 1

	assert c == 3

	f.close()

	d += b'\x00' * 1024

	f = io.BytesIO(d)
	gpt = PartitionTable.GPT(f, 512)

	with pytest.raises(ValueError):
		h = gpt.read_gpt_header()

	f.close()

	f = gzip.open(PT_GPT_3_GZ, 'rb')
	d = bytearray(f.read())
	f.close()

	d[1024 + 0] = 12
	d[1024 + 1] = 12
	d[1024 + 2] = 12
	d[1024 + 3] = 12

	f = io.BytesIO(d)
	gpt = PartitionTable.GPT(f, 512)
	h = gpt.read_gpt_header()

	assert h.location == 2 and '4A57F82F-3B54-45B7-9135-C1D4A9ADDF69' in str(h.disk_guid).upper() and h.number_of_partition_entries > 0 and h.size_of_partition_entry == 128

	c = 0
	for part in gpt.read_gpt_partitions(h.partition_entry_lba, h.number_of_partition_entries, h.size_of_partition_entry, h.partition_entry_crc32):
		if c == 0:
			assert '0FC63DAF-8483-4772-8E79-3D69D8477DE4' in str(part.partition_type_guid).upper() and '0C4A2A68-C2C3-441A-8757-1F888ED2715D' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 34 and part.ending_lba == 64 and part.attributes == 0
		elif c == 1:
			assert '0FC63DAF-8483-4772-8E79-3D69D8477DE4' in str(part.partition_type_guid).upper() and '127D7584-B1A0-48D7-9444-B63BF6AC3FCB' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 65 and part.ending_lba == 128 and part.attributes == 0
		elif c == 2:
			assert part.partition_type_guid == PartitionTable.EFI_SYSTEM_PARTITION_GUID and '8BD51A24-3053-4849-B987-E5BB05EAFE51' in str(part.unique_partition_guid).upper()
			assert part.starting_lba == 129 and part.ending_lba == 2014 and part.attributes == 0 and part.partition_name == 'EFI System'

		c += 1

	assert c == 3


def test_mbr():
	f = open(PT_MBR_0, 'rb')

	mbr = PartitionTable.MBR(f, 512)

	h = mbr.read_mbr()
	assert (not h.is_boot_code_present) and h.disk_signature == 0xdd23224b

	for i in mbr.read_mbr_partitions():
		assert False

	f.close()

	f = open(PT_MBR_1, 'rb')

	mbr = PartitionTable.MBR(f, 512)

	h = mbr.read_mbr()
	assert (not h.is_boot_code_present) and h.disk_signature == 0xf22af19f

	c = 0
	for i in mbr.read_mbr_partitions():
		assert i.starting_lba == 1 and i.size_in_lba == 2047 and i.os_type == 0x83 and i.boot_indicator == 0
		c += 1

	assert c == 1

	f.close()

	f = open(PT_MBR_4, 'rb')

	mbr = PartitionTable.MBR(f, 512)

	h = mbr.read_mbr()
	assert (not h.is_boot_code_present) and h.disk_signature == 0x4f781bc6

	c = 0
	for i in mbr.read_mbr_partitions():
		if c == 0:
			assert i.starting_lba == 1 and i.size_in_lba == 2 and i.os_type == 0x83 and i.boot_indicator == 0
		elif c == 1:
			assert i.starting_lba == 3 and i.size_in_lba == 2 and i.os_type == 0x83 and i.boot_indicator == 0
		elif c == 2:
			assert i.starting_lba == 5 and i.size_in_lba == 2 and i.os_type == 0x83 and i.boot_indicator == 0
		elif c == 3:
			assert i.starting_lba == 7 and i.size_in_lba == 2041 and i.os_type == 0x8e and i.boot_indicator == 0

		c += 1

	assert c == 4

	f.close()

	f = gzip.open(PT_MBR_1_1_4k_GZ, 'rb')

	mbr = PartitionTable.MBR(f, 4096)

	h = mbr.read_mbr()
	assert (not h.is_boot_code_present) and h.disk_signature == 0xce1e0256

	c = 0
	for i in mbr.read_mbr_partitions():
		if c == 0:
			assert i.starting_lba == 3 and i.size_in_lba == 2 and i.os_type == 0x8e and i.boot_indicator == 0x80
		elif c == 1:
			assert i.starting_lba == 8 and i.size_in_lba == 4 and i.os_type == 5 and i.boot_indicator == 0

		c += 1

	assert c == 2

	c = 0
	for i in mbr.read_ebr_partitions():
		assert i.starting_lba == 9 and i.size_in_lba == 2 and i.os_type == 0x83 and i.boot_indicator == 0

		c += 1

	assert c == 1

	f.close()

	f = gzip.open(PT_MBR_1_0_4k_GZ, 'rb')

	mbr = PartitionTable.MBR(f, 4096)

	h = mbr.read_mbr()
	assert (not h.is_boot_code_present) and h.disk_signature == 0xee042850

	c = 0
	for i in mbr.read_mbr_partitions():
		if c == 0:
			assert i.starting_lba == 1 and i.size_in_lba == 125 and i.os_type == 0x83 and i.boot_indicator == 0
		elif c == 1:
			assert i.starting_lba == 126 and i.size_in_lba == 130 and i.os_type == 5 and i.boot_indicator == 0

		c += 1

	assert c == 2

	for i in mbr.read_ebr_partitions():
		assert False

	f.close()

	f = gzip.open(PT_MBR_1_2_GZ_1, 'rb')

	mbr = PartitionTable.MBR(f, 512)
	h = mbr.read_mbr()
	assert (not h.is_boot_code_present) and h.disk_signature == 0x0b4a5fbe

	c = 0
	for i in mbr.read_mbr_partitions():
		if c == 0:
			assert i.starting_lba == 1 and i.size_in_lba == 1024 and i.os_type == 5 and i.boot_indicator == 0
		elif c == 1:
			assert i.starting_lba == 1025 and i.size_in_lba == 1023 and i.os_type == 0x83 and i.boot_indicator == 0

		c += 1

	assert c == 2

	c = 0
	for i in mbr.read_ebr_partitions():
		if c == 0:
			assert i.starting_lba == 2 and i.size_in_lba == 511 and i.os_type == 0x83 and i.boot_indicator == 0
		elif c == 1:
			assert i.starting_lba == 514 and i.size_in_lba == 511 and i.os_type == 0x83 and i.boot_indicator == 0

		c += 1

	assert c == 2

	f.close()

	f = gzip.open(PT_MBR_1_2_GZ_2, 'rb')

	mbr = PartitionTable.MBR(f, 512)
	h = mbr.read_mbr()
	assert (not h.is_boot_code_present) and h.disk_signature == 0x896fdd09

	c = 0
	for i in mbr.read_mbr_partitions():
		if c == 0:
			assert i.starting_lba == 1 and i.size_in_lba == 64 and i.os_type == 0x83 and i.boot_indicator == 0
		elif c == 1:
			assert i.starting_lba == 65 and i.size_in_lba == 1983 and i.os_type == 5 and i.boot_indicator == 0

		c += 1

	assert c == 2

	c = 0
	for i in mbr.read_ebr_partitions():
		if c == 0:
			assert i.starting_lba == 66 and i.size_in_lba == 35 and i.os_type == 0x83 and i.boot_indicator == 0
		elif c == 1:
			assert i.starting_lba == 102 and i.size_in_lba == 1946 and i.os_type == 0x8e and i.boot_indicator == 0

		c += 1

	assert c == 2

	f.close()

	f = tarfile.open(PT_MBR_WIN, 'r').extractfile('mbr-win-512.raw')

	mbr = PartitionTable.MBR(f, 512)
	h = mbr.read_mbr()
	assert h.is_boot_code_present and h.disk_signature == 0x882edd52

	c = 0
	for i in mbr.read_mbr_partitions():
		if c == 0:
			assert i.starting_lba == 128 and i.size_in_lba == 16384 and i.os_type == 6 and i.boot_indicator == 0
		elif c == 1:
			assert i.starting_lba == 16512 and i.size_in_lba == 16384 and i.os_type == 6 and i.boot_indicator == 0
		elif c == 2:
			assert i.starting_lba == 32896 and i.size_in_lba == 16384 and i.os_type == 6 and i.boot_indicator == 0
		elif c == 3:
			assert i.starting_lba == 49280 and i.size_in_lba == 471040 and i.os_type == 5 and i.boot_indicator == 0

		c += 1

	assert c == 4

	c = 0
	for i in mbr.read_ebr_partitions():
		if c == 0:
			assert i.starting_lba == 49408 and i.size_in_lba == 16384 and i.os_type == 6 and i.boot_indicator == 0
		elif c == 1:
			assert i.starting_lba == 65920 and i.size_in_lba == 16384 and i.os_type == 6 and i.boot_indicator == 0
		elif c == 2:
			assert i.starting_lba == 82432 and i.size_in_lba == 16384 and i.os_type == 6 and i.boot_indicator == 0
		elif c == 3:
			assert i.starting_lba == 98944 and i.size_in_lba == 417792 and i.os_type == 6 and i.boot_indicator == 0

		c += 1

	assert c == 4

	f.close()

def test_fcb_carver():
	f = open(FCB, 'rb')
	fcb = f.read()
	f.close()

	f = io.BytesIO()
	f.write(fcb)

	carver = MFT.MetadataCarver(f)

	with pytest.raises(ValueError):
		for i in carver.carve_fcb_timestamps():
			assert False

	f.close()

	f = io.BytesIO()

	for i in range(200):
		f.write(fcb)

	carver = MFT.MetadataCarver(f)
	c = 0
	for i in carver.carve_fcb_timestamps():
		assert i.positions[0] == c * 512 + 16
		assert i.positions[1] == 128 and i.positions[2] == 192

		c += 1

	assert c == 200

	f.close()

def test_movetable():
	f = open(TRACKING_4Kn, 'rb')

	with pytest.raises(ValueError):
		m = MoveTable.Header(f.read(1024))

	f.seek(0)

	parser = MoveTable.MoveTableParser(f, 4096)
	m = parser.get_header()

	assert m.get_unknown_16() == 65536
	assert m.get_flags() == 0
	assert m.get_unknown_24() == 0

	assert not m.is_log_flushed()

	expansion_data = m.get_expansion_data()
	assert expansion_data.lowest_log_entry_index_present == 0 and expansion_data.highest_log_entry_index_present == 0 and expansion_data.file_size == 0

	extended_header = m.get_extended_header()

	assert extended_header.machine_id == 'desktop-rd341ha' and str(extended_header.volume_object_id) == 'c621d9da-d9d0-47ef-aac8-0e4655e99c5e'
	assert extended_header.unknown_32 == 0 and extended_header.unknown_timestamp_int_40 == 0 and extended_header.unknown_timestamp_int_48 == 0
	assert extended_header.unknown_flags_56 == 0 and extended_header.unknown_state_60
	assert extended_header.unknown_log_entry_index_64 == 0 and extended_header.unknown_log_entry_index_68 == 0x7F and extended_header.unknown_log_entry_index_72 == 0
	assert extended_header.unknown_log_entry_index_76 == 0 and extended_header.unknown_log_entry_index_80 == 0x7F and extended_header.unknown_log_entry_index_84 == 0
	assert extended_header.unknown_log_entry_index_88 == 0xFFFFFFFF

	m = MoveTable.LogSector(f.read(4096))
	mf = m.get_footer()

	assert mf.get_lowest_log_entry_index_present() == 0 and mf.get_next_log_entry_index() == 9 and mf.get_unused() == b'\x00' * 8

	c = 0
	for log_sector in parser.log_sectors():
		c += 1

	assert c == 4

	c = 0

	next_index = 1
	this_index = 0
	prev_index = 0x7F
	for log_entry in parser.log_entries():
		c += 1

		assert log_entry.get_log_entry_type() == 2
		assert log_entry.get_next_log_entry_index() == next_index and log_entry.get_previous_log_entry_index() == prev_index and log_entry.get_log_entry_index() == this_index
		assert log_entry.get_unknown_16() == 0 and log_entry.get_unknown_120() == 0

		next_index += 1
		this_index += 1
		if prev_index == 0x7F:
			prev_index = 0
		else:
			prev_index += 1

		assert log_entry.get_machine_id() == 'desktop-rd341ha'

		assert str(log_entry.get_birth_droid()[0]) == 'c621d9da-d9d0-47ef-aac8-0e4655e99c5e'
		assert log_entry.get_birth_droid()[1].node == 90520731923542

		assert str(log_entry.get_droid()[0]) == '891b42ce-e70d-45d9-8919-b429b47817a8'
		assert log_entry.get_droid()[1].node == 90520731923542

		assert log_entry.get_object_id().node == 90520731923542

		ts_1, ts_2 = log_entry.get_timestamp()
		assert ts_1.year == 2020 and ts_2.year == 2020

	assert c == 9

	c = 0
	for log_sector in parser.log_sectors():
		c += 1

	assert c == 4

	f.close()

	f = open(TRACKING_512, 'rb')

	parser = MoveTable.MoveTableParser(f)
	m = parser.get_header()

	assert m.get_unknown_16() == 65536
	assert m.get_flags() == 1
	assert m.get_unknown_24() == 0

	assert m.is_log_flushed()

	expansion_data = m.get_expansion_data()
	assert expansion_data.lowest_log_entry_index_present == 0 and expansion_data.highest_log_entry_index_present == 0 and expansion_data.file_size == 0

	extended_header = m.get_extended_header()

	assert extended_header.machine_id == 'desktop-rd341ha' and str(extended_header.volume_object_id) == 'e6984ab8-17ef-4919-b259-c7bea2cd381b'
	assert extended_header.unknown_32 == 0 and extended_header.unknown_timestamp_int_40 == 0 and extended_header.unknown_timestamp_int_48 == 0
	assert extended_header.unknown_flags_56 == 0 and extended_header.unknown_state_60
	assert extended_header.unknown_log_entry_index_64 == 0 and extended_header.unknown_log_entry_index_68 == 0x9B and extended_header.unknown_log_entry_index_72 == 0
	assert extended_header.unknown_log_entry_index_76 == 0 and extended_header.unknown_log_entry_index_80 == 0x9B and extended_header.unknown_log_entry_index_84 == 0

	m = MoveTable.LogSector(f.read(512))
	mf = m.get_footer()

	assert mf.get_lowest_log_entry_index_present() == 0 and mf.get_next_log_entry_index() == 0 and mf.get_unused() == b'\x00' * 8

	c = 0
	for log_sector in parser.log_sectors():
		c += 1

	assert c == 39

	for log_entry in parser.log_entries():
		assert False

	c = 0
	for log_sector in parser.log_sectors():
		c += 1

	assert c == 39

	f.close()

	f = open(TRACKING_512_LARGE, 'rb')

	parser = MoveTable.MoveTableParser(f)
	m = parser.get_header()

	assert m.get_unknown_16() == 65536
	assert m.get_flags() == 1
	assert m.get_unknown_24() == 0

	assert m.is_log_flushed()

	c = 0
	for log_sector in parser.log_sectors():
		c += 1

	assert c == 39

	c = 0
	for log_entry in parser.log_entries():
		c += 1

		assert log_entry.get_machine_id() == 'desktop-tvv7sco'

		assert log_entry.get_birth_droid()[1].node == 90520731923542
		assert log_entry.get_droid()[1].node == 90520731923542
		assert log_entry.get_object_id().node == 90520731923542

		ts_1, ts_2 = log_entry.get_timestamp()
		assert ts_1.year == 2020 and ts_2.year == 2020 and ts_1.month == 8 and ts_2.month == 8

	assert c == 30

	c = 0
	for log_sector in parser.log_sectors():
		c += 1

	assert c == 39

	f.close()

def test_movetable_guess_sector_size():
	f = open(TRACKING_4Kn, 'rb')
	m = MoveTable.MoveTableParser(f)
	assert m.sector_size == 4096
	f.close()

	f = open(TRACKING_512, 'rb')
	m = MoveTable.MoveTableParser(f)
	assert m.sector_size == 512
	f.close()

	f = open(TRACKING_512_LARGE, 'rb')
	m = MoveTable.MoveTableParser(f)
	assert m.sector_size == 512
	f.close()

def test_shadow_two_volumes_1():
	f1 = tarfile.open(VOLUME_VSS_TWO_1, 'r').extractfile('vss_1_vol.raw')
	f2 = tarfile.open(VOLUME_VSS_TWO_2, 'r').extractfile('vss_2_stor.raw')

	with pytest.raises(NotImplementedError):
		parser = ShadowCopy.ShadowParser(f1, 67584 * 512)
		parser.select_shadow(1)

	with pytest.raises(NotImplementedError):
		parser = ShadowCopy.ShadowParserTwoVolumes(f2, f1, 67584 * 512, None, 67584 * 512)

	parser = ShadowCopy.ShadowParser(f2, 67584 * 512)

	c = 0
	for i in parser.shadows():
		c += 1

	assert c == 1

	parser.select_shadow(1)
	parser.seek(40 * 4096)
	buf_shadow = parser.read(2 * 4096)

	f2.seek(67584 * 512 + 40 * 4096)
	buf_curr = f2.read(2 * 4096)

	assert buf_shadow == b'STORAGE' * 1100 + b'\x00' * 492
	assert buf_curr == b'5TORAGE' * 1100 + b'\x00' * 492

	with pytest.raises(ShadowCopy.ShadowCopyNotFoundException):
		parser.select_shadow(2)

	with pytest.raises(ShadowCopy.ShadowCopyNotFoundException):
		parser.select_shadow(3)

	mft = MFT.FileSystemParser(parser)
	md5 = hashlib.md5()

	while True:
		buf = mft.read(512)
		md5.update(buf)

		if len(buf) != 512:
			break

	assert md5.hexdigest() == '58f3e851fa2c9b9c7a631db912386e21'

	parser.seek(44 * 4096)
	buf = parser.read(8192)

	assert hashlib.md5(buf).hexdigest() == '5149c33b9453e2bf30a5e6ec944654f7'

	parser = ShadowCopy.ShadowParserTwoVolumes(f1, f2, 67584 * 512, None, 67584 * 512)

	c = 0
	for i in parser.shadows():
		c += 1

	assert c == 2

	for __ in range(2):
		parser.select_shadow(1)

		parser.seek(1837 * 4096)
		buf_shadow = parser.read(172 * 4096)

		assert buf_shadow == b'1' * 703800 + b'\x00' * 712

		parser.select_shadow(2)

		parser.seek(1837 * 4096)
		buf_shadow = parser.read(172 * 4096)

		assert buf_shadow == b'2' * 703800 + b'\x00' * 712

		with pytest.raises(ShadowCopy.ShadowCopyNotFoundException):
			parser.select_shadow(3)

		f1.seek(67584 * 512 + 1837 * 4096)
		buf_curr = f1.read(172 * 4096)

		assert buf_curr == b'3' * 703800 + b'\x00' * 712

		parser.select_shadow(1)
		parser.select_shadow(2)

	bitmap = open(VOLUME_VSS_TWO_1_BM, 'rb').read()

	parser.select_shadow(1)
	md5 = hashlib.md5()

	i = 0
	while i < len(bitmap) * 8:
		if (bitmap[i // 8] >> (i % 8)) & 1 > 0:
			if i + 1 == len(bitmap) * 8:
				# Two hashes below have been generated from allocated data extracted by The Sleuth Kit.
				# Skip the last cluster to match its behavior.
				break

			parser.seek(i * 4096)
			buf = parser.read(4096)
			md5.update(buf)

		i += 1

	assert md5.hexdigest() == '1c3920a329d6ce78bd6b837fad79e4e4'

	# This shadow copy has the same bitmap.

	parser.select_shadow(2)
	md5 = hashlib.md5()

	i = 0
	while i < len(bitmap) * 8:
		if (bitmap[i // 8] >> (i % 8)) & 1 > 0:
			if i + 1 == len(bitmap) * 8: # See above.
				break

			parser.seek(i * 4096)
			buf = parser.read(4096)

			if buf.startswith(ShadowCopy.VSP_DIFF_AREA_FILE_GUID):
				# Such areas are nulled out by the volsnap driver.
				# But this parser returns them as is, let's deal with it.
				buf = b'\x00' * 4096

			md5.update(buf)

		i += 1

	assert md5.hexdigest() == '2f2e7ea121b37b2d83ff6a86648441fd'

	f1.close()
	f2.close()

def test_shadow_two_volumes_2():
	f = tarfile.open(VOLUME_VSS_TWO_3, 'r').extractfile('vss_3_volstor.raw')

	parser = ShadowCopy.ShadowParser(f, 2048 * 512)

	for i in parser.shadows():
		assert False

	parser = ShadowCopy.ShadowParserTwoVolumes(f, f, 4196352 * 512, None, 2048 * 512)

	c = 0
	for i in parser.shadows():
		c += 1

	assert c == 2

	parser.select_shadow(1)
	parser.seek(261856 * 4096)
	buf = parser.read(52272)
	assert buf.strip(b'1') == b''

	parser.select_shadow(2)
	parser.seek(261856 * 4096)
	buf = parser.read(52272)
	assert buf.strip(b'2') == b''

	f.seek(4196352 * 512 + 261856 * 4096)
	buf = f.read(52272)
	assert buf.strip(b'3') == b''

def test_fat32_bs_bpb():
	with open(FAT_BS, 'rb') as f:
		b = FAT.BSBPB(f.read(512))

	assert FAT.IsFileSystem32(b)

	assert b.get_bs_jmpboot() == b'\xeb\x58\x90'
	assert b.get_bs_oemname() == b'MSDOS5.0'
	assert b.get_bpb_bytspersec() == 512
	assert b.get_bpb_secperclus() == 32
	assert b.get_bpb_rsvdseccnt() == 2860
	assert b.get_bpb_numfats() == 2
	assert b.get_bpb_rootentcnt() == 0
	assert b.get_bpb_totsec16() == 0
	assert b.get_bpb_media() == 0xF8
	assert b.get_bpb_fatsz16() == 0
	assert b.get_bpb_secpertrk() == 63
	assert b.get_bpb_numheads() == 255
	assert b.get_bpb_hiddsec() == 0
	assert b.get_bpb_totsec32() == 61282631

	assert b.get_bpb_fatsz32() == 14954
	assert b.get_bpb_extflags() == (0, False)
	assert b.get_bpb_fsver() == 0
	assert b.get_bpb_rootclus() == 2
	assert b.get_bpb_fsinfo() == 1
	assert b.get_bpb_bkbootsec() == 6
	assert b.get_bpb_reserved() == b'\x00' * 12
	assert b.get_bs_drvnum() == 0x80

	assert b.is_volume_dirty() == (False, False)

	assert b.get_bs_extfields() == (0x4E42EF07, b'NO NAME    ', b'FAT32   ')

	with pytest.raises(FAT.BootSectorException):
		with open(FAT12_BS, 'rb') as f:
			b = FAT.BSBPB(f.read(512))

def test_fat32_bs_bpb_dirty():
	with open(FAT_BS_DIRTY, 'rb') as f:
		b = FAT.BSBPB(f.read(512))

	assert FAT.IsFileSystem32(b)

	assert b.get_bs_jmpboot() == b'\xeb\x58\x90'
	assert b.get_bs_oemname() == b'mkfs.fat'
	assert b.get_bpb_bytspersec() == 512

	assert b.is_volume_dirty() == (True, False)

def test_fat32_attributes():
	assert FAT.ResolveFileAttributes(0x02) == 'HIDDEN'
	assert FAT.ResolveFileAttributes(0x03) == 'READ_ONLY | HIDDEN'
	assert FAT.ResolveFileAttributes(0x23) == 'READ_ONLY | HIDDEN | ARCHIVE'
	assert FAT.ResolveFileAttributes(0) == ''

def test_fat32_sfn():
	assert FAT.ParseShortName(b'PICKLE  A  ') == 'PICKLE.A'
	assert FAT.ParseShortName(b'PICKLE  A ') is None
	assert FAT.ParseShortName(b'FOO     BAR') == 'FOO.BAR'
	assert FAT.ParseShortName(b'FOO12345BA ') == 'FOO12345.BA'
	assert FAT.ParseShortName(b'FOO12345BAR') == 'FOO12345.BAR'
	assert FAT.ParseShortName(b'\xE5OO12345BAR') == '_OO12345.BAR'
	assert FAT.ParseShortName(b'\x00OO12345B  ') == '_OO12345.B'
	assert FAT.ParseShortName(b'\x05OO1234 B  ', 'windows-1251') == 'еOO1234.B'
	assert FAT.ParseShortName(b'\x05OO123 B  ', 'windows-1251') is None
	assert FAT.ParseShortName(b' ' * 11, 'windows-1251') is None
	assert FAT.ParseShortName(b'FOO        ') == 'FOO'
	assert FAT.ParseShortName(b'FOO  C     ') == 'FOO  C'
	assert FAT.ParseShortName(b'FOO C      ') == 'FOO C'
	assert FAT.ParseShortName(b'FOO C   EXE') == 'FOO C.EXE'

def test_fat32_fs():
	f = gzip.open(FAT_FS_LSN, 'rb')

	b = FAT.BSBPB(f.read(512))

	assert FAT.IsFileSystem32(b)
	assert b.get_bpb_fsinfo() > 0

	offset_in_bytes, size_in_bytes, last_data_cluster_plus_one = b.fat_offset_and_size()
	assert offset_in_bytes > 512 and offset_in_bytes % 512 == 0 and size_in_bytes > 512 and size_in_bytes % 512 == 0 and last_data_cluster_plus_one > 2

	f.seek(b.get_bpb_fsinfo() * b.get_bpb_bytspersec())
	bi = FAT.FSINFO(f.read(512))

	assert bi.get_fsi_reserved1() == b'\x00' * 480
	assert bi.get_fsi_reserved2() == b'\x00' * 12
	assert bi.get_fsi_free_count() == 0x01F7EB
	assert bi.get_fsi_nxt_free() == 0x15

	fat = FAT.FAT(f, offset_in_bytes, size_in_bytes, last_data_cluster_plus_one)
	assert fat.get_bpb_media() == 0xF8
	assert not fat.is_volume_dirty()
	assert not fat.are_hard_errors_detected()

	assert fat.chain(15) == [ 15 ]
	assert fat.chain(255) == [ 255 ]
	assert fat.chain(256) == [ 256 ]
	assert fat.chain(2) == [ 2, 18 ]

	with pytest.raises(FAT.FileAllocationTableException):
		fat.chain(9000000)

	with pytest.raises(FAT.FileAllocationTableException):
		fat.chain(129024)

	fat.chain(129023)

	f.close()

def test_fat32_dirent():
	buf = open(FAT_DIRENT_1, 'rb').read()

	dirents = FAT.DirectoryEntries(buf)

	long_names = [ 'usual_2.txt.PFILE', 'empty.txt.PFILE', 'usual_.txt.PFILE', 'Текстовый документ.txt', 'Текстовый документ.txt.PFILE', 'new.txt.PFILE', 'Текстовый документ.txt', 'Текстовый документ.txt.PFILE', 'new_2_.txt.PFILE', 'very long file name here, this is a test.txt', 'very long file name here, this is a test.txt.PFILE', 'привет.txt', 'привет.txt.PFILE' ]
	cnt = 0
	cnt_2 = 0
	codepaged_found = False
	for i in dirents.entries('cp866', False):
		cnt += 1

		assert type(i) is FAT.FileEntry

		if i.short_name == '_sual.txt':
			cnt_2 += 1

			assert i.is_deleted and (not i.is_directory) and (i.long_name is None) and (i.size == 0)
			assert i.is_encrypted
			assert i.first_cluster == 12 and i.ntbyte == 0x19 and i.attributes == 0x20
			assert i.atime == datetime.date(2021, 11, 13)
			assert i.ctime > datetime.datetime(2021, 11, 13, 17, 21, 16) and i.ctime < datetime.datetime(2021, 11, 13, 17, 21, 17)
			assert i.mtime == datetime.datetime(2021, 11, 13, 17, 19, 50)

			ii = FAT.ExpandPath('/123', i)

			assert ii.short_name == '/123/_sual.txt'
			assert ii.is_deleted and (not ii.is_directory) and (ii.long_name is None) and (ii.size == 0)
			assert ii.is_encrypted
			assert ii.first_cluster == 12 and ii.ntbyte == 0x19 and ii.attributes == 0x20
			assert ii.atime == datetime.date(2021, 11, 13)
			assert ii.ctime > datetime.datetime(2021, 11, 13, 17, 21, 16) and ii.ctime < datetime.datetime(2021, 11, 13, 17, 21, 17)
			assert ii.mtime == datetime.datetime(2021, 11, 13, 17, 19, 50)

		if i.short_name == '$EFS':
			cnt_2 += 1

			assert (not i.is_deleted) and (not i.is_directory) and (i.long_name is None) and (i.size == 680)
			assert not i.is_encrypted
			assert i.first_cluster == 14 and i.ntbyte == 0 and i.attributes == 0x06
			assert i.atime == datetime.date(2021, 11, 13)
			assert i.ctime == datetime.datetime(2021, 11, 13, 17, 21, 33) + datetime.timedelta(milliseconds = 70)
			assert i.mtime == datetime.datetime(2021, 11, 13, 17, 21, 34)

			ii = FAT.ExpandPath('/123/', i)

			assert ii.short_name == '/123/$EFS'
			assert (not ii.is_deleted) and (not ii.is_directory) and (ii.long_name is None) and (ii.size == 680)
			assert not ii.is_encrypted
			assert ii.first_cluster == 14 and ii.ntbyte == 0 and ii.attributes == 0x06
			assert ii.atime == datetime.date(2021, 11, 13)
			assert ii.ctime == datetime.datetime(2021, 11, 13, 17, 21, 33) + datetime.timedelta(milliseconds = 70)
			assert ii.mtime == datetime.datetime(2021, 11, 13, 17, 21, 34)

		if 'ривет' in i.short_name.lower():
			codepaged_found = True

		if i.long_name is not None:
			assert i.long_name == long_names.pop(0) 

	assert cnt == 24
	assert cnt_2 == 2
	assert codepaged_found
	assert len(long_names) == 0

	buf = open(FAT_DIRENT_2, 'rb').read()

	dirents = FAT.DirectoryEntries(buf)

	cnt = 0
	cnt_2 = 0
	for i in dirents.entries('ascii', False):
		cnt += 1

		assert type(i) is FAT.FileEntry

		if i.short_name == '1':
			cnt_2 += 1

			assert (not i.is_deleted) and i.is_directory and (i.long_name is None) and (i.size == 0)
			assert not i.is_encrypted
			assert i.first_cluster == 4 and i.ntbyte == 0 and i.attributes == 0x10
			assert i.atime == datetime.date(2020, 12, 10)
			assert i.ctime == datetime.datetime(2021, 12, 1, 22, 53, 32)
			assert i.mtime == datetime.datetime(2021, 12, 1, 22, 50, 48)

			ii = FAT.ExpandPath('/123/', i)

			assert ii.short_name == '/123/1'
			assert (not ii.is_deleted) and ii.is_directory and (ii.long_name is None) and (ii.size == 0)
			assert not ii.is_encrypted
			assert ii.first_cluster == 4 and ii.ntbyte == 0 and ii.attributes == 0x10
			assert ii.atime == datetime.date(2020, 12, 10)
			assert ii.ctime == datetime.datetime(2021, 12, 1, 22, 53, 32)
			assert ii.mtime == datetime.datetime(2021, 12, 1, 22, 50, 48)

	assert cnt == 3
	assert cnt_2 == 1

	buf = open(FAT_DIRENT_3, 'rb').read()
	buf += b'\x00' * (512 - len(buf))

	dirents = FAT.DirectoryEntries(buf)

	cnt = 0
	for i in dirents.entries('ascii', False):
		cnt += 1

		assert type(i) is FAT.FileEntry

		if i.short_name == '32766.txt':
			assert i.size == 4
			assert i.first_cluster == 101672

	assert cnt == 1

def test_fat32_orphan_lfn():
	buf = open(FAT_DIRENT_ORPHAN, 'rb').read()

	dirents = FAT.DirectoryEntries(buf)

	cnt = 0
	cnt_2 = 0
	found_short = False
	for i in dirents.entries('cp866', False):
		cnt += 1

		if type(i) is FAT.OrphanLongEntry:
			cnt_2 += 1
			assert i.long_name_partial == 'long_name_test.txt'

			ii = FAT.ExpandPath('/123/', i)
			assert ii.long_name_partial == '/123/long_name_test.txt'

		if type(i) is FAT.FileEntry and i.short_name == 'SHORT.TXT' and i.long_name is None and not i.is_directory:
			found_short = True
			assert i.long_name is None

			ii = FAT.ExpandPath('/123/', i)
			assert ii.short_name == '/123/SHORT.TXT'

	assert cnt == 20
	assert cnt_2 == 1
	assert found_short

	buf = buf.replace(b'SHORT   TXT', b'\xE5HORT   TXT', 1)

	dirents = FAT.DirectoryEntries(buf)

	cnt = 0
	found_short = False
	for i in dirents.entries('cp866', False):
		cnt += 1

		assert type(i) is FAT.FileEntry

		if i.short_name == '_HORT.TXT' and not i.is_directory:
			found_short = True
			assert i.long_name == 'long_name_test.txt'

	assert cnt == 19
	assert found_short

def test_fat32_verylong():
	buf = open(FAT_DIRENT_VERYLONG, 'rb').read()

	dirents = FAT.DirectoryEntries(buf)

	long_names = [ 'АБВГДЕЖЗИЙКЛМНО' * 17, ('1БВГДЕЖЗИЙКЛМНО' * 17)[:-1], ('2БВГДЕЖЗИЙКЛМНО' * 17)[:-2],  ('3БВГДЕЖЗИЙКЛМНО' * 17)[:-3], 'Я' ]
	cnt = 0
	for i in dirents.entries('cp866', False):
		cnt += 1

		assert type(i) is FAT.FileEntry
		assert i.is_encrypted is not None and not i.is_encrypted
		assert i.long_name == long_names.pop(0) 

	assert cnt == 5
	assert len(long_names) == 0

@pytest.mark.parametrize('step', [0, 1])
def test_fat32_full(step):
	if step == 0:
		correct_off = 512
		f = io.BytesIO(b'\x01' * 512 + tarfile.open(FAT_FULL_TEST, 'r').extractfile('fat32_full_test.raw').read())
	else:
		correct_off = 0

		# This doesn't work:
		#
		#    f = tarfile.open(FAT_FULL_TEST, 'r').extractfile('fat32_full_test.raw')
		#
		# Looks like a bug:
		#
		# >>> import tarfile
		# >>> f = tarfile.open('fat32_full_test.tgz', 'r').extractfile('fat32_full_test.raw')
		# >>> b1 = f.read(512)
		# >>> f.seek(0)
		# 0
		# >>> b2 = f.read(512)
		# >>> __ = f.read()
		# >>> f.seek(0)
		# 0
		# >>> b3 = f.read(512)
		# >>> b1 == b2
		# True
		# >>> b2 == b3
		# False
		#
		# A workaround is:

		f = io.BytesIO(tarfile.open(FAT_FULL_TEST, 'r').extractfile('fat32_full_test.raw').read())

	with pytest.raises(ValueError):
		fs = FAT.FileSystemParser(f, correct_off, 1024*1024)
		for i in fs.walk():
			pass

	with pytest.raises(FAT.BootSectorException):
		fs = FAT.FileSystemParser(f, 1, 1024*1024)

	results = open(FAT_FULL_TEST_RESULTS, 'rb').read().decode('utf-8').splitlines()

	fs = FAT.FileSystemParser(f, correct_off, 536870912)

	found_1 = False
	found_2 = False
	for item in fs.walk():
		assert type(item) is FAT.FileEntry

		if (item.is_directory and (item.short_name.endswith('/.') or item.short_name.endswith('/..'))) or item.is_deleted:
			continue

		item_name = item.short_name
		if item.long_name is not None:
			item_name = item.long_name

		mtime_local = item.mtime + datetime.timedelta(hours = 3)

		result = results.pop(0)
		assert result == item_name + '\t' + mtime_local.strftime('%Y-%m-%d+%H:%M:%S') + '.0000000000'

		if item_name == '/111111/s1/s2/s3/s4/s6/s7/test.txt':
			found_1 = True
			buf = fs.read_chain(item.first_cluster, item.size)
			assert buf == b'test\n'

		if item_name == '/' + '1' * 248 + '/привет.txt':
			found_2 = True
			buf = fs.read_chain(item.first_cluster, item.size)
			assert hashlib.md5(buf).hexdigest() == '989b1b15d9acb7c0101633a935100868'

	assert len(results) == 0
	assert found_1 and found_2

	f.close()
