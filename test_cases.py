# coding: utf-8

# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov

import pytest
import os
import hashlib
import datetime
import re
import io
from dfir_ntfs import MFT, WSL, USN, Attributes, LogFile, BootSector

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

NTFS_FRAGMENTED_MFT = os.path.join(TEST_DATA_DIR, 'ntfs_frag_mft.bin')
NTFS_EXTREMELY_FRAGMENTED_MFT = os.path.join(TEST_DATA_DIR, 'ntfs_extremely_fragmented_mft.raw') # This file is too large to be included into the repository.

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
	assert s == 'READ_ONLY | SPARSE'

	s = Attributes.ResolveFileAttributes(0x80000)
	assert s == ''

	s = Attributes.ResolveFileAttributes(0x80004)
	assert s == 'SYSTEM'

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

	assert len(fs.mft_data_runs) == 5
	assert fs.mft_data_runs[0] == (597, 235)
	assert fs.mft_data_runs[1] == (1164, 116)
	assert fs.mft_data_runs[2] == (1304, 136)
	assert fs.mft_data_runs[3] == (1456, 112)
	assert fs.mft_data_runs[4] == (1616, 169)

	assert fs.mft_size == 3145728

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

	assert fs.seek(-1, 2) == fs.mft_size - 1
	assert fs.tell() == fs.mft_size - 1

	assert fs.seek(1, 2) == fs.mft_size + 1
	assert fs.tell() == fs.mft_size + 1

	assert fs.seek(0, 2) == fs.mft_size
	assert fs.tell() == fs.mft_size

	assert fs.seek(0) == 0
	assert fs.tell() == 0

	fs.seek(0)
	assert len(fs.read(9999999999999999)) == fs.mft_size

	fs.seek(4096 + 33)
	assert len(fs.read(9999999999999999)) == fs.mft_size - 4096 - 33

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

	assert md5.hexdigest() == 'ed9c202405fd9a28b7e0ee96e3f07b33'
	assert bytes_read == 52166656000

	f.close()
