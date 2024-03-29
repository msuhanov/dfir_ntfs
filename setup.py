from setuptools import setup
from dfir_ntfs import __version__

setup(
	name = 'dfir_ntfs',
	version = __version__,
	license = 'GPLv3',
	packages = [ 'dfir_ntfs', 'dfir_ntfs.addons' ],
	provides = [ 'dfir_ntfs', 'dfir_ntfs.addons' ],
	scripts = [ 'ntfs_parser', 'vsc_mount', 'fat_parser' ],
	description = 'An NTFS/FAT parser for digital forensics & incident response',
	author = 'Maxim Suhanov',
	author_email = 'no.spam.c@mail.ru',
	classifiers = [
		'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
		'Operating System :: OS Independent',
		'Programming Language :: Python :: 3',
		'Development Status :: 5 - Production/Stable'
	],
	extras_require = {
		'FUSE': [ 'llfuse' ]
	}
)
