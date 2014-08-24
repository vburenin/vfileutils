"""Different file utils that are useful while working with files."""

import hashlib
import logging
import os
import re

REMOVE_QUOTES_RE = re.compile('^["\']|["\']$')


def fopen(name, mode='r', file_access=None):
    """Use to open files instead the built-in open function.

    Will help a lot with unit testings.
    :param str name: Path to a file to open.
    :param str mode: A file opening mode.
    :param int|None file_access: A file access permissions.
    :rtype: __builtin__.file
    """
    fh = open(name, mode=mode)
    if file_access is not None:
        os.chmod(name, file_access)
    return fh


def ensure_dir(path, dir_access=0o755, raise_first_error=False):
    """Creates a directory according to a file path.

    :param str path: File path for which dir should be created.
           If path is a directory - make sure it is terminated with slash.
    :param int dir_access: A dir mode.
    """
    log = logging.getLogger(__name__)
    dir_name = os.path.realpath(os.path.dirname(path))
    if os.path.isfile(dir_name):
        log.warning('While creating directory a file with the same '
                    'name has been detected: %s', dir_name)
        os.unlink(dir_name)
    try:
        if not os.path.exists(dir_name):
            log.debug('Creating directory %s', dir_name)
            os.makedirs(dir_name, mode=dir_access)
        else:
            log.debug('Directory %s already exists', dir_name)
    except OSError as err:
        if not raise_first_error and dir_name != path:
            log.warning('Error during directory creation attempt: %s', err)
            ensure_dir(dir_name, dir_access, False)
            ensure_dir(path, dir_access, True)
        else:
            raise err


def write_file(file_path, content, create_dirs=True,
               dir_access=0o0755, file_access=None):
    """Writes file content and md5 checksum to it.

    :param str file_path: file path.
    :param basestring|Iterable content: content to be written.
    :param bool create_dirs: Will create all necessary directory structure.
    :param int dir_access: A directory access permissions.
    :param int|None file_access: A file access permissions.
    """
    if create_dirs:
        ensure_dir(file_path, dir_access)

    with fopen(file_path, 'wb', file_access=file_access) as fh:
        if isinstance(content, (str, bytes)):
            fh.write(content)
        else:
            for l in content:
                fh.write(l)


def read_key_value_file(filename):
    """Read file in format <key1>=<value1>\n...

    :param str filename: file to read

    :rtype: dict
    :return: dictionary in format {key1: value1, key2: value2, ...}
    """

    result = {}
    with open(filename) as fh:
        for line in fh:
            line = line.strip()
            if line and line[0] != '#':
                key, val = line.split('=')
                val = REMOVE_QUOTES_RE.sub('', val)
                result[key.strip()] = val.strip()

    return result


def write_key_value_file(filename, data_dict):
    """Write a key=value file.

    :param str filename: Destination filename.
    :param dict data_dict: Dictionary to write.
    """

    with open(filename, 'w') as fh:
        for key, value in data_dict.items():
            fh.write('%s=%s\n' % (key, value))


def file_hash(file_path, hash_obj):
    """Calculates file check sum.

    :param str file_path: File path.
    :param _hashlib.HASH hash_obj: File path.
    :return: String hex digest md5.
    :rtype: str
    """
    with fopen(file_path, 'rb') as fh:
        r = fh.read(1048576)
        while r:
            hash_obj.update(r)
            r = fh.read(1048576)
    return hash_obj.hexdigest()


def file_md5(file_path):
    """Calculates md5 file check sum.

    :param str file_path: File path.
    :return: Hex digest md5.
    :rtype: str
    """

    return file_hash(file_path, hashlib.md5())


def file_sha1(file_path):
    """Calculates sha1 file check sum.

    :param str file_path: File path.
    :return: Hex digest md5.
    :rtype: str
    """

    return file_hash(file_path, hashlib.sha1())


def file_sha256(file_path):
    """Calculates sha1 file check sum.

    :param str file_path: File path.
    :return: Hex digest md5.
    :rtype: str
    """

    return file_hash(file_path, hashlib.sha256())
