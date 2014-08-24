import hashlib
import io
import os
import unittest

from vmock import mockcontrol

import fileutils


class IStringIO(io.StringIO):

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return


class TestFileUtils(unittest.TestCase):
    def setUp(self):
        self.mc = mockcontrol.MockControl()
        self.addCleanup(self.mc.tear_down)

        self.fopen_mock = self.mc.mock_method(fileutils, 'fopen')
        self.chmod_mock = self.mc.mock_method(os, 'chmod')

    def test_ensure_dir(self):
        isfile_mock = self.mc.mock_method(os.path, 'isfile')
        exists_mock = self.mc.mock_method(os.path, 'exists')
        makedirs_mock = self.mc.mock_method(os, 'makedirs')
        unlink_mock = self.mc.mock_method(os, 'unlink')

        file_path = '/dir1/dir2/file.txt'
        dir_path = '/dir1/dir2'

        isfile_mock(dir_path).returns(True)
        unlink_mock(dir_path)
        exists_mock(dir_path).returns(False)
        makedirs_mock(dir_path, mode=0o0777)
        self.mc.replay()
        fileutils.ensure_dir(file_path, dir_access=0o0777)
        self.mc.verify()

    def test_ensure_dir_os_error(self):
        isfile_mock = self.mc.mock_method(os.path, 'isfile')
        exists_mock = self.mc.mock_method(os.path, 'exists')
        makedirs_mock = self.mc.mock_method(os, 'makedirs')
        unlink_mock = self.mc.mock_method(os, 'unlink')

        file_path = '/dir1/dir2/file.txt'

        dir_path = '/dir1/dir2'
        dir_path1 = '/dir1'

        # No top level directory. dir_path1 is a file.
        # System will try to delete it.

        isfile_mock(dir_path).returns(False)
        exists_mock(dir_path).returns(False)
        makedirs_mock(dir_path, mode=0o0777).raises(OSError())

        # Reduced path call.
        isfile_mock(dir_path1).returns(True)
        unlink_mock(dir_path1)
        exists_mock(dir_path1).returns(False)
        makedirs_mock(dir_path1, mode=0o0777)

        # Full round again.
        isfile_mock(dir_path).returns(False)
        exists_mock(dir_path).returns(False)
        makedirs_mock(dir_path, mode=0o0777)

        self.mc.replay()
        fileutils.ensure_dir(file_path, dir_access=0o0777)
        self.mc.verify()

    def test_ensure_dir_unrecoverable_error(self):
        isfile_mock = self.mc.mock_method(os.path, 'isfile')
        exists_mock = self.mc.mock_method(os.path, 'exists')
        makedirs_mock = self.mc.mock_method(os, 'makedirs')

        file_path = '/dir1/dir2/file.txt'

        dir_path = '/dir1/dir2'
        dir_path1 = '/dir1'

        # No dir2 directory, can't create it due to permission denied error.

        isfile_mock(dir_path).returns(False)
        exists_mock(dir_path).returns(False)
        makedirs_mock(dir_path, mode=0o0777).raises(OSError())

        # Reduced path call.
        isfile_mock(dir_path1).returns(False)
        exists_mock(dir_path1).returns(True)

        # Full round again.
        isfile_mock(dir_path).returns(False)
        exists_mock(dir_path).returns(False)
        makedirs_mock(dir_path, mode=0o0777).raises(OSError())

        self.mc.replay()
        self.assertRaises(OSError, fileutils.ensure_dir, file_path,
                          dir_access=0o0777)
        self.mc.verify()

    def test_write_file_bytes(self):
        data_buf = IStringIO()
        self.fopen_mock('name', 'wb', file_access=None).returns(data_buf)

        self.mc.replay()
        fileutils.write_file('name', '01234567890', create_dirs=False)
        self.assertEqual('01234567890', data_buf.getvalue())
        self.mc.verify()

    def test_write_file_generator(self):
        data_buf = IStringIO()

        self.fopen_mock('name', 'wb', file_access=None).returns(data_buf)

        def data():
            for i in '01234567890':
                yield i

        self.mc.replay()
        fileutils.write_file('name', data(), create_dirs=False)
        self.assertEqual('01234567890', data_buf.getvalue())
        self.mc.verify()

    def test_file_hash(self):
        content = b'abc123'
        data_buf = io.BytesIO(content)
        content_hash = hashlib.md5(content).hexdigest()
        hash_obj = hashlib.md5()
        self.fopen_mock('name', 'rb').returns(data_buf)
        self.mc.replay()
        test_content_hash = fileutils.file_hash('name', hash_obj)
        self.assertEqual(content_hash, test_content_hash)

    def test_file_md5(self):
        content = b'abc123'
        data_buf = io.BytesIO(content)
        content_hash = hashlib.md5(content).hexdigest()
        self.fopen_mock('name', 'rb').returns(data_buf)
        self.mc.replay()
        test_content_hash = fileutils.file_md5('name')
        self.assertEqual(content_hash, test_content_hash)


    def test_file_sha1(self):
        content = b'abc123'
        data_buf = io.BytesIO(content)
        content_hash = hashlib.sha1(content).hexdigest()
        self.fopen_mock('name', 'rb').returns(data_buf)
        self.mc.replay()
        test_content_hash = fileutils.file_sha1('name')
        self.assertEqual(content_hash, test_content_hash)


    def test_file_sha256(self):
        content = b'abc123'
        data_buf = io.BytesIO(content)
        content_hash = hashlib.sha256(content).hexdigest()
        self.fopen_mock('name', 'rb').returns(data_buf)
        self.mc.replay()
        test_content_hash = fileutils.file_sha256('name')
        self.assertEqual(content_hash, test_content_hash)


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.CRITICAL)
    unittest.TestProgram()
