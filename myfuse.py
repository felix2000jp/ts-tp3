import os
import sys
import errno
import logging
import grp, pwd 
from fuse import FUSE, FuseOSError, Operations, fuse_get_context


class FileSystem(Operations):
  # Constructor to the source folder.
  def __init__(self, root):
    self.root = root
    self.logs = logging.basicConfig(filename="log.log", format='%(asctime)s %(message)s', level=logging.INFO)


  # Returns the current full path for the mouted file system.
  def __full_path(self, partial):
    if partial.startswith("/"):
      partial = partial[1:]
    return os.path.join(self.root, partial)

  def __logs_handler(self):
    uid, gid, _ = fuse_get_context()
    group_name = grp.getgrgid(gid).gr_name
    user_name = pwd.getpwuid(uid).pw_name
    return user_name, group_name


  # Clean the resources used by the filesystem. It is used when the we exit the program.  
  def destroy(self, path):
    pass


  # Access a file
  def access(self, path, mode):
    full_path = self.__full_path(path)
    if not os.access(full_path, mode):
      raise FuseOSError(errno.EACCES)

  # This fills in the elements of the "stat" structure. Required.
  def getattr(self, path, fh=None):
    full_path = self.__full_path(path)
    st = os.lstat(full_path)
    result = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
    return result

  # This is essential because it is what makes commands like ls work.
  def readdir(self, path, fh):
    full_path = self.__full_path(path)
    dirents = ['.', '..']
    if os.path.isdir(full_path):
        dirents.extend(os.listdir(full_path))
    for r in dirents:
        yield r

  # Change files permissions.
  def chmod(self, path, mode):
    full_path = self.__full_path(path)
    return os.chmod(full_path, mode)

  # Change files ownership (we need to look at this).
  def chown(self, path, uid, gid):
    full_path = self.__full_path(path)
    return os.chown(full_path, uid, gid)

  def mknod(self, path, mode, dev):
    return os.mknod(self._full_path(path), mode, dev)

  def rmdir(self, path):
    full_path = self._full_path(path)
    return os.rmdir(full_path)

  def mkdir(self, path, mode):
    return os.mkdir(self._full_path(path), mode)

  def utimens(self, path, times=None):
    return os.utime(self._full_path(path), times)

  # Not really sure why we need this.
  def readlink(self, path):
    pathname = os.readlink(self.__full_path(path))
    if pathname.startswith("/"):
      # Path name is absolute, sanitize it.
      return os.path.relpath(pathname, self.root)
    else:
      return pathname
  
  # Not really sure why we need this.
  def symlink(self, name, target):
    return os.symlink(name, self.__full_path(target))

  # This deals with files that associate with other files.
  def link(self, target, name):
    return os.link(self.__full_path(target), self._full_path(name))
  
  # Unlinks a file. (can remove).
  def unlink(self, path):
    return os.unlink(self.__full_path(path))

  # This is for statistics on the filesystem.
  def statfs(self, path):
    full_path = self.__full_path(path)
    stv = os.statvfs(full_path)
    return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))


  # Open a file.
  def open(self, path, flags):
    user_name, group_name = self.__logs_handler()
    logging.info(" USER " + user_name + " GROUP " + group_name + " OPEN " + path[1:])
    full_path = self.__full_path(path)
    return os.open(full_path, flags)
  
  # Create a file.
  def create(self, path, mode, fi=None):
    user_name, group_name = self.__logs_handler()
    logging.info(" USER " + user_name + " GROUP " + group_name + " CREATE " + path[1:])
    full_path = self.__full_path(path)
    return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
  
  # Read a file.
  def read(self, path, size, offset, fh):
    user_name, group_name = self.__logs_handler()
    logging.info(" USER " + user_name + " GROUP " + group_name + " READ " + path[1:])
    os.lseek(fh, offset, os.SEEK_SET)
    return os.read(fh, size)

  # Write in a file.
  def write(self, path, data, offset, fh):
    print("write")
    user_name, group_name = self.__logs_handler()
    logging.info(" USER " + user_name + " GROUP " + group_name + " WRITE " + path[1:])
    os.lseek(fh, offset, os.SEEK_SET)
    return os.write(fh, data)

  # Truncate a file so that it size is exact.
  def truncate(self, path, length, fh=None):
    full_path = self.__full_path(path)
    with open(full_path, 'r+') as f:
      f.truncate(length)

  # Flush buffered information.
  def flush(self, path, fh):
    return os.fsync(fh)

  # Releasing a file (not exactly closing it).
  def release(self, path, fh):
    user_name, group_name = self.__logs_handler()
    logging.info(" USER " + user_name + " GROUP " + group_name + " RELEASE " + path[1:] + "\n")
    return os.close(fh)


  # Flush any dirty information to disk. (Not sure why we need this)
  def fsync(self, path, datasync, fh):
    return self.flush(path, fh)



def main(mountpoint, root):
    FUSE(FileSystem(root), mountpoint, nothreads=True, foreground=True, **{'allow_other': True, 'default_permissions': True})

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1])

























