import os
import sys
import errno
import logging
import grp, pwd 
import stat
import tkinter
import pyotp
import qrcode
import hashlib
from fuse import FUSE, FuseOSError, Operations, fuse_get_context

class FileSystem(Operations):
  # Constructor to the source folder.
  def __init__(self, root):
    self.root = root
    
    # Logs
    self.logs = logging.getLogger('log')
    formatter = logging.Formatter(fmt="%(asctime)s %(levelname)-8s %(message)s", datefmt="%a, %d %b %Y %H:%M:%S")
    file_handler = logging.FileHandler("logs.log")
    file_handler.setFormatter(formatter)
    self.logs.setLevel(logging.INFO)
    self.logs.addHandler(file_handler)

    # OTP
    secret = pyotp.random_base32()
    self.totp = pyotp.TOTP(secret)
    url = self.totp.provisioning_uri(name='FUSE', issuer_name='Secure App')
    img = qrcode.make(url)
    img.save('qr_googleAUTH.png')
    
    # Flgas
    self.access_permission = False

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

  def __permit_file(self):
    def _get_code(event):
      code.set(entry.get())
      window.destroy()
     
    print(self.totp.now())
    window = tkinter.Tk()
    window.title('')
    window.geometry("200x200")
    label  = tkinter.Label(text="Access Code")
    label.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)
    entry  = tkinter.Entry()
    entry.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)
    button = tkinter.Button(window, text="Submit Code")
    button.place(relx=0.5, rely=0.7, anchor=tkinter.CENTER)
    button.bind("<Button>", _get_code)
    code = tkinter.StringVar()
    window.mainloop()

    if self.totp.verify(code.get()):
      return True
    else:
      return False  

  
  def __permissions_to_unix_name(self, full_path):
    st = os.lstat(full_path)
    is_dir = 'd' if stat.S_ISDIR(st.st_mode) else '-'
    dic = {'7':'rwx', '6' :'rw-', '5' : 'r-x', '4':'r--', '3': '-wx', '2': '-w-', '1': '--x', '0': '---'}
    perm = str(oct(st.st_mode)[-3:])
    return (is_dir + ''.join(dic.get(x,x) for x in perm))[1:10], st



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
    user_name, group_name = self.__logs_handler()
    uid, _, _ = fuse_get_context()
    st = os.lstat(self.root)
    if uid == st.st_uid:
      self.logs.info(" USER " + user_name + " GROUP " + group_name + " CHANGED PERMISSIONS ON " + path[1:])
      return os.chmod(full_path, mode)
    else:
      self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO CHANGE PERMISSIONS ON " + path[1:])
      raise FuseOSError(errno.EPERM)
    

  # Change files ownership (we need to look at this).
  def chown(self, path, uid, gid):
    full_path = self.__full_path(path)
    return os.chown(full_path, uid, gid)

  def mknod(self, path, mode, dev):
    return os.mknod(self.__full_path(path), mode, dev)

  def rmdir(self, path):
    full_path = self.__full_path(path)
    user_name, group_name = self.__logs_handler()
    uid, _, _ = fuse_get_context()
    st = os.lstat(self.root)
    if uid == st.st_uid:
      self.logs.info(" USER " + user_name + " GROUP " + group_name + " REMOVED DIR " + path[1:])
      return os.rmdir(full_path)
    else:
      self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO REMOVE DIR " + path[1:])
      raise FuseOSError(errno.EPERM)

    
  def mkdir(self, path, mode):
    full_path = self.__full_path(path)
    user_name, group_name = self.__logs_handler()
    uid, _, _ = fuse_get_context()
    st = os.lstat(self.root)
    if uid == st.st_uid:
      self.logs.info(" USER " + user_name + " GROUP " + group_name + " CREATED DIR " + path[1:])
      return os.mkdir(full_path, mode)
    else:
      self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO CREATE DIR " + path[1:])
      raise FuseOSError(errno.EPERM)
    

  def utimens(self, path, times=None):
    return os.utime(self.__full_path(path), times)

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
    full_path = self.__full_path(path)
    user_name, group_name = self.__logs_handler()
    uid, _, _ = fuse_get_context()
    st = os.lstat(self.root)
    if uid == st.st_uid:
      self.logs.info(" USER " + user_name + " GROUP " + group_name + " REMOVE " + path[1:])
      return os.unlink(full_path)
    else:
      self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO REMOVE " + path[1:])
      raise FuseOSError(errno.EPERM)
   

  # This is for statistics on the filesystem.
  def statfs(self, path):
    full_path = self.__full_path(path)
    stv = os.statvfs(full_path)
    return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))


  # Open a file.
  def open(self, path, flags):
    user_name, group_name = self.__logs_handler()
    full_path = self.__full_path(path)
    
    # Permissoes para abir
    permissions, st = self.__permissions_to_unix_name(full_path)
    uid, gid, _ = fuse_get_context()
    owner = permissions[0:3] # owner
    group = permissions[3:6] # group
    other = permissions[6:9] # other

    if uid == st.st_uid: # owner
      if owner == "---" and not self.__permit_file():
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO OPEN " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.access_permission = True
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " OPEN " + path[1:])
        return os.open(full_path, flags)
    elif gid == st.st_gid: # group
      if group == "---" and not self.__permit_file():
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO OPEN " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.access_permission = True
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " OPEN " + path[1:])
        return os.open(full_path, flags)
    else: # other
      if other == "---" and not self.__permit_file():
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO OPEN " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.access_permission = True
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " OPEN " + path[1:])
        return os.open(full_path, flags)

  
  # Create a file.
  def create(self, path, mode, fi=None):
    full_path = self.__full_path(path)
    user_name, group_name = self.__logs_handler()
    uid, _, _ = fuse_get_context()
    st = os.lstat(self.root)
    if uid == st.st_uid:
      self.logs.info(" USER " + user_name + " GROUP " + group_name + " CREATE " + path[1:])
      return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
    else:
      self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO CREATE " + path[1:])
      raise FuseOSError(errno.EACCES)
    
  # Read a file.
  def read(self, path, size, offset, fh):
    user_name, group_name = self.__logs_handler()
    full_path = self.__full_path(path)

    # Permissoes para abir
    permissions, st = self.__permissions_to_unix_name(full_path)
    uid, gid, _ = fuse_get_context()
    owner = permissions[0:3] # owner
    group = permissions[3:6] # group
    other = permissions[6:9] # other
    if uid == st.st_uid: # owner
      if owner[0] != "r" and not self.access_permission:
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO READ " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.access_permission = False
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " READ " + path[1:])
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, size)
    elif gid == st.st_gid: # group
      if group[0] != "r" and not self.access_permission:
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO READ " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.access_permission = False
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " READ " + path[1:])
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, size)
    else: # other
      if other[0] != "r" and not self.access_permission:
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO READ " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.access_permission = False
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " READ " + path[1:])
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, size)

  # Write in a file.
  def write(self, path, data, offset, fh):
    user_name, group_name = self.__logs_handler()
    full_path = self.__full_path(path)

    # Permissoes para abir
    permissions, st = self.__permissions_to_unix_name(full_path)
    uid, gid, _ = fuse_get_context()
    owner = permissions[0:3] # owner
    group = permissions[3:6] # group
    other = permissions[6:9] # other
    if uid == st.st_uid: # owner
      if owner[1] != "w":
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO WRITE " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " WRITE " + path[1:])
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, data)
    elif gid == st.st_gid: # group
      if group[1] != "w":
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO WRITE " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " WRITE " + path[1:])
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, data)
    else: # other
      if other[1] != "w":
        self.logs.warning(" USER " + user_name + " GROUP " + group_name + " TRIED TO WRITE " + path[1:])
        raise FuseOSError(errno.EACCES)
      else:
        self.logs.info(" USER " + user_name + " GROUP " + group_name + " WRITE " + path[1:])
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
    return os.close(fh)

  # Flush any dirty information to disk. (Not sure why we need this)
  def fsync(self, path, datasync, fh):
    return self.flush(path, fh)


class Metadata:

  def _hash(self, file):
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    #md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            #md5.update(data)
            sha1.update(data)

    #print("MD5: {0}".format(md5.hexdigest()))
    return format(sha1.hexdigest())

  def __permissions_to_unix_name(self, st):
    is_dir = 'd' if stat.S_ISDIR(st.st_mode) else '-'
    dic = {'7':'rwx', '6' :'rw-', '5' : 'r-x', '4':'r--', '0': '---'}
    perm = str(oct(st.st_mode)[-3:])
    return is_dir + ''.join(dic.get(x,x) for x in perm)

  def get_metadata(self, root):
    self.meta = logging.getLogger('metadata')
    formatter = logging.Formatter(fmt="%(message)s")

    file_handler = logging.FileHandler("metadata.log", mode='w')
    file_handler.setFormatter(formatter)

    self.meta.setLevel(logging.INFO)
    self.meta.addHandler(file_handler)

    ass = os.walk(root, topdown=True, onerror=None, followlinks=False)
    for root, dirs, files in ass:
      for name in files:
        path = os.path.join(root, name)
        stats = os.lstat(path)
        perms = self.__permissions_to_unix_name(stats)
        owner = pwd.getpwuid(stats.st_uid).pw_name
        owner_g = grp.getgrgid(stats.st_gid).gr_name
        h = self._hash(path)
        self.meta.info(f"{name} {perms} {owner} {owner_g} {h}")
      for name in dirs:
        path = os.path.join(root, name)
        stats = os.lstat(path)
        owner = pwd.getpwuid(stats.st_uid).pw_name
        owner_g = grp.getgrgid(stats.st_gid).gr_name
        perms = self.__permissions_to_unix_name(stats)
        self.meta.info(f"{name} {perms} {owner} {owner_g}")
    os.chmod("metadata.log", stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)



def main(mountpoint, root):
  metadata = Metadata()
  metadata.get_metadata(root)
  FUSE(FileSystem(root), mountpoint, nothreads=True, foreground=True, **{'allow_other': True})

if __name__ == '__main__':
  main(sys.argv[2], sys.argv[1])