import os
import stat
import psutil
import logging
from audit import Audit
from pwd import getpwnam, getpwuid 
from grp import getgrnam, getgrgid 
from utils.decorators import assign_order



class DockerFileAudit(Audit):
  """
  Checks assosiated with Docker installation files
  """
  # Enhancement - Identify more strict permissions?Recursive for directories?
  @assign_order(1)
  def check_permissions(self,paths):
    """Check permissions, according to perms for a given file or folder"""
    #Owner permissions dictionary
    bad_files = []
    usrperms = {"0": 0,
                "1": stat.S_IXUSR,
                "2": stat.S_IWUSR,
                "3": (stat.S_IXUSR & stat.S_IWUSR), 
                "4": stat.S_IRUSR,
                "5": (stat.S_IRUSR & stat.S_IXUSR),
                "6": (stat.S_IRUSR & stat.S_IWUSR),
                "7": stat.S_IRWXU
                }
    # Group permissions dictionary
    grpperms = {"0": 0,
                "1": stat.S_IXGRP,
                "2": stat.S_IWGRP,
                "3": (stat.S_IXGRP & stat.S_IWGRP), 
                "4": stat.S_IRGRP,
                "5": (stat.S_IRGRP & stat.S_IXGRP),
                "6": (stat.S_IRGRP & stat.S_IWGRP),
                "7": stat.S_IRWXG
                }
    #Others permissions dictionary
    othperms = {"0": 0,
                "1": stat.S_IXOTH,
                "2": stat.S_IWOTH,
                "3": (stat.S_IXOTH & stat.S_IWOTH), 
                "4": stat.S_IROTH,
                "5": (stat.S_IROTH & stat.S_IXOTH),
                "6": (stat.S_IROTH & stat.S_IWOTH),
                "7": stat.S_IRWXO
                }
    for fpath,perms in paths.iteritems():
      try:
        # Split permission decimal values and OR corresponding 
        #dict. values for final bitmask
        st = os.stat(fpath).st_mode
        mask = usrperms[perms[0]] | grpperms[perms[1]] | othperms[perms[2]]
      except KeyError:
        logging.error('''Wrong permission value for %s. 
                      Check your configuration''' %fpath)
        continue
      except OSError:
        logging.warning("No file or directory found: %s" %fpath)
        continue
      if not bool(st & mask):
        bad_files.append(fpath)

    if len(bad_files):
      self.templog['status'] = "Fail"
      self.templog['descr'] = "%d file(s) with wrong permissions"\
                              %len(bad_files)
      self.templog['output'] = bad_files
    else:
      self.templog['status'] = "Pass"
      self.templog['descr'] = "All files have appropriate permissions"
    
    #self.add_check_results('check_permissions')
    return self.templog

  #Enhancement - If path is directory, do the check recursively
  @assign_order(2)
  def check_owner(self,paths,owner):
    """Check file user and group owner."""
    bad_files = []
    # Get uid and gid for given user
    usruid = getpwnam(owner)[2]
    grpuid = getgrnam(owner)[2]
    for fpath in paths:
      try:
        st = os.stat(fpath)
      except OSError:
        logging.warning("No file or directory found: %s"% fpath)
        continue
      #Get uid and gid for given file
      fileuid = st.st_uid
      filegid = st.st_uid
      fileusr = getpwuid(fileuid)[0]
      filegrp = getgrgid(fileuid)[0]

      if not (fileuid == usruid and grpuid == filegid):
        bad_files.append(fpath)

    if len(bad_files):
      self.templog['status'] = "Fail"
      self.templog['descr'] = "The following files should be owned by %s:%s"\
                              %(owner,owner)
      self.templog['output'] = bad_files
    else:
      self.templog['status'] = "Pass"
      self.templog['descr'] = "File user and group owner are correct"

    #self.add_check_results('check_owner')
    return self.templog

class DockerConfAudit(Audit):
  """Checks assosiated with Docker server configuration"""

  @assign_order(1)
  def check_unwanted_args(self,args):
    """Generic method to detect insecure arguments for running docker"""
    found =[]

    cmd = self.process_running('docker')
    try:
      for arg in args:
        if (arg in cmd):
          found.append(arg)
    except TypeError:
      logging.error("Aborting check.")
      return

    if len(found):
      self.templog['status'] = "Fail"
      self.templog['descr'] = "Docker is running with %d unwanted arguments"\
                              %(len(found))
      self.templog['output'] = found
    else:
      self.templog['status'] = "Pass"
      self.templog['descr'] = "No insecure arguments found"
    #return self.add_check_results('check_unwanted_args')
    return self.templog

  @assign_order(2)
  def check_wanted_args(self,args):
    """Generic method to detect missing security-hardening arguments"""
    missing =[]

    cmd = self.process_running('docker')
    try:
      for arg in args:
        if not (arg in cmd):
          missing.append(arg)
    except TypeError:
      logging.error("Aborting check.")
      return

    if len(missing):
      self.templog['status'] = "Fail"
      self.templog['descr'] = "Docker is running with %d arguments missing"\
                              %(len(missing))
      self.templog['output'] = missing
    else:
      self.templog['status'] = "Pass"
      self.templog['descr'] = "Docker is running with security hardening arguments"

    #return self.add_check_results('check_wanted_args')
    return self.templog
  