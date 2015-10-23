import os
import re
import psutil
import subprocess
import logging

from utils.decorators import assign_order
from grp import getgrnam
from audit import Audit
from docker import Client


class HostConfAudit(Audit):

  #Default values
  kern_ver = 3.10 #kernel version

  @assign_order(1)
  def check_seperate_partition(self):
    """1.1 Create a seperate partition for containers"""    
    mountpoint = "/var/lib/docker"
    partitions = psutil.disk_partitions()
    for partition in partitions:
      if (partition[1] == mountpoint):
        self.templog['status'] = "Pass"
        self.templog['descr'] = "%s mountpoint is %s" \
                                %(partition[0],partition[1])
      else:
        self.templog['status'] = "Fail"
        self.templog['descr'] = "No seperate partition for containers"
    
    return self.add_check_results('check_seperate_partition')

  @assign_order(2)
  def check_kernel_ver(self,ver=kern_ver):
    """1.2 Use the updated kernel version"""
    version = self.cli.version()['KernelVersion']
    isupdate = self.version_check(version,ver)
    if isupdate:
      self.templog['status'] = "Pass"
      self.templog['descr'] =  "Host uses an updated kernel"
    else:
      self.templog['status'] = "Fail"
      self.templog['descr'] =  "Host uses an outdated kernel"
    self.templog['output'] = version
   
    return self.add_check_results('check_kernel_ver')

#Enhancement - Add a list of essential ports
  @assign_order(3)
  def check_listening_srv(self):
    """1.5 Remove all non-essential services from the host"""
    openports= []
    conns = psutil.net_connections()
    for con in conns:
      if (con[5] == 'LISTEN'):
        openports.append([con[3][0],con[3][1]])
    self.templog['descr'] = "Host has %d open ports" %(len(openports))
    self.templog['output'] = openports
    return self.add_check_results('check_listening_srv')

  @assign_order(2)
  def check_docker_ver(self,ver):
    """1.6 Keep Docker up to date"""
    cli = self.cli
    version = cli.version()['Version']
    isupdate = self.version_check(version,ver)
    if isupdate:
      self.templog['status'] = "Pass"
      self.templog['descr'] =  "Host uses an updated Docker version"
    else:
      self.templog['status'] = "Fail"
      self.templog['descr'] =  "Host uses an outdated Docker version"
    self.templog['output'] = version
   
    return self.add_check_results('check_docker_ver')

#Enhancement - Add a list of trusted users
  @assign_order(4)
  def list_trusted_users(self):
    """1.7 Only allow trusted users to control Docker daemon"""
    dockergroup = getgrnam('docker')
    users = dockergroup[3]
    self.templog['descr'] = "%d users in docker group" %(len(users))
    self.templog['output'] = users
    return self.add_check_results('list_trusted_users')

  @assign_order(5)
  def check_auditd_rules(self,rules):
    """1.8 - 1.19 Audit docker daemon, files and directories"""
    found = []
    missing = []
    results = {'found': found,
             'missing' : missing}
    try:
      auditcmd = subprocess.check_output("auditctl -l", shell=True)
      for rule in rules:
        if  (re.search(rule, auditcmd)):
          found.append(rule)
        else:
          missing.append(rule)
    except subprocess.CalledProcessError:
      logging.error("auditd is not installed. REMINDER: \
                    safedock should be run as root")

    if len(missing) > 0:
        self.templog['status'] = "Fail"
        self.templog['descr'] = "%d out of %d auditd rules are missing" \
                                %(len(missing),len(rules)) 
    else:
      self.templog['status'] = "Pass"
      self.templog['descr'] = "All auditd rules are in place"      

    self.templog['output'] = results
    return self.add_check_results('check_auditd_rules')