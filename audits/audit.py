import os
import sys
import logging
import psutil
from docker import Client
from collections import defaultdict

BASE_URL = 'unix://var/run/docker.sock'

class Audit:

  def __init__(self):
    #logdict stores the results of the audit category,
    #templog is a temp dict which stores the result of each check
    #and gets cleared after each check
    self.logdict = {}
    self.templog = {}
    self.cli = Client(base_url= BASE_URL)
    self.running = self.running_containers()

  def call(self,audit):
    """Reads YML profile and calls the equivelent method"""
    try:
      return getattr(self, audit)()
    except AttributeError:
      return logging.error("No audit named %s" %(audit))

  def call_with_args(self,audit):
    """Same as call() but for methods with arguments"""
    args = []
    func = audit.keys()[0]
    for argument in audit.values():
      for key,value in argument.iteritems():
        args.append(value)
   # try:
    return getattr(self,func)(*args)
   # except :
   #   return logging.error("No audit named %s" %(func))

  def run_audits(self,audits):
    for audit in audits:
      if (type(audit) == str):
        logging.debug("Running %s with no args" %audit)
        self.call(audit)
      else:     
        logging.debug("Running %s with args %s" \
                      %(audit.keys(), audit.values()))
        self.call_with_args(audit)
    return 

  def add_check_results(self,audit_name):
    """Adds audit results to output dict"""
    self.logdict[audit_name] = self.templog
    self.templog = {}
    return

  def running_containers(self):
    """Check if there are running containers.
    Helper method to determine if some checks should execute.
    """
    cont_ids = []
    cli = self.cli
    running_cont = cli.containers()
    if len(running_cont):
      for cont in running_cont:
        cont_ids.append(cont['Id'])
      return cont_ids
    else:
      logging.error("No running containers!")
      return None

  def check_inspect_value(self,value,dct,*args):
    """Compare a dict entry with a value. Args define depth."""
    key =args[0]
    if key in dct.keys():
      if isinstance(dct[key],dict):
        if len(args) > 1:
          return self.check_inspect_value(value,dct[key],*args[1:])
      elif dct[key] == value:
        return True
      else:
        return False
    else:
      return False

  def process_running(self,proc_name):
    """Check if process is running"""
    procs = psutil.process_iter()
    for proc in procs:
      if (proc.name() == proc_name) :
        cmd = proc.cmdline()
        return cmd
    logging.error("No process named %s.Are you sure %s is running?"\
                                              %(proc_name,proc_name))          
    return None

  def compare_dicts(self,source,exclude):
    """
    Compares keys,values of two dicts and produces a dict with their diff
    """
    diff = defaultdict(list)
    for key in source:
      if key in exclude:
        for port in source[key]:
          if not port in exclude[key]:
            diff[key].append(port)
    return diff

  def version_check(self, ver_soft, ver_ref ):
    """ Compares software version with a given value"""
    ver_num = ver_soft.split('-')[0]
    ver_soft = ver_num.split('.')
    ver_ref = ver_ref.split('.')

    for dgt in range(len(ver_ref)):
      if int(ver_ref[dgt]) > int(ver_soft[dgt]):
        return False
      elif int(ver_ref[dgt]) < int(ver_soft[dgt]):
        return True
      else:
        continue
    return True