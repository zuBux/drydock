import os
import sys
import logging
import psutil
from docker import Client
from collections import defaultdict

BASE_URL = 'unix://var/run/docker.sock'

class Audit(object):

  def __init__(self):
    #logdict stores the results of the audit category,
    #templog is a temp dict which stores the result of each check
    #and gets cleared after each check
    self.logdict = {}
    self.templog = {}

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
      if type(argument) == dict:
        for key,value in argument.iteritems():
          args.append(value)
    try:
      return getattr(self,func)(*args)
    except AttributeError:
      return logging.error("No audit named %s" %(func))

  def run_audits(self,audits):
    for audit in audits:
      if (type(audit) == str):
        logging.debug("Running %s with no args" %audit)
        res = self.call(audit)
        self.add_check_results(audit,res)
      else:     
        logging.debug("Running %s with args %s" \
                      %(audit.keys()[0], audit.values()))
        res = self.call_with_args(audit)
        self.add_check_results(audit.keys()[0],res)
    return 

  def add_check_results(self,audit_name,results):
    """Adds audit results to output dict"""
    self.logdict[audit_name] = results
    self.templog = {}
    return

  def running_containers(self):
    """Check if there are running containers.
    Helper method to determine if some checks should execute.
    """
    cont_ids = []
    cli = self.cli
    try:
      running_cont = cli.containers()
    except:
      logging.error("Unable to connect to docker host. \
                    Verify that current user has permissions to use %s\
                    Aborting audit..." %(BASE_URL))
      sys.exit(0)

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
    for key in source.keys():
      if key in exclude.keys():
        for port in source[key]:
          if port in exclude[key]:
            source.pop(key,None)
    return source

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