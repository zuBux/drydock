import sys
import os
import json
import logging
from collections import OrderedDict
from datetime import datetime
from colorama import init, Fore, Back, Style

from audits.host import HostConfAudit
from audits.dock import DockerConfAudit, DockerFileAudit
from audits.containers import ContainerImgAudit, ContainerRuntimeAudit

class FormattedOutput:

  def __init__(self,outfile):
    self.output = outfile
    self.log = {}
    self.audit_categories = {'host':HostConfAudit(),
                  'dockerconf': DockerConfAudit(),
                  'dockerfiles': DockerFileAudit(),
                  'container_imgs': ContainerImgAudit(),
                  'container_runtime': ContainerRuntimeAudit(),
                  }
    init()

  def audit_init_info(self,profile):
    info = {}
    (passed, total) = self.get_score()

    info['date'] = str(datetime.now())
    info['profile'] = profile
    info['score'] = "%s/%s" %(passed,total)
    self.log['info'] = info
    return
    
  def save_results(self,name,res):
    self.log[name] = res
    return

  def write_file(self):
    if os.path.isfile(self.output):
      logging.warn("File exists,deleting...")
      os.remove(self.output)
    with open(self.output,'a') as f:
      json_data = json.dumps(self.log,sort_keys=True,
                 indent=4, separators=(',', ': '))
     # print json_data
      f.write(json_data)
    return
  
  def get_score(self):
    """
    Calculates benchmark score by taking account 
    results containing 'status' key
    """
    allchecks = 0
    passed = 0
    for cat,check in self.log.iteritems():
      for result in check.iteritems():
        try:
          if (result[1]['status'] == 'Pass'):
            passed = passed +1
            allchecks = allchecks +1
          else :
            allchecks = allchecks +1
        except KeyError:
          continue
    return passed, allchecks

  def print_results(self,results):
    try:
      if results['status'] == 'Pass':
        print ("Status: " + Fore.GREEN + 'Pass' + Fore.RESET)
      elif results['status'] == 'Fail':
        print ("Status: " + Fore.RED + 'Fail' + Fore.RESET)
    except KeyError:
      pass
    print "Description: " + results['descr']
    try:
      res = str(results['output'])
      print "Output: "
      print(Style.DIM + res + Style.RESET_ALL)
    except KeyError:
      pass
    print "\n"
    return None

  def create_ordereddict(self,dct,auditcat):
    """Creates a sorted dict of audits from an unsorted one"""
    tempdict = {}
    auditclass = self.audit_categories[auditcat]
    for key in dct.keys():
      order = getattr(auditclass,key).order
      tempdict[key] = order
    ordered = OrderedDict(sorted(tempdict.items(), key=lambda t: t[1]))
    return ordered

  def terminal_output(self):
    output = self.log
    tempdict = {}
    auditcats = {'host': '1.Host Configuration',
                 'dockerconf': '2.Docker Daemon Configuration',
                 'dockerfiles': '3.Docker daemon configuration files',
                 'container_imgs': '4.Container Images and Build File',
                 'container_runtime': '5.Container Runtime',
                 }

    print '''drydock v0.2 Audit Results\n==========================\n'''
    #Print Overview info for the audit
    print(Style.BRIGHT + "Overview\n--------" +Style.RESET_ALL)
    print('Profile: ' + output['info']['profile'])
    print('Date: ' + output['info']['date'])
    success,total = output['info']['score'].split('/')
    success = float(success)
    total = float(total)
    if 0 <= success/total <= 0.5:
      print('Score: ' + Fore.RED + output['info']['score'] + Fore.RESET)
    elif 0.5 < success/total <= 0.8:
      print('Score: ' + Fore.YELLOW + output['info']['score'] + Fore.RESET)
    else:
      print('Score: ' + Fore.GREEN + output['info']['score'] + Fore.RESET)
    #Print results
    for cat, catdescr in auditcats.iteritems():
      cat_inst = self.audit_categories[cat]
      if output[cat]:
        audits = self.create_ordereddict(output[cat],cat)
        print(Style.BRIGHT + "\n" + catdescr + "\n" + \
              '-'*len(catdescr) + '\n'+ Style.RESET_ALL)
        for audit in audits.keys():
          results = output[cat][audit]
          descr = getattr(cat_inst,audit).__doc__
          print( descr + '\n' + '-'*len(descr) ) 
          self.print_results(results)