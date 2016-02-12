import sys
import os
import json
import logging
from collections import OrderedDict
from datetime import datetime
from colorama import init, Fore, Back, Style
from junit_xml import TestSuite, TestCase

from audits.host import HostConfAudit
from audits.dock import DockerConfAudit, DockerFileAudit
from audits.containers import ContainerImgAudit, ContainerRuntimeAudit

class FormattedOutput:

  def __init__(self,outfile,**kwargs):
    self.output = outfile
    self.log = {}
    self.audit_categories = {}
    for key in kwargs:
      self.audit_categories[key] = kwargs[key]

  def audit_init_info(self,profile):
    info = {}
    (passed, total) = self.get_score()

    info['date'] = str(datetime.now())
    info['profile'] = profile
    info['score'] = "%s/%s" %(passed,total)
    self.log['info'] = info

  def save_results(self,name,res):
    self.log[name] = res

  def write_file(self):
    if os.path.isfile(self.output):
      logging.warn("File exists,deleting...")
      os.remove(self.output)
    with open(self.output,'a') as f:
      json_data = json.dumps(self.log,sort_keys=True,
                 indent=4, separators=(',', ': '))
     # print json_data
      f.write(json_data)

  def write_xml_file(self):
    test_cases = []
    if os.path.isfile(self.output):
      logging.warn("File exists,deleting...")
      os.remove(self.output)
    with open(self.output,'a') as f:
      for _, elements in self.log.items():
        for j in elements.viewitems():
          if j[0] == 'date' or j[0] == 'profile' or j[0] == 'score':
            # we really don't care
            pass
          else:
            try:
              test_case = TestCase(j[0], j[1]['descr'], '', '', '')
              if j[1]['status'] == 'Fail':
                test_case.add_failure_info(j[1]['output'])
              else:
                test_case = TestCase(j[0], '', '', '', '')
              test_cases.append(test_case)
            except KeyError:
              # the world's smallest violin playin' for KeyError
              pass
      ts = [TestSuite("Docker Security Benchmarks", test_cases)]
      TestSuite.to_file(f, ts)

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
        except TypeError:
          continue
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
    except TypeError:
      pass
    print "Description: " + results['descr']
    try:
      res = str(results['output'])
      print "Output: "
      print(Style.DIM + res + Style.RESET_ALL)
    except KeyError:
      pass
    print "\n"

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

    print '''drydock v0.3 Audit Results\n==========================\n'''
    # Print results
    for cat, catdescr in auditcats.iteritems():
      cat_inst = self.audit_categories[cat]
      try:
        if output[cat]:
          audits = self.create_ordereddict(output[cat],cat)
          print(Style.BRIGHT + "\n" + catdescr + "\n" + \
                '-'*len(catdescr) + '\n'+ Style.RESET_ALL)
          for audit in audits.keys():
            results = output[cat][audit]
            descr = getattr(cat_inst,audit).__doc__
            print( descr + '\n' + '-'*len(descr) )
            self.print_results(results)
      except KeyError:
        logging.warn("No audit category %s" %auditcats[cat])
        continue

    # Print Overview info for the audit
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
