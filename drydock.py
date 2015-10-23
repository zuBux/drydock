import argparse
import logging

from audits.host import HostConfAudit
from audits.dock import DockerConfAudit, DockerFileAudit
from audits.containers import ContainerImgAudit, ContainerRuntimeAudit

from utils.confparse import ConfParse
from utils.output import FormattedOutput

def main():
  #Argument parsing.
  confparser = ConfParse()

  parser = argparse.ArgumentParser()
  parser.add_argument("-p", "--profile", help="Audit configuration file")
  parser.add_argument("-o", "--output", help="Output file")
  parser.add_argument("-v", "--verbosity", help="Verbosity level")
  args = parser.parse_args()

  #Verbosity level - Default is ERROR
  if args.verbosity:
    verbosity = args.verbosity
    if verbosity == '1':
      loglevel = logging.ERROR
    elif verbosity == '2':
      loglevel = logging.WARNING
    elif verbosity == '3':
      loglevel = logging.DEBUG
  else:
    loglevel = logging.ERROR
  logging.basicConfig(level=loglevel,\
                    format='%(asctime)s - %(levelname)s - %(message)s')

  # If no profile specified, switch to default
  if args.profile:
    conf = args.profile
    logging.info("Using profile %s" %(conf)) 
  else:
    conf = "conf/default.yml"
    logging.warning("No profile selected. Using default %s" %(conf)) 
  #If no output file is selected, switch to default
  if args.output:
    outfile = args.output
  else:
    outfile = "output.json"

  out = FormattedOutput(outfile)
  profile =confparser.load_conf(conf)

  audit_categories = {'host':HostConfAudit(),
                      'dockerconf': DockerConfAudit(),
                      'dockerfiles': DockerFileAudit(),
                      'container_imgs': ContainerImgAudit(),
                      'container_runtime': ContainerRuntimeAudit(),
                      }
  
  for cat,auditclass in audit_categories.iteritems():
    try:
      auditcat = confparser.select_key(profile,cat)
      audit = auditclass
      audit.run_audits(auditcat)
      out.save_results(cat, audit.logdict)
    except KeyError:
      logging.error("No audit category '%s' defined." %cat)

  out.audit_init_info(conf)
  out.write_file()
  out.terminal_output()

if  __name__ =='__main__':
    main()