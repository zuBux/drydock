import yaml
import sys
import logging

class ConfParse:

  def load_conf(self,conf):
    """ 
    Loads and parses an audit category from a configuration file
    """
    try:
      with open(conf) as conf:
        profile = yaml.load(conf)
    except IOError:
      logging.error("Invalid file specified: %s" %(conf)) 
      sys.exit(0)
    return profile

  def select_key(self,prof,key):
    return prof[key]
