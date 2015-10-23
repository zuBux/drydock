import os
import stat
import psutil
import logging
from audit import Audit
from docker import Client
from collections import defaultdict
from utils.decorators import assign_order



class ContainerImgAudit(Audit):
  
  @assign_order(1)     
  def container_user(self):
    """4.1 Create a user for the container"""
    nouser = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        root = self.check_inspect_value(0, info, 'Config', 'User')
        if root == False:
          nouser.append(container)
    except TypeError:
      return None
    if len(nouser):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) running as root "\
                              %len(nouser)
      self.templog['output'] = nouser
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "No container running as root"
      
    return self.add_check_results('container_user')


class ContainerRuntimeAudit(Audit):

  @assign_order(1)
  def verify_apparmor(self):
    """5.1 Verify AppArmor profile"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        noapparmor = self.check_inspect_value('', info, 'AppArmorProfile')
        if noapparmor == True:
          badconts.append(container)
    except TypeError:
      return None
    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) with no AppArmor profile."\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers have AppArmor profiles"

    return self.add_check_results('verify_apparmor')
    
  @assign_order(2)
  def verify_selinux(self):
    """5.2 Verify SELinux security options"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        noselinux = self.check_inspect_value(None, info, \
                                             'HostConfig','SecurityOpt')
        if noselinux == True:
          badconts.append(container)
    except TypeError:
      return None
    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d containers with no SELinux policies."\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers have SELinux policies"

    return self.add_check_results('verify_selinux')

  @assign_order(3)
  def single_process(self):
    """5.3 Verify that containers are running only a single main process"""
    badconts = []
    try:
      for container in self.running:
        processes = self.cli.top(container)['Processes']
        procnames = []
        for process in processes:
          procnames.append(process[7])
        if len(set(procnames)) > 1:
          badconts.append(container)
    except TypeError:
      return None
    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d containers have more than one main process"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers have one main single process"

    return self.add_check_results('single_process')

  @assign_order(4)
  def kernel_capabilities(self):
    """5.4 Restrict Linux Kernel Capabilities within containers"""
    container_caps = {}
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        caps = defaultdict(list)
        capadd = info['HostConfig']['CapAdd']
        capdrop = info['HostConfig']['CapDrop']
        if capadd:
          caps['CapAdd'] = capadd
        if capdrop:
          caps['CapDrop'] = capdrop
        if caps:
          container_caps[container] = caps
    except TypeError:
      return None

    if len(container_caps):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) have bad restart policy"\
                              %len(container_caps)
      self.templog['output'] = container_caps
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers have proper restart policy"

    return self.add_check_results('kernel_capabilities')

  @assign_order(5)
  def privileged_containers(self):
    """5.5 Do not use privileged containers"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        nopriv = self.check_inspect_value(False, info, \
                                             'HostConfig','Privileged')
        if nopriv == False:
          badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d privileged containers found"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "No privileged containers detected."

    return self.add_check_results('privileged_containers')

  @assign_order(6)
  def mounted_hostdirs(self):
    """5.6 Do not mount sensitive host system directories on containers"""
    bad_dirs = [ '/', '/boot', '/etc', '/dev', \
                 '/lib', '/proc', '/sys', '/usr']

    badconts = defaultdict(list)
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        mounts = info['Mounts']
        for mount in mounts:
          if mount['Source'] in bad_dirs and mount['RW'] == True:
            badconts[container].append(mount['Source'])
    except TypeError:
      return None

    if badconts:
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "Sensive dirs mounted with RW"
      self.templog['output'] = [(v, k) for k, v in badconts.iteritems()]
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = 'No sensitive dirs mounted'

    return self.add_check_results('mounted_hostdirs')

  @assign_order(7)
  def ssh_running(self):
    """5.7 Do not run ssh within containers"""
    badconts = []
    try:
      for container in self.running:
        processes = self.cli.top(container)['Processes']
        for process in processes:
          procname = process[7]
        if 'sshd' in procname:
          badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d containers are running ssh"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "No container is running ssh"

    return self.add_check_results('ssh_running')

  @assign_order(8)
  def privileged_ports(self,args):
    """5.8 Do not map privileged ports within containers"""
    exclude = defaultdict(list)
    mappings = defaultdict(list)
    for k,v in args.iteritems():
      exclude[k].append(v)
    try:
      for cont in self.running:
        info = self.cli.inspect_container(cont)
        contimg = info['Image']
        ports = info['Ports']
        for port in ports:
          try:
            pubport = port['PublicPort']
            if pubport < 1024:
              mappings[contimg].append(pubport)
          except KeyError:
            continue
    except TypeError:
      return None

    privports = self.compare_dicts(mappings,exclude)

    if privports:
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "Mapped privileged ports found"
      self.templog['output'] = [(v, k) for k, v in privports.iteritems()]
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = 'No unauthorized privileged ports found'
    return self.add_check_results('privileged_ports')

  @assign_order(9)
  def open_ports(self,hostports):
    """5.9 Open only needed ports on container"""
    exclude = defaultdict(list)
    mappings = defaultdict(list)
    for k,v in hostports.iteritems():
      exclude[k].append(v)
    try:
      for cont in self.running:
        info = self.cli.inspect_container(cont)
        contimg = info['Image']
        ports = info['Ports']
        for port in ports:
          try:
            exp_port = port['PrivatePort']
            mappings[contimg].append(exp_port)
          except KeyError:
            continue
    except TypeError:
      return None

    privports = self.compare_dicts(mappings,exclude)

    if privports:
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "Uneeded exposed ports found"
      self.templog['output'] = [(v, k) for k, v in privports.iteritems()]
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = 'Only needed ports are exposed'
    return self.add_check_results('open_ports')

  @assign_order(10)
  def host_network_mode(self):
    """5.10 Do not use host network mode on container"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        hostmode = self.check_inspect_value('host', info,\
                                            'HostConfig','NetworkMode')
        if hostmode == True:
          badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s)' networking is not containerized"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers are inside a seperate network stack"

    return self.add_check_results('host_network_mode')

  @assign_order(11)
  def memory_usage_limit(self):
    """5.11 Limit memory usage for container"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        nolimit = self.check_inspect_value(0, info, 'HostConfig','Memory')
        if nolimit == True:
          badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) have no memory limits"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers have memory limits in place"

    return self.add_check_results('memory_usage_limit')

  @assign_order(12)
  #1024 also means no shares.SHOULD FIX
  def cpu_priority(self):
    """5.12 Set container CPU priority appropriately"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        noshares = self.check_inspect_value(0, info, 'HostConfig','CpuShares')
        if noshares == True:
          badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) have no CPU shares set"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers have CPU shares in place"

    return self.add_check_results('cpu_priority')

  @assign_order(13)
  def readonly_root_fs(self):
    """5.13 Mount container's root filesystem as read-only"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        noreadonly = self.check_inspect_value(False, info, \
                                              'HostConfig','ReadonlyRootfs')
        if noreadonly == True:
          badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) have writable root FS"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers have read-only root FS"

    return self.add_check_results('readonly_root_fs')

  @assign_order(14)
  def bind_host_interface(self):
    """5.14 Bind incoming container traffic to a specific host interface"""
    mappings = defaultdict(list)
    try:
      for cont in self.running:
        info = self.cli.inspect_container(cont)
        contimg = info['Image']
        ports = info['Ports']
        for port in ports:
          try:
            hostip = port['IP']
            if hostip == '0.0.0.0':
              pubport = port['PublicPort']
              mappings[contimg].append(pubport)
          except KeyError:
            continue
    except TypeError:
      return None

    if mappings:
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "Containers listen to any host interface"
      self.templog['output'] = [(v, k) for k, v in mappings.iteritems()]
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = 'Traffic bound to specific host interface'
    return self.add_check_results('bind_host_interface')

  @assign_order(15)
  def failure_restart_policy(self):
    """5.15 Set the 'on-failure' container restart policy to 5"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        restartpol = info['HostConfig']['RestartPolicy']['Name']
        if restartpol == 'always':
          badconts.append(container)
        elif restartpol == 'on-failure':
          retries = info['HostConfig']['RestartPolicy']['MaximumRetryCount']
          if retries > 5:
            badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) have bad restart policy"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers have proper restart policy"

    return self.add_check_results('failure_restart_policy')

  @assign_order(16)
  def host_process_namespace(self):
    """5.16 Do not share the host's process namespace"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        hostproc = self.check_inspect_value('host', info, \
                                              'HostConfig','PidMode')
        if hostproc == True:
          badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) share host's process namespace"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers' process namespace is isolated"
    return self.add_check_results('host_process_namespace')

  @assign_order(17)
  def host_ipc_namespace(self):
    """5.17 Do not share the host's IPC namespace"""
    badconts = []
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        hostipc = self.check_inspect_value('host', info, \
                                              'HostConfig','IpcMode')
        if hostipc == True:
          badconts.append(container)
    except TypeError:
      return None

    if len(badconts):
      self.templog['status'] = 'Fail'
      self.templog['descr'] = "%d container(s) share host's process namespace"\
                              %len(badconts)
      self.templog['output'] = badconts
    else:
      self.templog['status'] = 'Pass'
      self.templog['descr'] = "All containers' process namespace is isolated"
    return self.add_check_results('host_ipc_namespace')

  @assign_order(18)
  def expose_host_devices(self):
    """5.18 Do not directly expose host devices to containers"""
    containers_exposed = defaultdict(list)
    try:
      for container in self.running:
        info = self.cli.inspect_container(container)
        devices = info['HostConfig']['Devices']
        if devices:
          containers_exposed[container] = devices
    except TypeError:
      return None

    if containers_exposed:
      self.templog['descr'] = "Host devices are exposed to %d container(s)"\
                              %len(containers_exposed)
      self.templog['output'] = [(v, k) \
                                for k, v in containers_exposed.iteritems()]
    else:
      self.templog['descr'] = "No host devices exposed to containers"
    return self.add_check_results('expose_host_devices')