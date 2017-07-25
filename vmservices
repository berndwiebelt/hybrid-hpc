#!/usr/bin/env python
#
# version 0.3
#

#from novaclient.v1_1 import client
from pprint import pprint
import re
import subprocess
import os_client_config
from novaclient import exceptions as nova_except
#import novaclient.exceptions,requests.exceptions
import sys,os,logging,threading
import ConfigParser

monitorVM_conf = "/usr/local/etc/monitorVM.conf"

def getID(name):
    id = name.replace("moab_vm_", "").split(".")
    
    return id[0]

def isJobID(string):
   
    if re.match("^[0-9][0-9\[\]]*$", string):
        return True
    else:
        return False

def main():
    #global flavor,logger,shutdown_flag

    # Get configuration from config-file
    config = ConfigParser.ConfigParser()
    config.read(monitorVM_conf)
    os_username = config.get("OPENSTACK", "USERNAME")
    os_password = config.get("OPENSTACK", "PASSWORD")
    os_tenant_name = config.get("OPENSTACK", "TENANT_NAME")
    os_tenant_id = config.get("OPENSTACK", "TENANT_ID")
    os_auth_url = config.get("OPENSTACK", "AUTH_URL")
    cluster_zone = config.get("CLUSTER", "ZONE")
    debug_level = config.get("DEFAULT", "DEBUG_LEVEL")

    # Configure logging
    log_fmt = '%(asctime)s %(message)s'
    logging.basicConfig(stream=sys.stdout, format=log_fmt)
    logger = logging.getLogger()
    logger.setLevel(getattr(logging,debug_level))

    logger.info("-- Monitor VM Script --")

    logger.info("Connecting to OpenStack ...")
    #nova = client.Client(
    #        username=os_username,
    #        api_key=os_password,
    #        project_id=os_tenant_name,
    #        auth_url=os_auth_url,
    #        timeout=120.0,
    #        #http_log_debug=True,
    #        connection_pool=True)

    nova = os_client_config.make_client('compute',
                                        auth_url=os_auth_url,
                                        username=os_username,
                                        password=os_password,
                                        project_name=os_tenant_name,
                                        region_name="NEMO-Cluster",
                                        user_domain_name='Default',
                                        project_domain_name='Default',
                                        timeout=600.0,
                                        connection_pool=True)

    #print nova # TODO

    # Get all VMs from OpenStack
    vms = nova.servers.list(search_opts={'all_tenants': 1})

    
    # Get all Jobs from Scheduler
    #jobs = subprocess.check_output("showq -r | awk '{print $1}'|tail -n +5| head -n -6", shell=True)
    #proc = subprocess.Popen("showq -r | awk '{print $1}'|tail -n +5| head -n -6", shell=True, stdout=subprocess.PIPE)
    proc = subprocess.Popen("qstat -r -l |tail -n +6 | awk '{print $1}'", shell=True, stdout=subprocess.PIPE)
    #proc.wait()
    
    stdout = proc.communicate()[0].split(b'\n')
    #out = stdout.decode().split('/n')
    if proc.returncode != 0:
        logger.error("ERROR: Unable to get running Job from Moab! -> EXIT")
        exit(1)

    jobs_list = []
    for line in stdout:
        l = line.decode().rstrip()
        job = l.split(".")[0]
        
        if isJobID(job):
            jobs_list.append(job)
        elif line == '':
            continue
        else:
            logger.error("ERROR: Job-ID List from Moab is not valid! Value is: %s", job)
            exit(1)
    
    if len(jobs_list) == 0:
        logger.error("No Moab-Jobs found! -> EXIT")
        exit()

    #print jobs_list
    #print vms
    #exit()

    for vm in vms:
        #print vm.name
        id = getID(vm.name)
        zone = vm._info['OS-EXT-AZ:availability_zone']
        #print zone, COMPUTE_ZONE
        if zone == cluster_zone:
            if id in jobs_list:
                logger.info("VM ok: %s", vm.name)
            elif "moab_job_id" in vm.metadata and getID(vm.metadata["moab_job_id"]) in jobs_list:
                logger.info("VM ok: %s", vm.name)
            else:
                logger.warning("WARNING: VM not found in Moab: %s", vm.name)
                logger.warning("WARNING: Deleting VM: %s", vm.name)
                try:
                    vm.delete()
                except:
                    logger.error("ERROR: VM-Delete failed: %s", vm.name)
                logger.warning("WARNING: VM Terminated: %s", vm.name)
        else:
            logger.info("VM \"%s\" not on zone=%s -> ignored", vm.name, cluster_zone)

    logger.info("Monitor run finished!")
    exit()

if __name__ == '__main__':
    main()
