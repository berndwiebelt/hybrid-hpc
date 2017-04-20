#!/usr/bin/env python
#
# startVM by Konrad Meier
# konrad.meier@rz.uni-freiburg.de 
# version 0.5
#
import os,sys,logging,re
import ConfigParser
import argparse
import signal
import os_client_config
from novaclient import exceptions as nova_except
from requests import exceptions as request_except
import subprocess
import time
import threading
from pprint import pprint
import libvirt
import xml.etree.ElementTree as ET
         
def signal_handler(sig, frame):
    """Signal Handler for the SIGTERM from pbs_mom"""
    global shutdown_flag, orig_sighandler
    signal.signal(signal.SIGTERM, signal.SIG_IGN)  # Disable SIGTERM
    logger.warning("SIGTERM received! Normally this triggered by the walltime limit.")
    shutdown_flag.set()
    return


def getEnvironmentVars(var):
    """Read the environment variables"""

    if var['pbs-jobid'] is None:
        var['pbs-jobid'] = os.getenv("MOAB_JOBID")
    if var['pbs-jobid'] is None:
        logger.error("ERROR: Environment Variable MOAB_JOBID not found!")
        exit(1)

    return var


def getVM(nova, vm_):
    """return the new VM Object"""
    try:
        vm = nova.servers.get(vm_)
    except nova_except.NotFound:
        logger.error("ERROR: VM disappeared => stop")
        exit(1)
    except request_except.ConnectionError as message:
        logger.warning("WARNING: nova-api - servers.get(vm): %s", message)
        # in this case we return the old vm object
    except Exception as ex:
        logger.error("ERROR: nova-api - servers.get(vm): %s", ex)
        # in this case we return the old vm object
    return vm


def runCmd( cmd ):

    p = subprocess.Popen(cmd, env=dict(os.environ), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # get stderr and stdout, and wait for the process to complete
    # which should return list of applications and their status

    (out,err) = p.communicate()
    while p.returncode is None:
        time.sleep(1)

    # convert to dictionary and return

    #result = { "out": out.decode(), "err": err.decode(), "exitcode": p.returncode }
    result = { "out": re.sub(u"(\u2018|\u2019)", "'",out.decode()), "err": re.sub(u"(\u2018|\u2019)", "'",err.decode()), "exitcode": p.returncode }

    return( result )


def getMoabVars( xml ):

    jobVars = {}
    if not xml["err"]:
        xml = ET.fromstring(xml["out"])
        checkjob = {}

        for job in xml.findall('job'):
            for variables in job.findall('Variables'):
                for v in variables.findall('Variable'):
                    jobVars[v.attrib['name']] = v.text

        return jobVars
    else:
        return {}


def deleteVM(nova, vm):
    """Delete the VM. In case of an error try it again."""

    success = False
    while not success:
        try:
            logger.debug("Call vm.delete")
            vm.delete()
            time.sleep(1)
            #pprint(vars(nova.servers.get(vm)))
            success = True
        except nova_except.NotFound:
            logger.error("ERROR: VM disappeared => stop")
            break
        except request_except.ConnectionError as message:
            logger.warning("WARNING: nova-api - vm.delete(): %s", message)
        except Exception as ex:
            logger.error("ERROR: nova-api - servers.get(vm): %s", ex)
        
    logger.info("INFO: VM terminated")
    return


def main(var):
    """Main function to start and monitor the VM"""
    vm = None
    var = getEnvironmentVars(var)


    result=runCmd("/opt/moab/bin/checkjob --xml " + var['pbs-jobid'])
    moabVars = getMoabVars(result)

    logger.info("Connecting to OpenStack ...")
   
    nova = os_client_config.make_client('compute',
                                        auth_url=var['os-auth-url'],
                                        username=var['os-username'],
                                        password=var['os-password'],
                                        project_name=var['os-project-name'],
                                        region_name=var['os-region-name'],
                                        user_domain_name='Default',
                                        project_domain_name='Default',
                                        timeout=600.0,
                                        connection_pool=True)
    
    
    logger.info("Get nova vm by id=%s", moabVars['VM-ID'])
    vm = nova.servers.get(moabVars['VM-ID'])
    
    logger.info("Terminating VM...")
    deleteVM(nova, vm)
    logger.info("Job finished!")

    return 
  
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Delete OpenStack Virtual Machine.",
                                                 argument_default=argparse.SUPPRESS)

    parser.add_argument("--config-file", dest="config-file", type=str, default="startVM.conf", help="startVM config file")
    parser.add_argument("--key-file", dest="key-file", default=None, type=str, help="startVM Key-File for OpenStack username/password or token")
    parser.add_argument("--debug-level", dest="debug-level", type=str, default="INFO", help="Debug level: DEBUG INFO WARNING ERROR CRITICAL")

    parser.add_argument("--os-auth-url", dest="os-auth-url", default=os.environ.get('OS_AUTH_URL', None), type=str, help="startVM config file")
    parser.add_argument("--os-username", dest="os-username", default=os.environ.get('OS_USERNAME', None), type=str, help="Username to login with")
    parser.add_argument("--os-password", dest="os-password", default=os.environ.get('OS_PASSWORD', None), type=str, help="Password to login with")
    parser.add_argument("--os-project-name", dest="os-project-name", default=os.environ.get('OS_PROJECT_NAME', None), type=str, help="project name to scope to")
    parser.add_argument("--os-project-id", dest="os-project-id", default=os.environ.get('OS_PROJECT_ID', None), type=str, help="project name to scope to")
    parser.add_argument("--os-region-name", dest="os-region-name", default=os.environ.get('OS_REGION_NAME', None), type=str, help="Authentication region name")

    parser.add_argument("--pbs-jobid", dest="pbs-jobid", default=None, type=str, help="Compute-Job ID (WARNING: Only for development or debug)")

    
    args = vars(parser.parse_args())
    
    
    location = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    config = ConfigParser.ConfigParser()
    if os.path.isfile(args['config-file']):
        config.read(args['config-file'])
    elif os.path.isfile("/root/startVM.conf/startVM.conf"):
        config.read("/root/startVM.conf/startVM.conf") 
    else:
        print "Config-File not found!"
        exit(1)

    if args['os-auth-url'] is None: 
        args['os-auth-url'] = config.get("OPENSTACK", "AUTH_URL")
    if args['key-file'] is None: 
        args['key-file'] = config.get("OPENSTACK", "KEY_FILE")
    if args['os-project-name'] is None:
        args['os-project-name'] = config.get("OPENSTACK", "PROJECT_NAME")
    if args['os-project-id'] is None:
        args['os-project-id'] = config.get("OPENSTACK", "PROJECT_ID")
    if args['os-region-name'] is None:
        args['os-region-name'] = config.get("OPENSTACK", "REGION")
    #if args['image-id'] is None:
    #    args['image-id'] = config.get("VM", "IMAGE_ID")
    #if args['image-name'] is None:
    #    args['image-name'] = config.get("VM", "IMAGE_NAME")
    #if args['key-name'] is None:
    #    args['key-name'] = config.get("VM", "KEYNAME")
    #if args['security-group'] is None:
    #    args['security-group'] = config.get("VM", "SECURITY_GROUP")
    #if args['availability-zone'] is None:
    #    args['availability-zone'] = config.get("CLUSTER", "AVAILABILITY_ZONE")
    #if args['vm-name-is-ip'] is None:
    #    if config.get("VM", "VM_NAME_IS_IP") in ['true', 'True', 'yes', 'Yes', '1', 'y', 'Y']:
    #        args['vm-name-is-ip'] = True
    #    else:
    #        args['vm-name-is-ip'] = False
    #os_tenant_id = config.get("OPENSTACK", "TENANT_ID")
    #debug_level = config.get("DEFAULT", "DEBUG_LEVEL")
    #args['vm-name-prefix'] = config.get("VM", "VM_NAME_PREFIX")

    configKey = ConfigParser.ConfigParser()
    
    
    if os.path.isfile(args['key-file']):
        configKey.read(args['key-file'])
    elif os.path.isfile("/root/startVM.conf/" + args['key-file']):
        configKey.read("/root/startVM.conf/" + args['key-file']) 
    else:
        log.error("Key-File not found!")
        exit(1)
    if args['os-username'] is None: 
        args['os-username'] = configKey.get("KEY", "USERNAME")
    if args['os-password'] is None:
        args['os-password'] = configKey.get("KEY", "PASSWORD")
    

    # Configure logging
    log_fmt = '%(asctime)s %(message)s'
    logging.basicConfig(stream=sys.stdout, format=log_fmt)
    logger = logging.getLogger()
    logger.setLevel(getattr(logging,args['debug-level']))
    
    logger.info("-- delete VM Script --")

    # register signal handler to intercept SIGHUP
    # this is needed to terminate the VM if the job wall-time is over
    orig_sighandler = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, signal_handler)
    
    shutdown_flag = threading.Event()
    
    #print args
    main(args)
