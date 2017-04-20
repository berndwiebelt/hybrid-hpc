#!/usr/bin/env python
#
# monitorVM by Konrad Meier
# konrad.meier@rz.uni-freiburg.de 
# version 0.1
#
import os,sys,logging,re
import argparse
import signal
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
        var['pbs-jobid'] = os.getenv("PBS_JOBID")
    if var['pbs-jobid'] is None:
        logger.error("ERROR: Environment Variable PBS_JOBID not found!")
        exit(1)

    return var


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


def main(var):
    """Main function to monitor the VM"""
    var = getEnvironmentVars(var)

    # Connect to the local libvirtd socket read only
    conn = libvirt.openReadOnly("qemu:///system")
    if conn == None:
        logger.error("Failed to open connection to the hypervisor")
        sys.exit(1)
    domainIDs = conn.listDomainsID()


    result=runCmd("checkjob --xml " + var['pbs-jobid'])
    moabVars = getMoabVars(result)

    # We need the libvirtd instance_name for monitoring 
    if 'VM_NAME' in moabVars:
        instance_name = moabVars['libvirtName']
    else:
        logger.error("VM_NAME not found in Moab Job Metadata")
        exit(1)

    logger.info("VM instance_name=%s", instance_name)

    logger.info("VM is ACTIVE -> continue Monitoring via libvirtd")
    try:
        domain = conn.lookupByName(instance_name)
    except:
        logger.error("ERROR: unable to find VM in libvirt! Name=%s", instance_name)
        # In this case the VM musst be terminated in OpenStack.
        # Possible reason: the VM was started on a wrong Compute-Node
        #deleteVM(nova, vm)
        exit(1)

    while True:
        try:
            state, reason =  domain.state()
        except:
            logger.info("Domain vanished: asuming it was terminated in OpenStack")
            break

        if state == libvirt.VIR_DOMAIN_RUNNING:
            logger.info("The state is VIR_DOMAIN_RUNNING")
        elif state == libvirt.VIR_DOMAIN_SHUTDOWN:
            logger.info("The state is VIR_DOMAIN_SHUTDOWN")
            break
        elif state == libvirt.VIR_DOMAIN_SHUTOFF:
            logger.info("The state is VIR_DOMAIN_SHUTOFF")
            break
        elif state == libvirt.VIR_DOMAIN_CRASHED:
            logger.info("The state is VIR_DOMAIN_CRASHED")
            break
        else:
            logger.info("The libvirtd state is unknown.")
            break
        logger.debug("The reason code is %s", str(reason))
        time.sleep(30)
        if shutdown_flag.isSet():
            logger.debug("Shutdown-Event: Exit main loop")
            break

    logger.info("Monitoring is finished. Exit")

    return 
  
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Monitors a local Virtual Machine.",
                                                 argument_default=argparse.SUPPRESS)
    
    parser.add_argument("--debug-level", dest="debug-level", type=str, default="DEBUG", help="Debug level: DEBUG INFO WARNING ERROR CRITICAL")
    parser.add_argument("--vm-name", dest="vm-name", default=None, type=str, help="Name of the VM in OpenStack")
    parser.add_argument("--pbs-jobid", dest="pbs-jobid", default=None, type=str, help="Compute-Job ID (WARNING: Only for development or debug)")
    
    args = vars(parser.parse_args())


    # Configure logging
    log_fmt = '%(asctime)s %(message)s'
    logging.basicConfig(stream=sys.stdout, format=log_fmt)
    logger = logging.getLogger()
    logger.setLevel(getattr(logging,args['debug-level']))
    
    logger.info("-- Monitor VM Script --")

    # register signal handler to intercept SIGHUP
    # this is needed to terminate the VM if the job wall-time is over
    orig_sighandler = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, signal_handler)
    
    shutdown_flag = threading.Event()
    
    print args
    logger.debug("CMD args:" + str(args))
    main(args)
