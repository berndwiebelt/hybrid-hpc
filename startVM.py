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
from subprocess import call, check_output
import time
import threading
from pprint import pprint
import libvirt

         
def signal_handler(sig, frame):
    """Signal Handler for the SIGTERM from pbs_mom"""
    global shutdown_flag, orig_sighandler
    signal.signal(signal.SIGTERM, signal.SIG_IGN)  # Disable SIGTERM
    logger.warning("SIGTERM received! Normally this triggered by the walltime limit.")
    shutdown_flag.set()
    return

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


def getEnvironmentVars(var):
    """Read the environment variables"""
    if var['compute-hostname'] is None:
        var['compute-hostname'] = os.getenv("MOAB_NODELIST")
    if var['compute-hostname'] is None:
        logger.error("ERROR: Environment Variable HOSTNAME not found!")
        exit(1)
    logger.info("Job executed on Host: %s", var['compute-hostname'])

    if var['np'] is None:
        var['np'] = os.getenv("PBS_NP")
    if var['np'] is None:
        logger.warning("Warning: PBS_NP not set! Number of CPUs set to 1.")
        var['np'] = 1
    logger.info("Number of requested CPUs: %s", var['np'])

    if var['pbs-jobid'] is None:
        var['pbs-jobid'] = os.getenv("MOAB_JOBID")
    if var['pbs-jobid'] is None:
        logger.error("ERROR: Environment Variable PBS_JOBID not found!")
        exit(1)

    # TODO  Walltime is not provided!
    #if var['pbs-walltime'] is None:
    #    var['pbs-walltime'] = os.getenv("PBS_WALLTIME")
    #if var['pbs-walltime'] is None:
    #    logger.warning("Warning: PBS_WALLTIME not set!")
    #    exit(1)
    #logger.info('Walltime of the VM in seconds: %s', var['pbs-walltime'])

    # get job memory
    if var['mem'] is None:
       var['mem'] = os.getenv("vm-mem")
    if var['mem'] is None:
        logger.error("ERROR: Environment Variable vm-mem not found!")
    
    #if var['mem'] is None:
    #    logger.info("Get Job Memory from pbs")
    #    
    #    command = ["qstat", "-f", var['pbs-jobid']] # +" | grep req_information.memory.0 | awk {' print $3 '}"
    #    mem_string = "req_information.memory.0"
    #    #command = ["ls", "-la"]
    #    logger.debug("system command: %s", command)
    #    try:
    #        #print command
    #        out = check_output(command)
    #        #pprint(vars(out))
    #        logger.debug("pbs output: %s", out)
    #    except:
    #        logger.error("ERROR - failed to get memory from pbs")
    #        exit(1)
    #    #var['mem'] = out
    #    if mem_string in out:
    #        out = out[out.find(mem_string)+len(mem_string):]
    #        out = out[3:out.find("\n")]
    #        logger.debug("mem info: %s", out) 
    #        var['mem'] = int(out[:-2])/1024
    #    else:
    #        logger.error("ERROR - failed to parse memory string from pbs output")
    logger.info('RAM requested: %s MB', var['mem'])
    
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

def getVMnet(var):
    logger.info("Converting VM Name to VM IP")
    pos = re.search("\d", var['vm-name'])
    vm_ip = var['vm-name'].replace('-', '.')[pos.start():]
    logger.info("VM IP is set to: %s", vm_ip)
    neutron = os_client_config.make_client('network',
                                    auth_url=var['os-auth-url'],
                                    username=var['os-username'],
                                    password=var['os-password'],
                                    project_name=var['os-project-name'],
                                    region_name=var['os-region-name'],
                                    user_domain_name='Default',
                                    project_domain_name='Default',
                                    timeout=600.0,
                                    connection_pool=True)
    network = neutron.list_networks(tenant_id=var['os-project-id'])
    network_id = network['networks'][0]['id']
    logger.info("Neutron Network ID is: %s", network_id)
     
    return [{'net-id': network_id, 'v4-fixed-ip': vm_ip}]

def getImageID(nova ,var):
    try:  
        image = nova.images.find(name=var['image-name'])
    except nova_except.NotFound:
        logger.error("ERROR: IMAGE_NAME not found!")
        exit(1)
    except nova_except.NoUniqueMatch:
        logger.error("ERROR: IMAGE_NAME not unique. More than one Image found.")
        exit(1)
    logger.info("Found Image-ID: %s ", image.id)    
    return image.id

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
    returnCode = 0
    var = getEnvironmentVars(var)

    zone_host = "%s:%s" % (var['availability-zone'], var['compute-hostname'])
    logger.info("Start of VM in %s (zone:host)" % zone_host)

    if var['vm-name'] is None:
        var['vm-name'] = var['vm-name-prefix'] + var['pbs-jobid']

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
    
    # get the flavor from the nova-api
    logger.info("OpenStack Flavors: %s", nova.flavors.list())
    try:
        os_flavor = nova.flavors.find(vcpus=int(var['np']),ram=int(var['mem']))
    except request_except.ConnectionError as message:
        logger.error("ERROR: Nova API - flavors.find: %s", message)
        exit(1)
    except Exception as ex:
        logger.error("ERROR: Nova API - flavors.find: %s", ex)
        exit(1)
    logger.info("Flavor found: %s", os_flavor.name) 

    # if required get the IP and network ID to set a specific IP address 
    if var['vm-name-is-ip'] is True:
        nic = getVMnet(var)
    else:
        nic = None
        
    if var['image-id'] is None or var['image-id'] == "":
        logger.info("No Image-ID given. Convert Image-Name to Image-ID.")
        var['image-id'] = getImageID(nova, var)
    # start the new VM
    logger.info("Starting new VM ...")

    #meta_data = {"Wall Time": var['pbs-walltime'], "moab_job_id": var['pbs-jobid']}
    meta_data = {"moab_job_id": var['pbs-jobid']}    

    logger.info("VM metadata: %s", meta_data)
        
    try:
        vm = nova.servers.create(name=var['vm-name'],
                                 image=var['image-id'],
                                 flavor=os_flavor,
                                 nics=nic,
                                 meta=meta_data,
                                 security_groups={var['security-group']},
                                 #userdata=user_data,
                                 key_name=var['key-name'],
                                 availability_zone=zone_host)
    except Exception as ex:
        logger.error("ERROR: Nova API - server.create: %s", ex)
        exit(1)
    logger.info("VM started! ID=%s", vm.id)
    #pprint(vars(vm))
        
    # Only works for a VM with a single Network
    while len(vm.networks) == 0:
        logger.info("Wait for VM-Network...")
        time.sleep(1)
        vm = getVM(nova, vm)
        if (vm.status == "SHUTOFF") or (vm.status == "ERROR"):
            returnCode = 1
            #pprint(vm)
            break
    vm_ip = ""
    if len(vm.networks) != 0:
        vm_ip = vm.networks.itervalues().next()[0]
        logger.info("Found VM-IP: %s", vm_ip)

    if vm_ip != "":
        logger.info("Update Job Metadata in Moab:")
        command = ["mjobctl", "-m var+=VM_IP=" + vm_ip + ",VM-ID=" + vm.id, var['pbs-jobid']]
        logger.debug("mjobctl command: %s", command)
        try:
            call(command)
        except:
            logger.error("ERROR - failed command: ", command)

    # Connect to the local libvirtd socket read only
    conn = libvirt.openReadOnly("qemu:///system")
    if conn == None:
        log.error("Failed to open connection to the hypervisor")
        sys.exit(1)
    domainIDs = conn.listDomainsID()

    # This ist the Main loop.
    # 1. poll the VM via OpenStack-API until the VM is "ACTIVE"
    # 2. poll the VM via libvirtd
    logger.info("Waiting for VM to shutdown ...")
    while True:
        vm = getVM(nova, vm)
        logger.info("VM-Status: %s", vm.status)
        if vm.status == "ACTIVE":
            logger.info("VM is ACTIVE")
            break
        if vm.status == "SHUTOFF":
            logger.info("VM is Shutoff")
            break
        elif vm.status == "ERROR":
            logger.warning("VM is in ERROR-State.")
            returnCode = 1
            break
        if shutdown_flag.isSet():
            logger.debug("Shutdown-Event: Exit main loop")
            break
        time.sleep(30)
        if shutdown_flag.isSet():
            logger.debug("Shutdown-Event: Exit main loop")
            break
    
    if vm.status == "ACTIVE":
        # We need the libvirtd instance_name for monitoring 
        instance_name = vm.__getattr__('OS-EXT-SRV-ATTR:instance_name')
        logger.info("VM instance_name=%s", instance_name)

        logger.info("VM is ACTIVE -> continue Monitoring via libvirtd")
        try:
             domain = conn.lookupByName(instance_name)
        except:
            log.error("ERROR: unable to find VM in libvirt! Name=%s", instance_name)
            # In this case the VM musst be terminated in OpenStack.
            # Possible reason: the VM was started on a wrong Compute-Node
            deleteVM(nova, vm)
            exit(1)

        logger.info("Adding the libvirt instance name to Moab-Job information")
        command = ["mjobctl", "-m var+=libvirtName=" + instance_name, var['pbs-jobid']]
        logger.debug("mjobctl command: %s", command)
        try:
            call(command)
        except:
            logger.error("ERROR - failed command: ", command)


    logger.info("Job finished!")
    exit(returnCode)
     
    return 
  
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Start an OpenStack Virtual Machine. Values can either be supplied "
                                                 "in the script itself or via command-line interface. The latter "
                                                 "takes precedence.",
                                                 argument_default=argparse.SUPPRESS)
    
    parser.add_argument("--config-file", dest="config-file", type=str, default="startVM.conf", help="startVM config file")
    parser.add_argument("--key-file", dest="key-file", default=None, type=str, help="startVM Key-File for OpenStack username/password or token")
    parser.add_argument("--debug-level", dest="debug", type=str, default="DEBUG", help="Debug level: DEBUG INFO WARNING ERROR CRITICAL")
    
    parser.add_argument("--os-auth-url", dest="os-auth-url", default=os.environ.get('OS_AUTH_URL', None), type=str, help="startVM config file")
    parser.add_argument("--os-username", dest="os-username", default=os.environ.get('OS_USERNAME', None), type=str, help="Username to login with")
    parser.add_argument("--os-password", dest="os-password", default=os.environ.get('OS_PASSWORD', None), type=str, help="Password to login with")
    parser.add_argument("--os-project-name", dest="os-project-name", default=os.environ.get('OS_PROJECT_NAME', None), type=str, help="project name to scope to")
    parser.add_argument("--os-project-id", dest="os-project-id", default=os.environ.get('OS_PROJECT_ID', None), type=str, help="project name to scope to")
    parser.add_argument("--os-region-name", dest="os-region-name", default=os.environ.get('OS_REGION_NAME', None), type=str, help="Authentication region name")
    
    parser.add_argument("--user-data", dest="user-data", type=str, help="User-data string(s) for cloud-init")
    parser.add_argument("--image-id", dest="image-id", default=None, type=str, help="OpenStack VM Image ID (GUID)")
    parser.add_argument("--image-name", dest="image-name", default=None, type=str, help="OpenStack VM Image Name")
    parser.add_argument("--key-name", dest="key-name", default=None, type=str, help="Keypair to inject into this server")
    parser.add_argument("--security-group", dest="security-group", default=None, type=str, help="Security group to assign to this server")
    parser.add_argument("--flavor", dest="flavor", default=None, type=str, help="Create server with this flavor")
    parser.add_argument("--nic", dest="nic", default=None, type=str, help="Create a NIC on the server. <net-id=net-uuid,v4-fixed-ip=ip-addr>")
    parser.add_argument("--vm-name", dest="vm-name", default=None, type=str, help="Name of the VM in OpenStack")
    parser.add_argument("--vm-name-is-ip", dest="vm-name-is-ip", default=None, type=bool, help="Convert the VM name to the IP address of the VM")

    parser.add_argument("--availability-zone", dest="availability-zone", default=None, type=str, help="Select an availability zone for the server")  
    
    parser.add_argument("--compute-hostname", dest="compute-hostname", default=None, type=str, help="Hostname of the Compute-Node (WARNING: Only for development or debug)")
    parser.add_argument("--np", dest="np", default=None, type=str, help="Number of processors (Cores) (WARNING: Only for development or debug)")
    parser.add_argument("--mem", dest="mem", default=None, type=str, help="Memory in MB (RAM) (WARNING: Only for development or debug)")

    parser.add_argument("--pbs-jobid", dest="pbs-jobid", default=None, type=str, help="Compute-Job ID (WARNING: Only for development or debug)")
    parser.add_argument("--pbs-walltime", dest="pbs-walltime", default=None, type=str, help="Compute-Job Walltime in Seconds (WARNING: Only for development or debug)")

    
    args = vars(parser.parse_args())
    
    
    #location = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
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
    if args['image-id'] is None:
        args['image-id'] = config.get("VM", "IMAGE_ID")
    if args['image-name'] is None:
        args['image-name'] = config.get("VM", "IMAGE_NAME")
    if args['key-name'] is None:
        args['key-name'] = config.get("VM", "KEYNAME")
    if args['security-group'] is None:
        args['security-group'] = config.get("VM", "SECURITY_GROUP")
    if args['availability-zone'] is None:
        args['availability-zone'] = config.get("CLUSTER", "AVAILABILITY_ZONE")
    if args['vm-name-is-ip'] is None:
        if config.get("VM", "VM_NAME_IS_IP") in ['true', 'True', 'yes', 'Yes', '1', 'y', 'Y']:
            args['vm-name-is-ip'] = True
        else:
            args['vm-name-is-ip'] = False
    #os_tenant_id = config.get("OPENSTACK", "TENANT_ID")
    debug_level = config.get("DEFAULT", "DEBUG_LEVEL")
    args['vm-name-prefix'] = config.get("VM", "VM_NAME_PREFIX")

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
    logger.setLevel(getattr(logging,debug_level))
    
    logger.info("-- Monitor VM Script --")

    # register signal handler to intercept SIGHUP
    # this is needed to terminate the VM if the job wall-time is over
    orig_sighandler = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, signal_handler)
    
    shutdown_flag = threading.Event()
    
    #print args
    main(args)
