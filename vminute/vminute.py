#!/usr/bin/python
 # -*- coding: utf8 -*-

import getopt
import os
import sys
import re
import termios
import fcntl
import subprocess
import urllib2
import random
import time
import math
import traceback
import urllib
from prettytable import PrettyTable
import socket

try:
    from keystoneclient.v2_0 import client as keystone_client
    from cinderclient import client as cinder_client
    from cinderclient import exceptions as cinder_exceptions
    from heatclient import client as heat_client
    from heatclient import exc as heat_exceptions
    from neutronclient.neutron import client as neutron_client
    from novaclient import client as nova_client
    from novaclient import exceptions as nova_exceptions
    from keystoneclient.auth.identity import v2 as keystoneIdentity
    from keystoneclient import session as keystoneSession
    import xmltodict
except ImportError, ie:
    sys.stderr.write(ie.message+"\n")
    sys.exit(1)

try:
    # Python 2.7
    from functools import wraps
except:
    # Python 2.4
    from backports.functools import wraps


CONF_DIR = '~/.5minute'
USER = os.environ["USER"]
DEBUG = False
DISABLE_CATCH = False
PROGRESS = None

# -----------------------------------------------------------
# Helpers functions
# -----------------------------------------------------------


def die(message, excode=1, exception=None):
    """
    Print error message into srdErr
    :param message: message
    :param excode: exitcode
    :param exception: exception for debugging mode
    """
    global PROGRESS
    if PROGRESS is not None:
        progress(result="\x1b[31;01mFAIL\x1b[39;49;00m")
    global DEBUG
    if exception and DEBUG:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        sys.stderr.write("\n\x1b[92;01m")
        traceback.print_tb(exc_traceback)
        sys.stderr.write("\x1b[39;49;00m\n")
    sys.stderr.write("\n\x1b[31;01m%s\x1b[39;49;00m\n\n" % message)
    sys.exit(excode)


def warning(message, answer=None):
    """
    Print warning message into srdErr and may can for answer
    :param message: message
    :param answer: list of supported options. Default is first item.
    """
    c = ""
    sys.stderr.write("\n\x1b[92;01m%s " % message)
    if answer:
        fd = sys.stdin.fileno()
        oldterm = termios.tcgetattr(fd)
        newattr = termios.tcgetattr(fd)
        newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, newattr)
        oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)
        try:
            while 1:
                try:
                    c = sys.stdin.read(1)
                    break
                except IOError:
                    pass
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
            fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)
        c = (u"%s" % c).lower()
    sys.stderr.write(" %s\x1b[39;49;00m\n\n" % c)
    if answer:
        for it in answer:
            if c in it:
                return c
        return answer.pop(0)


def progress(title=None, result=None):
    """
        Function for displaying of progress bar.

        Example of using:
            progress(title="Name of action")
            for i in range(0, 30):
                progress()
            progress(result="GOOD")

    """
    CHARS = ('.', '-', '=', '_')
    global PROGRESS
    if title:
        PROGRESS = 0
        sys.stdout.write("%s" % title.ljust(40, " "))
    if result:
        sys.stdout.write("%s\x1b[92;01m%s\x1b[39;49;00m\n" %
                         ("\b" * (PROGRESS % 20), result.ljust(20, " ")))
        PROGRESS = None
    if title is None and result is None:
        PROGRESS += 1
        if PROGRESS % 20 == 0:
            sys.stdout.write("\b" * 19)
            PROGRESS += 1
        sys.stdout.write(CHARS[int(math.ceil(PROGRESS / 20)) % len(CHARS)])
    sys.stdout.flush()


def catch_exception(text=None, type=Exception):
    """  Decorator for catch exception   """
    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            catch_message = text
            try:
                return func(*args, **kwargs)
            except type as ex:
                if not DISABLE_CATCH:
                    if catch_message is None:
                        catch_message = ex.message
                    die(catch_message, exception=ex)
                else:
                    raise ex
        return wrapper
    return decorate


class disable_catch_exception:
    """ Disbale decorator for catch exception. """
    def __enter__(self):
        global DISABLE_CATCH
        DISABLE_CATCH = True

    def __exit__(self, type, value, traceback):
        global DISABLE_CATCH
        DISABLE_CATCH = False


def get_FQDN_from_IP(ip):
    # If we want to support old version of OpenStack, we have to update this function and
    # solve it via serviceman
    return "host-{1}-{2}-{3}.host.centralci.eng.rdu2.redhat.com".format(*ip.split("."))

# -----------------------------------------------------------
# Classes
# -----------------------------------------------------------


class BaseClass(object):
    __nova = None
    __keystone = None
    __cinder = None
    __heat = None
    __token = None
    __neutron = None
    __first_check = False
    __tmpconf = "/tmp/5minute.conf"
    __profiles = "profiles/"
    _scenarios = "./vminute/scenarios/"
    __check_env_done = False

    @catch_exception(
        "The configuration file ~/.5minute/config does not exist.\n"
        "Please download the OpenStack RC file from OpenStack WebUI (Access & Security > API Access "
        "> Download OpenStack RC file) and save it to ~/.5minute/config.\n")
    def __load_configuration(self):
        if not os.path.isfile(self.__tmpconf):
            subprocess.check_call("source {config_loc}/config; env | grep OS_ >> {tmpfile}"
                                  .format(config_loc=CONF_DIR, tmpfile=self.__tmpconf), shell=True)
        lines = []
        with open(os.path.expanduser(self.__tmpconf), "r") as fd:
            lines = fd.readlines()
        rx2 = re.compile(r'^\s*([A-z_]*)="?([^"]*)"?\s*$')
        for it in lines:
            res = rx2.search(it)
            if res:
                key, value = res.groups()
                os.environ[key] = value.strip()

    def __checkenv(self):
        if self.__check_env_done:
            return
        if not os.environ.get('OS_AUTH_URL') or \
                not os.environ.get('OS_TENANT_NAME') or \
                not os.environ.get('OS_USERNAME') or \
                not os.environ.get('OS_PASSWORD'):
            if not self.__first_check:
                self.__load_configuration()
                self.__first_check = True
                self.__checkenv()
            else:
                die("The configuration file %s/config doesn't contain all important variables.\n" % CONF_DIR)
        self.__profiles = "%s/%s" % (CONF_DIR, self.__profiles)
        if not os.path.isdir(os.path.expanduser(self.__profiles)):
            try:
                os.makedirs(os.path.expanduser(self.__profiles))
            except OSError:
                die("The problem with creating of folder '%s'." % self.__profiles)
        self.__scenarios = "%s/%s" % (CONF_DIR, self.__scenarios)
        if not os.path.isdir(os.path.expanduser(self.__scenarios)):
            try:
                os.makedirs(os.path.expanduser(self.__scenarios))
            except OSError:
                die("The problem with creating of folder '%s'." % self.__scenarios)
        self.__check_env_done = True

    @catch_exception("Your SSL pub-key is not yet uploaded on the server. "
                     "Please use: 5minute key ~/.ssh/id_dsa.pub")
    def _check_key(self):
        self.nova.keypairs.get(USER)

    @catch_exception("Problem with connection to OpenStack. Please, check the configuration file "
                     "~/.5minute/config. (maybe OS_PASSWORD is not explicite value or is not set up in env)")
    def __check_connection(self):
        try:
            self.__nova.authenticate()
        except Exception as ex:
            os.remove(self.__tmpconf)
            raise ex

    def __get_cinder(self):
        if not self.__cinder:
            self.__checkenv()
            self.__cinder = cinder_client.Client(1,
                                                 os.environ.get('OS_USERNAME'),
                                                 os.environ.get('OS_PASSWORD'),
                                                 os.environ.get('OS_TENANT_NAME'),
                                                 os.environ.get('OS_AUTH_URL'))
        return self.__cinder

    def __get_heat(self):
        if not self.__heat:
            self.__checkenv()
            endpoint = self.__get_endpoint('orchestration')
            self.__heat = heat_client.Client(1, endpoint=endpoint,  token=self.token)
        return self.__heat

    def __get_keystone(self):
        if not self.__keystone:
            self.__checkenv()
            self.__keystone = keystone_client.Client(username=os.environ.get('OS_USERNAME'),
                                                     password=os.environ.get('OS_PASSWORD'),
                                                     tenant_name=os.environ.get('OS_TENANT_NAME'),
                                                     auth_url=os.environ.get('OS_AUTH_URL'))
        return self.__keystone

    def __get_nova(self):
        if self.__nova:
            return self.__nova
        self.__checkenv()
        self.__nova = nova_client.Client(2,
                                         username=os.environ.get('OS_USERNAME'),
                                         api_key=os.environ.get('OS_PASSWORD'),
                                         project_id=os.environ.get('OS_TENANT_NAME'),
                                         auth_url=os.environ.get('OS_AUTH_URL'))
        self.__check_connection()
        return self.__nova

    def __get_token(self):
        if not self.__token:
            self.__checkenv()
            auth = keystoneIdentity.Password(username=os.environ.get('OS_USERNAME'),
                                             password=os.environ.get('OS_PASSWORD'),
                                             tenant_name=os.environ.get('OS_TENANT_NAME'),
                                             auth_url=os.environ.get('OS_AUTH_URL'))
            session = keystoneSession.Session(auth=auth)
            self.__token = auth.get_token(session)
        return self.__token

    def __get_neutron(self):
        if not self.__neutron:
            self.__checkenv()
            endpoint = self.__get_endpoint('network')
            self.__neutron = neutron_client.Client('2.0', endpoint_url=endpoint, token=self.token)
        return self.__neutron

    def __get_endpoint(self, name):
        endpoints = self.keystone.service_catalog.get_endpoints()
        if name not in endpoints:
            die("This endpoint '%s' is not known" % name)
        return endpoints.get(name)[0]['publicURL']

    def __getattr__(self, name):
        if name == 'cinder':
            return self.__get_cinder()
        elif name == 'heat':
            return self.__get_heat()
        elif name == 'nova':
            return self.__get_nova()
        elif name == 'keystone':
            return self.__get_keystone()
        elif name == 'token':
            return self.__get_token()
        elif name == 'neutron':
            return self.__get_neutron()
        return None

    @catch_exception("The problem with parsing of profile XML file. ")
    def __get_scenario(self, filename):
        xml = None
        try:
            xml = urllib2.urlopen('https://example.com/scenarios/%s' % filename).read()
        except:
            warning("This profile '%s' doesn't exist." % filename)
            return dict()
        return xmltodict.parse(xml)

    def cmd(self, argv):
        self.help()

    def help(self):
        print """
            Usage: 5minute <-d|--debug>  [COMMAND]
            Manager for your openstack machines.

            OPTIONS:
                -d, --debug - enable debugging mode.

            COMMANDS:
                help        - this help
                key         - upload your SSL key on the server
                images      - the list of accessible images
                flavor      - the list of flavors
                list        - the list of instances
                delete      - delete a quest
                boot        - create a new quest
                scenario    - working with scenarios

            Examples:
                5minute help
                5minute key ~/.ssh/id_dsa.pub
                5minute images
                5minute images -h
                5minute images --all
                5minute images satellite
                5minute flavor
                5minute list
                5minute list --all
                5minute list satellite
                5minute boot --help
                5minute boot 5minute-RHEL6
                5minute boot --name myRHEL6 5minute-RHEL6
                5minute scenarios --help
        """


class KeyClass(BaseClass):
    @catch_exception("The problem with uploading of public key.")
    def __upload_key(self, key):
        if not os.access(key, os.R_OK):
            die("SSL key '%s' is not readable." % key)
        with open(key) as fd:
            self.nova.keypairs.create(USER, fd.read())
            print "The key %s was successfully uploaded." % key

    def cmd(self, argv):
        if len(argv) == 0 or argv[0] in ('help', '--help', '-h'):
            self.help()
        else:
            self.__upload_key(argv[0])

    def help(self):
        print """
            Usage: 5minute key <SSL-PUB-KEY>
            Upload your SSL key on the OpenStack server.

            Examples:
                5minute key ~/.ssh/id_dsa.pub
            """


class ImagesClass(BaseClass):
    __filter = "5minute-"

    @catch_exception("The problem getting list of images.")
    def __images(self):
        images = self.nova.images.list()
        x = PrettyTable(["Name", "ID", "Status"])
        x.align["Name"] = "l"
        rx = re.compile(self.__filter, re.IGNORECASE)
        for img in images:
            if rx.search(img.name):
                row = [img.name, img.id, img.status]
                x.add_row(row)
        print x.get_string(sortby="Name")

    def cmd(self, argv):
        if len(argv) > 0:
            if argv[0] in ('help', '--help', '-h'):
                self.help()
                return 0
            elif argv[0] in ('--all', '-a'):
                self.__filter = ""
            else:
                self.__filter = argv[0]
        self.__images()

    def help(self):
        print """
        Usage: 5minute images [PARAM]
        Show the list of accessible images. By default, it shows only 5minute images.

        PARAM:
            -a, --all   show all accessible images
            <REGEXP>    we can use a regular expression for the filtering of the result

        Examples:
            5minute images
            5minute images --all
            5minute images satellite
            5minute images fedora
        """


class FlavorClass(BaseClass):

    @catch_exception("The problem getting list of flavors.")
    def __flavors(self):
        flavors = self.nova.flavors.list()
        x = PrettyTable(["Name", "CPU", "RAM", "HDD", "ephemeral", "swap"])
        x.align["Name"] = "l"
        for flav in flavors:
                row = [flav.name, flav.vcpus,
                       "%s MB" % flav.ram,
                       "%s GB" % flav.disk,
                       "%s GB" % flav.ephemeral,
                       "%s MB" % flav.swap if flav.swap else ""]
                x.add_row(row)
        print x

    def cmd(self, argv):
        if len(argv) > 0:
            if argv[0] in ('help', '--help', '-h'):
                self.help()
                return 0
        self.__flavors()

    def help(self):
        print """
        Usage: 5minute flavors
        Show the list of accessible flavors.

        Examples:
            5minute flavors
        """


class ServerClass(BaseClass):

    @catch_exception("The instance doesn't exist.", nova_exceptions.NotFound)
    @catch_exception("The name of the instance is ambiguous, please use ID.", nova_exceptions.NoUniqueMatch)
    def get_instances(self, id):
        if re.match(r'^[0-9a-f\-]+$', id) is None:
            return self.nova.servers.find(name=id)
        else:
            return self.nova.servers.get(id)

    @catch_exception("The image doesn't exist.", nova_exceptions.NotFound)
    @catch_exception("The name of the image is ambiguous, please use ID.", nova_exceptions.NoUniqueMatch)
    def get_image(self, id):
        if re.match(r'^[0-9a-f\-]+$', id) is None:
            return self.nova.images.find(name=id)
        else:
            return self.nova.images.get(id)

    @catch_exception("The volume doesn't exist.", cinder_exceptions.NotFound)
    @catch_exception("The name of the volume is ambiguous, please use ID.", cinder_exceptions.NoUniqueMatch)
    def get_volume(self, id):
        if re.match(r'^[0-9a-f\-]+$', id) is None:
            return self.cinder.volumes.find(name=id)
        else:
            return self.cinder.volumes.get(id)

    @catch_exception("The snapshot doesn't exist.")
    def get_snapshot(self, id):
        if re.match(r'^[0-9a-f\-]+$', id) is None:
            return self.cinder.volume_snapshots.find(display_name=id)
        else:
            return self.cinder.volume_snapshots.get(id)

    @catch_exception("The flavor doesn't exist.", nova_exceptions.NotFound)
    @catch_exception("The flavor is ambiguous, please use ID.", nova_exceptions.NoUniqueMatch)
    def get_flavor(self, id):
        if re.match(r'^[0-9a-f\-]+$', id) is None:
            return self.nova.flavors.find(name=id)
        else:
            return self.nova.flavors.get(id)

    @catch_exception("The problem with getting of the list of networks.")
    def get_networks(self, filter=None):
        def test_net(net, filter):
            if filter is None:
                return True
            for key, val in filter.items():
                if isinstance(val,  str):
                    if re.search(val, net.get(key, "")) is None:
                        return False
                elif val != net.get(key):
                    return False
            return True

        res = list()
        for net in self.neutron.list_networks()['networks']:
            if test_net(net, filter) and len(net.get('subnets')) > 0:
                res.append(net)
        return res

    def get_stable_private_network(self):
        def get_count_free_ip(cidr, flist):
            address_size = 32
            ip_pool_mask = int(cidr.split("/")[1])
            ip_pool_bit_size = address_size - ip_pool_mask
            max_pool_size = 2 ** ip_pool_bit_size - 2
            return max_pool_size - len([ip_addr for ip_addr in flist if
                                        ip_addr.pool == cidr and ip_addr.instance_id])
        nets = self.get_networks(filter={'name': "^default-", "router:external": False})
        max_network_space = 0
        current_biggest_network = None
        flist = self.nova.floating_ips.list()
        res = list()
        for net in nets:
            pub_net = self.__get_external_for_private_network(net)
            if pub_net:
                sub = self.neutron.list_subnets(id=net['subnets'].pop(0))
                if len(sub.get('subnets')) > 0:
                    cidr = sub['subnets'][0]['cidr']
                    network_free_space = get_count_free_ip(cidr, flist)
                    if network_free_space > max_network_space:
                        max_network_space = network_free_space
                        res = list()
                        res.append({'private': net, 'free_ip': network_free_space, 'public': pub_net})
                    elif network_free_space > 0 and network_free_space == max_network_space:
                        res.append({'private': net, 'free_ip': network_free_space, 'public': pub_net})
        return random.choice(res)

    def __get_external_for_private_network(self, pnet):
        """
            This function returns public network for private network,
            if the router is present between these nets.
        """
        ports = self.neutron.list_ports(network_id=pnet['id'], device_owner="network:router_interface").get('ports')
        if len(ports) == 0:
            return None
        router = self.neutron.show_router(ports.pop(0)['device_id'])
        return self.neutron.show_network(router['router']['external_gateway_info']['network_id'])['network']

    def cmd(self, argv):
        pass

    def help(self):
        pass


class ListInstancesClass(ServerClass):
    """
    This is only view on the ServerClass for getting of list of instances.
    """
    def cmd(self, argv):
        filter = None
        if len(argv) == 0:
            filter = "%s-" % USER
        else:
            if argv[0] in ('help', '--help', '-h'):
                self.help()
                return 0
            elif argv[0] not in ('--all', '-a'):
                filter = argv[0]
        self.list_instances(filter)

    @catch_exception("The problem with getting of the list of instances.")
    def list_instances(self, filter):
        instances = self.nova.servers.list(search_opts={"name": filter})
        x = PrettyTable(["Name", "ID", "Status", "FQDN"])
        x.align["Name"] = "l"
        x.align["FQDN"] = "l"
        for ins in instances:
            row = [ins.name, ins.id, ins.status, ins.metadata.get('fqdn', "")]
            x.add_row(row)
        print x.get_string(sortby="Name")

    def help(self):
        print """
        Usage: 5minute list [PARAM]
        Show the list of instances. By default, it shows only your instances.

        PARAM:
            -a, --all   show all accessible instances
            <REGEXP>    we can use a regular expression for the filtering of the result

        Examples:
            5minute list
            5minute list --all
            5minute list satellite
            5minute list fedora
        """


class DeleteInstanceClass(ServerClass):
    """
     This is only view on the ServerClass for deletting of instance.
    """
    def cmd(self, argv):
        if len(argv) == 0:
            die("Missing parameter. Please try 5minute delete <name|id>.")
        else:
            if argv[0] in ('help', '--help', '-h'):
                self.help()
                return 0
            else:
                self.kill_instances(argv[0])

#    @catch_exception("The problem deleting of the instances.")
    def kill_instances(self, id):
        server = self.get_instances(id)
        progress(title="Release floating IP:")
        # This is stupid method for checking of lock, if it is activated
        fips = self.nova.floating_ips.findall(instance_id=server.id)
        for fip in fips:
            server.remove_floating_ip(fip.ip)
        progress(result="DONE")
        vols = self.nova.volumes.get_server_volumes(server.id)
        if len(vols) > 0:
            progress(title="Release volumes:")
            for vol in vols:
                progress()
                cvol = self.cinder.volumes.get(vol.id)
                self.cinder.volumes.begin_detaching(cvol)
            progress(result="DONE")
        progress(title="Delete instance:")
        done = False
        try:
            server.delete()
            done = True
            while len(self.nova.servers.findall(id=server.id)) > 0:
                time.sleep(1)
                progress()
            progress(result="DONE")
        except Exception as e:
            if 'locked' in e.message:
                progress(result="\x1b[31;01mLOCKED\x1b[39;49;00m")
            else:
                progress(result="FAIL")
        for fip in fips:
            if done:
                self.nova.floating_ips.delete(fip.id)
            else:
                server.add_floating_ip(fip.ip)
        for vol in vols:
            cvol = self.cinder.volumes.get(vol.id)
            if done:
                progress(title="Delete volume:")
                cvol.delete()
                while len(self.cinder.volumes.findall(id=cvol.id)) > 0:
                    time.sleep(1)
                    progress()
                progress(result="DONE")
            else:
                self.cinder.volumes.roll_detaching(cvol)


    def help(self):
        print """
         Usage: 5minute (del|kill|delete) <NAME|ID>
         Delete instance.

         PARAM:
             <NAME|ID>   Name or ID of instance

         Examples:
             5minute delete 5minute-RHEL6
             5minute kill 5minute-RHEL6
         """


class BootInstanceClass(ServerClass):
    """
     This is only view on the ServerClass for booting of instance.
    """
    ufile = ""
    default_flavor = "m1.medium"
    variables = None
    created_volume = False

    def __parse_params(self, opts, argv):
        params = {}
        for key, val in opts:
            if key in ('--help', '-h') or 'help' in argv:
                params['help'] = True
                return params
            elif key in ('--flavor', '-f'):
                params['flavor'] = self.get_flavor(val)
            elif key in ('--console', '-c'):
                params['console'] = True
            elif key in ('--name', '-n'):
                params['name'] = "%s-%s" % (USER, val)
            elif key in ('--volume', '-v'):
                params['volume'] = val
            elif key in ('--profile', '-p'):
                params['profile'] = val
            elif key == '--novolume':
                params['novolume'] = True
            elif key == '--noip':
                params['noip'] = True
            elif key == '--userdata':
                params['userdata'] = val
            else:
                die("Bad parameter '%s'. Please try 5minute boot --help." % key)
        if len(argv) != 1:
            die("The name of image is ambiguous or empty.")
        params['image'] = self.get_image(argv.pop(0))
        self.add_variable('image', params['image'].name)
        self.add_variable('image_id', params['image'].id)
        if 'name' not in params:
            params['name'] = "%s-%s" % (USER, params['image'].name)
        self.add_variable('name', params['name'])
        return params

    @catch_exception("Bad parameter. Please try 5minute boot --help.")
    def cmd(self, argv):
        opts, argv = \
            getopt.getopt(argv, "hcf:n:v:p:",
                          ['help', 'console', 'flavor=', 'name=', 'volume=', 'userdata=',
                           'novolume', 'noip'])
        self.params = self.__parse_params(opts, argv)
        if 'help' in self.params:
            self.help()
            return 0
        self.boot_instance()

    def add_variable(self, key, val):
        if not self.variables:
            self.variables = dict()
        self.variables[key] = val

    def __release_resources(self):
        if "floating-ip" in self.variables and \
                self.variables.get("floating-ip"):
            self.nova.floating_ips.delete(self.variables['floating-ip'])
        if self.created_volume:
            cvol = self.cinder.volumes.get(self.volume.id)
            cvol.detach()
            cvol.delete()

    @catch_exception()
    def boot_instance(self):
        self._check_key()
        with disable_catch_exception():
            try:
                self.__setup_networking()
                self.__setup_volume(self.params['image'])
                self.__setup_userdata_script(self.params['image'])
                self.__choose_flavor(self.params['image'])
                self.__create_instance(self.params['image'])
            except Exception, ex:
                self.__release_resources()
                die(str(ex), exception=ex)

    def help(self):
        print """
         Usage: 5minute boot [PARAM]  <IMAGE-NAME|IMAGE-ID>
         Boot new instance.

         PARAM:
              -n, --name      name of the instance
              -f, --flavor    name of flavor
              -v, --volume    the volume snapshot (default: 5minute-satellite5-rpms)
              --novolume      no voluume snapshot
              -c, --console   display the console output during booting
              --userdata      the paths or URLs to cloud-init scripts

         Examples:
             5minute boot 5minute-RHEL6
         """

    def __setup_networking(self):
        progress(title='Chossing the private network:')
        network = self.get_stable_private_network()
        progress(result=network['private']['name'])
        progress(title='Obtaining a floating IP:')
        floating_ip = self.nova.floating_ips.create(network['public']['id'])
        if not floating_ip:
            raise Exception("The problem with getting of IP address.")
        self.add_variable('floating-ip', floating_ip)
        self.add_variable('private-net', network['private']['id'])
        progress(result=floating_ip.ip)
        progress(title='Obtaining a domain name:')
        hostname = get_FQDN_from_IP(floating_ip.ip)
        if not hostname:
            raise Exception("The problem with getting of DNS record.")
        self.add_variable('hostname', hostname)
        progress(result=hostname)

#    @catch_exception("The problem with downloading of the userdata script for this image")
    def __setup_userdata_script(self, image):
        res = None
        filenames = None
        if "userdata" in self.params:
            filenames = self.params['userdata']
        elif "cscripts" in image.metadata:
            filenames = image.metadata['cscripts']
        if filenames:
            progress(title='Loading the userdata script:')
            self.params['cscript'] = ""
            for filename in filenames.split():
                cscript = urllib.urlopen(filename).read()
                self.params['cscript'] += cscript.format(**self.variables)
                self.params['cscript'] += "\n"
            progress(result="DONE")

    def __setup_volume(self, image):
        self.volume = None
        if not self.params.get('novolume', False):
            volume_name = self.params.get('volume')
            if volume_name is None:
                volume_name = image.metadata.get('volumes')
            if volume_name:
                # Is the volume_name name/id of existing volume?
                try:
                    self.volume = self.get_volume(volume_name)
                except cinder_exceptions.NotFound as ex:
                    pass
                if self.volume is None:
                    # The volume_name is name of snapshot,
                    # we create new volume from it
                    self.volume = self.__create_new_volume(volume_name, image)

    def __create_new_volume(self, volume_name, image):
        progress(title="Creating a new volume:")
        snap = self.get_snapshot(volume_name)
        name = self.params.get('name', "%s-%s" % (USER, image.name))
        vol = self.cinder.volumes.create(size=snap.size, snapshot_id=snap.id,
                                         display_name=name)
        while vol.status == 'creating':
            progress()
            time.sleep(1)
            vol = self.get_volume(vol.id)
        if vol.status == 'error':
            raise Exception("The problem with creating of the volume.")
        progress(result="DONE")
        self.created_volume = True
        return vol

    def __choose_flavor(self, image):
        progress(title="Used  flavor:")
        if 'flavor' not in self.params:
            if 'default_flavor' in image.metadata:
                self.params['flavor'] =\
                    self.get_flavor(image.metadata.get('default_flavor'))
            if self.params.get('flavor') is None:
                self.params['flavor'] =\
                    self.get_flavor(self.default_flavor)
        flavor = ("{name} (RAM: {ram} MB, vCPU: {vcpus}, disk: {disk} GB)")\
            .format(**self.params['flavor'].__dict__)
        progress(result=flavor)

    def __create_instance(self, image):
        progress(title="Instance name:", result=self.params.get('name'))
        progress("Creating a new instance:")
        param_dict = {'name': self.params.get('name'),
                      'image': image.id,
                      'flavor': self.params.get('flavor').id,
                      'key_name': USER,
                      'nics': [{'net-id': self.variables['private-net']}],
                      'meta': {'fqdn': self.variables["hostname"]},
                      'security_group': ['satellite5'],
                      'config_drive': True}
        if self.volume:
            param_dict['block_device_mapping'] = {'vdb': self.volume.id}
#        print(param_dict)
        if "cscript" in self.params:
            param_dict['userdata'] = self.params['cscript']
        server = self.nova.servers.create(**param_dict)
        status = server.status
        while status == 'BUILD':
            time.sleep(1)
            progress()
            status = self.nova.servers.get(server.id).status
#            print server.progress
        if status == 'ACTIVE':
            progress(result="DONE")
        else:
            progress(result="FAIL")
        if "floating-ip" in self.variables:
            server.add_floating_ip(self.variables['floating-ip'])
        self.__check_console_output(server)

    def __check_console_output(self, server):
        lindex = 0
        show_output = self.params.get('console')
        exit_status = None
        exit_message = "DONE"
        counter = 60
        reg_login = re.compile(r".*login:\s*$")
        reg_warning = re.compile(r"(warning)", re.I)
        reg_error = re.compile(r"(error)", re.I)
        if show_output:
            print "Booting of the instance:"
        else:
            progress(title="Booting of the instance:")
        output = server.get_console_output().splitlines()
        while counter > 0 and exit_status is None:
            nindex = len(output) - 1
            if lindex >= nindex:
                counter -= 1
            else:
                counter = 60
                for line in output[lindex:]:
                    patern = "%s\n"
                    if reg_login.match(line):
                        counter = 0
                        if exit_status is None:
                            exit_status = True
                        break
                    if reg_warning.search(line):
                        patern = "\x1b[92;01m%s\x1b[39;49;00m\n"
                    if reg_error.search(line):
                        patern = "\x1b[31;01m%s\x1b[39;49;00m\n"
                        exit_message = "Errors in the userdata script"
                    if show_output:
                        sys.stdout.write(patern % line)
                    else:
                        progress()
                    time.sleep(1)
                lindex = nindex + 1
            if exit_status is None:
                output = server.get_console_output(30).splitlines()
        if not show_output:
            progress(result=exit_message)
        if exit_status is None:
            exit_status = False
        return exit_status


class ScenarioClass(ServerClass):
    """
     This is class for scenarios
    """
    @staticmethod
    def getInstance(subcmd):
        if subcmd == 'list':
            return ListScenarioClass()
        elif subcmd == 'templates':
            return TemplateScenarioClass()
        elif subcmd == 'boot':
            return BootScenarioClass()
        elif subcmd in ('del', 'delete', 'kill'):
            return DeleteScenarioClass()
        else:
            return ScenarioClass()

    def cmd(self, argv):
        self.help()
        return 0

    @catch_exception("The scenario doesn't exist.", heat_exceptions.NotFound)
    def get_scenario(self, id):
        return self.heat.stacks.get(id)

    def help(self):
        print """
         Usage: 5minute scenarios <COMMAND> [PARAM]
         Managing scenaros

         COMMAND:
            help                -   show this help
            templates           -   show the list of templates
            list                -   show the list of scenarios
            boot                -   create new scenario/stack
            del|kill            -   delete scenario

         Examples:
             5minute scenarios help
             5minute scenarios templates
             5minute scenarios list
             5minute scenarios boot template1
             5minute scenarios boot --name myscenario template1
             5minute scenarios del myscenario

         """


class TemplateScenarioClass(ScenarioClass):

    def __get_list_templates(self):
        templates = list()
        folder = os.path.expanduser(self._scenarios)
        for file in os.listdir(folder):
            if file.endswith(".yaml"):
                templates.append(re.sub(r'\.yaml$', '', file))
        return templates

    def cmd(self, argv):
        if len(argv) > 0 and argv.pop(0) in ('help', '--help', '-h'):
            self.help()
            return 0
        else:
            x = PrettyTable(["Name", ])
            x.align["Name"] = "l"
            for row in self.__get_list_templates():
                print row
                x.add_row([row, ])
            print x.get_string(sortby="Name")

    def help(self):
        print """
         Usage: 5minute scenarios templates
         Show the list of available templates

         Examples:
             5minute scenarios templates

         """


class BootScenarioClass(ScenarioClass):

    @catch_exception("Bad parameter. Please try 5minute scenario boot --help.")
    def cmd(self, argv):
        params = dict()
        opts, argv2 = getopt.getopt(argv, "n:h", ['name=', 'help'])
        for key, val in opts:
            if key in ('--help', '-h'):
                self.help()
                return
            elif key in ('--name', '-n'):
                params['name'] = val
            else:
                die("Bad parameter '%s'. Please try 5minute scenario boot --help." % key)
        if len(argv2) != 1:
            die("You have to set name of template. Please try 5minute scenario boot --help.")
        template_name = argv2.pop(0)
        if template_name == 'help':
            self.help()
            return
        params['template_name'] = template_name
        params['template'] = self.__get_template(template_name)
        self._check_key()
        self.__crate_stack(params)

    @catch_exception("Error: Problem with the loading of the template.")
    def __get_template(self, name):
        template = None
        with open(os.path.expanduser("{folder}/{template}.yaml".format(folder=self._scenarios,
                                                                       template=name)), 'r') as tmd:
            template = tmd.read()
        return template

    def __crate_stack(self, params):
        progress(title="Creating of scenario:")
        params['name'] = "%s-%s" % (USER, params['template_name'] if 'name' not in params else params['name'])
        current_biggest_network, free_ips = self.get_network()
        stack = self.heat.stacks.create(stack_name=params['name'], template=params['template'], parameters={
                                        'key_name': USER,
                                        'image': 'RHEL-6.5-Server-x86_64-released',
                                        'flavor': 'm1.medium',
                                        'public_net': current_biggest_network['id'],
                                        'prefix_name': params['name'],
                                        'private_net_cidr': '192.168.250.0/24',
                                        'private_net_gateway': '192.168.250.1',
                                        'private_net_pool_start': '192.168.250.10',
                                        'private_net_pool_end': '192.168.250.250'
                                        })
        uid = stack['stack']['id']
        stack = self.heat.stacks.get(stack_id=uid).to_dict()
        while stack['stack_status'] == 'CREATE_IN_PROGRESS':
            progress()
            stack = self.heat.stacks.get(stack_id=uid).to_dict()
            time.sleep(3)
        if stack['stack_status'] == 'CREATE_COMPLETE':
            progress(result="DONE")
            for it in stack['outputs']:
                print "{key}: {val}".format(key=it['output_key'], val=it['output_value'])
            print "Stack succesfully created."
        else:
            progress(result="FAIL")
            die("Stack fall to unknow status: {}".format(stack))

    def __get_count_free_ip(self, net, flist):
        address_size = 32
        ip_pool_mask = int(net['name'].split("/")[1])
        ip_pool_bit_size = address_size - ip_pool_mask
        max_pool_size = 2 ** ip_pool_bit_size - 2
        return max_pool_size - len([ip_addr for ip_addr in flist if
                                    ip_addr.pool == net['name'] and ip_addr.instance_id])

    def get_network(self):
        max_network_space = 0
        current_biggest_network = None
        flist = self.nova.floating_ips.list()
        for net in self.neutron.list_networks()['networks']:
            if net.get('router:external') and len(net.get('subnets')) > 0:
                network_free_space = self.__get_count_free_ip(net, flist)
                if network_free_space > max_network_space:
                    max_network_space = network_free_space
                    current_biggest_network = net
        return (current_biggest_network, max_network_space)

    def help(self):
        print """
         Usage: 5minute scenarios boot [PARAM] <TEMPLATE-NAME>
         Boot new scenaro

         PARAM:
             -n, --name         Name of scenario
             <TEMPLATE-NAME>    The name of template

         Examples:
             5minute scenarios boot template1
             5minute scenarios boot --name myscenario template1

         """


class ListScenarioClass(ScenarioClass):

    def cmd(self, argv):
        filter = None
        if len(argv) == 0:
            filter = "%s-" % USER
        else:
            if argv[0] in ('help', '--help', '-h'):
                self.help()
                return 0
            elif argv[0] not in ('--all', '-a'):
                filter = argv[0]
        self.list_scenarios(filter)

    @catch_exception("The problem with getting of the list of scenarios.")
    def list_scenarios(self, filter):
        scenarios = self.heat.stacks.list(search_opts={"name": filter})
        x = PrettyTable(["Name", "ID", "Status", "Template"])
        x.align["Name"] = "l"
        x.align["Template"] = "l"
        for ins in scenarios:
            row = [ins.stack_name, ins.id, ins.stack_status, ins.description.split("\n", 1)[0][0:20]]
            x.add_row(row)
        print x.get_string(sortby="Name")

    def help(self):
        print """
        Usage: 5minute scenarios list [PARAM]
        Show the list of scenarios. By default, it shows only your scenarios.

        PARAM:
            -a, --all   show all accessible scenarios
            <REGEXP>    we can use a regular expression for the filtering of the result

        Examples:
            5minute scenarios list
            5minute scenarios list --all
            5minute scenarios list satellite-infrastructure
        """


class DeleteScenarioClass(ScenarioClass):
    """
     This is only view on the ServerClass for deletting of instance.
    """
    def cmd(self, argv):
        if len(argv) == 0:
            die("Missing parameter. Please try 5minute scenario delete <name|id>.")
        else:
            if argv[0] in ('help', '--help', '-h'):
                self.help()
                return 0
            else:
                self.kill_scenario(argv[0])

    @catch_exception("The problem with deleting of the scenario.")
    def kill_scenario(self, id):
        scenario = self.get_scenario(id)
        scenario.delete()

    def help(self):
        print """
         Usage: 5minute scenarios (del|kill|delete) <NAME|ID>
         Delete scenario.

         PARAM:
             <NAME|ID>   The name of the scenario

         Examples:
             5minute scenarios delete 5minute-RHEL6
             5minute scenarios kill 5minute-RHEL6
         """

# -----------------------------------------------------------
# Manuals
# -----------------------------------------------------------


def main(argv):
    if 'novaclient' not in sys.modules:
        die("Please install python-novaclient (maybe 'yum -y install python-novaclient'?)")
    if 'xmltodict' not in sys.modules:
        die("Please install python-xmltodict (maybe 'yum -y install python-xmltodict'?)")

    cmd = None
    if len(argv) > 0:
        cmd = argv.pop(0)
    if cmd in ('--debug', '-d'):
        global DEBUG
        DEBUG = True
        if len(argv) > 0:
            cmd = argv.pop(0)
    if cmd is None or cmd in ('help', '--help', '-h'):
        BaseClass().cmd(argv)
    elif cmd == 'key':
        KeyClass().cmd(argv)
    elif cmd == 'images':
        ImagesClass().cmd(argv)
    elif cmd == 'flavors':
        FlavorClass().cmd(argv)
    elif cmd == 'list':
        ListInstancesClass().cmd(argv)
    elif cmd in ('del', 'delete', 'kill'):
        DeleteInstanceClass().cmd(argv)
    elif cmd == 'boot':
        BootInstanceClass().cmd(argv)
    elif cmd in ('scenario', 'scenarios'):
        scmd = None
        if len(argv) > 0:
            scmd = argv.pop(0)
        ScenarioClass.getInstance(scmd).cmd(argv)

if __name__ == "__main__":
    main(sys.argv[1:])

