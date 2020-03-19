
from os import path
from shutil import copy 
import sys 
import subprocess
import inspect
#from dynamite_nsm.services.helpers import pf_ring

UNIT_FILE_DIR = '/etc/systemd/system'
AGENT_UNITS = ['dynamite.target', 'filebeat.service', 'suricata.service', 'zeek.service']

class cmdResult:
    """
    Container class for parsed and decoded systemctl command output
    """
    def __init__(self):
        self.out = None
        self.err = None
        self.exit = None
        self.cmd = None
        self.svc = None

class dynctl:
    """
    Provides a wrapper around systemctl for managing Dynamite Services.
    """
    def __init__(self,
                stdout=True,
                verbose=False):
        """
        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """
        # Verify systemctl is installed and in path, bail if not 
        p = subprocess.Popen('which systemctl', stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=True)
        p.communicate()
        if p.returncode != 0:
            raise Exception('Systemctl not found, is it installed?  {}\n'.format(p.stderr.read()))

        for svc in AGENT_UNITS:
            self._update_comp_status(svc)
        
    def __getattribute__(self, name):
        """
        Retrieves an attribute by name. 
        """
        return object.__getattribute__(self, name)

    def _get_svc_status(self, svc):
        """
        Retrieve the full status output from systemctl for a given service name. 
        """
        return self._exec('status', svc, [])        

    def _get_comp_state(self, component):
        """
        Retrieve the ActiveState and LoadState from systemctl for a given unit name. 
        """
        state = {'LoadState':None, 'ActiveState':None}
        res = self._exec('show', component, ['-p ActiveState -p LoadState'])
        if res.exit == 0 and res.err == '' and res.out != '':
            state = {l.split('=')[0].strip() : l.split('=')[1].strip() for l in res.out.split('\n') if '=' in l}
        return state 
 
    def _update_comp_status(self, component):
        """
        Updated the status attributes of the given component based on the state reported by systemctl.
        """
        state = self._get_comp_state(component)

        comp = component.split('.')[0]
        comp_enabled = comp + "_enabled"
        comp_running = comp + "_running"
        if state['LoadState'] != 'loaded':
            self.__setattr__(comp_enabled, False)
        else:
            self.__setattr__(comp_enabled, True)
        if state['ActiveState'] != 'active':
            self.__setattr__(comp_running, False)
        else:
            self.__setattr__(comp_running, True)

        return (comp, self.__getattribute__(comp_running))

    def _exec(self, cmd, svc, args):
        """
        Wrapper for systemctl cli utility. 

        Returns an object containing stdout, stderr, exit code from the executed systemctl command.
        """
        res = cmdResult()
        res.svc = svc 
        res.cmd = " ".join(["systemctl", cmd, svc])
        if args and len(args) > 0:
            for arg in args:
                res.cmd += " " + arg
        p = subprocess.Popen(res.cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        res.err = err.decode().strip()
        res.out = out.decode().strip()
        res.exit = p.returncode
        return res

    def _exec_update(self, cmd, svc):
        """
        Executes the systemctl command and updates the component's status. 

        :return: 
        """
        self._exec(cmd, svc, [])
        return self._update_comp_status(svc)

    def status(self, svc):
        """
        Displays the full systemctl status output of the given service. 
        """
        if svc == 'dynamite':
            svc = 'dynamite.target'
        res = self._get_svc_status(svc)
        print("[+] {} status:\n{}".format(svc, res.out))

    def start(self, svc):
        """
        Start the specified service and show the result. 
        """
        print("[+] Starting {}\n".format(svc))
        res = self._exec_update("start", svc)
        if res[1] == True:
            print("[+] Success. {} is running\n".format(svc))
        else:
            print("[-] Failed. {} is not running\n".format(svc))
        
    def start_dynamite(self, stdout=False):
        """
        Start Dynamite Services
        What gets started depends on the node type.  If running as Agent this will start
        zeek, suricata and filebeat. 
        """
        print("Starting Dynamite Services\n")
        res = self._exec_update("start", "dynamite.target")
        print("Dynamite Services Running: {}\n".format(res[1]))
        
    def stop_dynamite(self, stdout=False):
        """
        Stop all Dynamite services.
        What gets stopped depends on the node type.  If running as Agent this will stop
        zeek, suricata and filebeat. 
        """
        print("Stopping Dynamite Services\n")
        res = self._exec_update("stop", "dynamite.target")
        print("Dynamite Services Running: {}\n".format(res[1]))

    def stop_zeek(self, stdout=False):
        """
        Stop Zeek Services
        """
        print("Stopping Zeek\n")
        res = self._exec_update("stop", "zeek")
        print("Zeek is running: {}\n".format(res[1]))

    def start_zeek(self, stdout=False):
        """
        Start Zeek Services

        :return: Print output to console
        """
        print("Starting Zeek\n")
        res = self._exec_update("start", "zeek")
        print("Zeek is running: {}\n".format(res[1]))

    def restart_zeek(self, stdout=False):
        """
        Restart Zeek Services.  Note this has the effect of running the following sequence:
            
            broctl stop, broctl clean, broctl install, broctl start

        :return: Print output to console
        """
        print("Restarting Zeek\n")
        self._exec_update("stop", "zeek")
        res = self._exec_update("start", "zeek")
        print("Zeek is running: {}\n".format(res[1]))

    def start_suricata(self, stdout=False):
        """
        Start Suricata services.  
        """
        print("Starting Suricata\n")
        res = self._exec_update("start", "suricata")
        print("Suricata is running: {}\n".format(res[1]))

    def stop_suricata(self, stdout=False):
        """
        Stop Suricata services.  

        :return: Print output to console
        """
        print("Stopping Suricata\n")
        res = self._exec_update("stop", "suricata")
        print("Suricata is running: {}\n".format(res[1]))

    def restart_suricata(self, stdout=False):
        """
        Restart Suricata services.  

        :return: Print output to console
        """
        print("Restarting Suricata\n")
        self._exec_update("stop", "suricata")
        res = self._exec_update("start", "suricata")
        print("Suricata is running: {}\n".format(res[1]))

    def start_filebeat(self, stdout=False):
        """
        Start Filebeat services.  

        :return: Print output to console
        """
        print("Starting Filebeat\n")
        res = self._exec_update("start", "filebeat")
        print("Filebeat is running: {}\n".format(res[1]))

    def stop_filebeat(self, stdout=False):
        """
        Stop Filebeat services.  

        :return: Print output to console
        """
        print("Stopping Filebeat\n")
        res = self._exec_update("stop", "filebeat")
        print("Filebeat is running: {}\n".format(res[1]))

    def restart_filebeat(stdout=False):
        """
        Restart Filebeat services.  

        :return: Print output to console
        """
        print("Restarting Filebeat\n")
        self._exec_update("stop", "filebeat")
        res = self._exec_update("start", "filebeat")
        print("Filebeat is running: {}\n".format(res[1]))

class SystemdConfigurator:
    """
    Provides an interface for installing, enabling and disabling Dynamite Services.
    """
    def __init__(self,
                 interfaces=None,
                 stdout=True,
                 verbose=False):
        """
        :param interfaces: List of inspection interfaces to monitor
        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """
        if not path.exists(UNIT_FILE_DIR):
            raise Exception("Systemd unit file directory not found. Is systemd installed? {}".format(UNIT_FILE_DIR))
        else:
            self.unit_file_dir = UNIT_FILE_DIR

        # Verify systemctl is installed and in path, bail if not 
        p = subprocess.Popen('which systemctl', stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=True)
        p.communicate()
        if p.returncode != 0:
            raise Exception('Systemctl not found, is it installed?  {}\n'.format(p.stderr.read()))

        self.stdout = stdout
        self.verbose = verbose
        self.interfaces = interfaces

    # @staticmethod
    # def pfring_is_loaded():
    #     """
    #     Verify PF_RING kernel module is loaded

    #     :return: bool
    #     """
    #     return pf_ring.PFRingProfiler().is_running
    # )

    def install_agent_unit_files(self, stdout=False):
        """
        Install Dynamite Agent systemd unit files 

        :return: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Installing Dynamite Agent Services.\n')
            sys.stdout.flush()

        for sfile in AGENT_UNITS:
            try:
                copy(sfile, self.unit_file_dir)
            except Exception as e:
                sys.stderr.write("[-] Failed to install unit file: {}\n".format(e))
                return False
        
        p = subprocess.Popen('systemctl enable dynamite.target', stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        p.communicate()
        if p.returncode != 0:
            sys.stderr.write('[-] Failed to enable the Dynamite service: {}\n'.format(p.stderr.read()))
            return False
        return True