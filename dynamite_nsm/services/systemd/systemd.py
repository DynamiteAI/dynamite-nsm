
import os
from shutil import copy 
import sys 
import subprocess
import inspect
#from dynamite_nsm.services.helpers import pf_ring

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
    Provides a wrapper for systemctl for managing Dynamite services.
    """
    # Class variables
    UNIT_FILE_DIR = '/etc/systemd/system'
    AGENT_UNITS = ['dynamite.target', 'filebeat.service', 'suricata.service', 'zeek.service']

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

        for svc in self.AGENT_UNITS:
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

    def _enable_svc(self, svc):
        """
        Execute the systemctl enable command for the given service. 
        """
        return self._exec('enable', svc, [])   
    
    def _disable_svc(self, svc):
        """
        Execute the systemctl disable command for the given service. 
        """
        return self._exec('disable', svc, [])   

    def _get_comp_state(self, component):
        """
        Retrieve the ActiveState and LoadState from systemctl for a given unit name. 
        """
        state = {'LoadState':None, 'ActiveState':None}
        res = self._exec('show', component, ['-p ActiveState -p LoadState'])
        if res.exit == 0 and res.err == '' and res.out != '':
            state = {l.split('=')[0].strip() : l.split('=')[1].strip() for l in res.out.split('\n') if '=' in l}
        return state 
 
    def _get_comp_status(self, component):
        """
        Convert ActiveState and LoadState to status report for a given component. 
        
        :return: dict() with keys 'RUNNING' and 'ENABLED'
        """
        status = {'ENABLED':False, 'RUNNING':False}
        res = self._exec('show', component, ['-p ActiveState -p LoadState'])
        if res.exit == 0 and res.err == '' and res.out != '':
            state = {l.split('=')[0].strip() : l.split('=')[1].strip() for l in res.out.split('\n') if '=' in l}
            if state['LoadState'] == 'loaded':
                status['ENABLED'] = True
            if state['ActiveState'] == 'active':
                status['RUNNING'] = True
        return status 

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

        return (comp, self.__getattribute__(comp_running), self.__getattribute__(comp_enabled))

    def _exec(self, cmd=None, svc=None, args=None):
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
        Executes the given systemctl cmd for the given component and updates the component's status in the instance object. 

        :return:  A tuple in the form of: (<"service name">, Running (T/F), Enabled (T/F))
        """
        self._exec(cmd, svc, [])
        return self._update_comp_status(svc)

    def daemon_reload(self):
        """
        Executes `systemctl daemon-reload` to reload all systemd unit files.   

        :return:  True if successful.  False otherwise. 
        """
        p = subprocess.Popen('systemctl daemon-reload', stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        if p.returncode == 0:
            return True
        else:
            return False 

    def enable(self, svc):
        """
        Enable the given service. This will cause it to run at boot after network services have started.

        :return: True if successful. False otherwise. 
        """
        sys.stderr.write("[+] Enabling {}\n".format(svc))
        if svc == 'dynamite':
            svc = 'dynamite.target'
        res = self._exec_update("enable", svc)
        if res[2] == True:
            sys.stderr.write("[+] {} was enabled successfully.\n".format(svc))
            return True 
        else:
            sys.stderr.write("[-] Unable to enable {}\n".format(svc))
            return False 

    def disable(self, svc):
        """
        Disable the given service. This will prevent it from running at boot. 
        """
        if svc == 'dynamite':
            svc = 'dynamite.target'
        res = self._exec_update("disable", svc)
        if res[2] == False:
            sys.stderr.write("[+] Successfully disabled {}.\n".format(svc))
            return True
        else:
            sys.stderr.write("[-] Failed to disable {}.\n".format(svc))
            return False 
        
    def status(self, svc):
        """
        Displays the full systemctl status output for the given service. 
        """
        sys.stderr.write("[+] {} status:\n".format(svc))
        if svc == 'dynamite':
            svc = 'dynamite.target'
        res = self._get_svc_status(svc)
        sys.stderr.write(res.out + '\n')

    def _start(self, svc, stdout=False):
        """
        Start the specified service and show the result. 
        """
        if stdout:
            sys.stdout.write("[+] Starting {}\n".format(svc))

        if svc == 'dynamite':
            svc = 'dynamite.target'
        res = self._exec_update("start", svc)
        if res[1] == True:
            if stdout:
                sys.stderr.write("[+] {} started successfully\n".format(svc))
            return True
        else:
            sys.stderr.write("[-] {} failed to start\n".format(svc))
            return False 

    # Need this for each agent service 
    # 'INSTALLED': self.is_installed,
    # 'RUNNING': self.is_running,

    def dynamite_status(self, stdout=False):
        """
        Test if the Dynamite services target is enabled and running. 

        :return: dict() of {'ENABLED': True/False, 'RUNNING': True/False}
        """
        return self._get_comp_status('dynamite.target')

    def zeek_status(self, stdout=False):
        """
        Test if Zeek is enabled and running. 

        :return: dict() of {'ENABLED': True/False, 'RUNNING': True/False}
        """
        return self._get_comp_status('zeek')

    def suricata_status(self, stdout=False):
        """
        Test if Suricata is enabled and running. 

        :return: dict() of {'ENABLED': True/False, 'RUNNING': True/False}
        """
        return self._get_comp_status('suricata')

    def filebeat_status(self, stdout=False):
        """
        Test if Filebeat is enabled and running. 

        :return: dict() of {'ENABLED': True/False, 'RUNNING': True/False}
        """
        return self._get_comp_status('filebeat')

    def _stop(self, svc):
        """
        Stop the specified service and show the result. 
        """
        sys.stderr.write("[+] Stopping {}\n".format(svc))
        if svc == 'dynamite':
            svc = 'dynamite.target'
        res = self._exec_update("stop", svc)
        if res[1] == False:
            sys.stderr.write("[+] Successfully stopped {}\n".format(svc))
            return True 
        else:
            sys.stderr.write("[-] Failed to stop {}\n".format(svc))
            return False 

    def enable_agent(self, stdout=False):
        """
        Enable Dynamite Agent services. 
        """
        return self.enable("dynamite")

    def disable_agent(self, stdout=False):
        """
        Disable Dynamite Agent services. 
        """
        return self.disable("dynamite")

    def start_agent(self, stdout=False):
        """
        Start Dynamite Agent services zeek, suricata and filebeat. 
        """
        self._start("dynamite")
        
    def stop_agent(self, stdout=False):
        """
        Stop all Dynamite Agent services zeek, suricata and filebeat.
        """
        self._stop("dynamite")

    def stop_zeek(self, stdout=False):
        """
        Stop Zeek Services
        """
        self._stop("zeek")

    def start_zeek(self, stdout=False):
        """
        Start Zeek Services

        :return: Print output to console
        """
        self._start("zeek")

    def restart_zeek(self, stdout=False):
        """
        Restart Zeek Services.  Note this has the effect of running the following sequence:
            
            broctl stop, broctl clean, broctl install, broctl start

        :return: Print output to console
        """
        if stdout:
            sys.stdout.write("[+] Restarting Zeek.\n")
        self._stop("zeek")
        self._start("zeek")

    def start_suricata(self, stdout=False):
        """
        Start Suricata services.  
        """
        self._start("suricata")

    def stop_suricata(self, stdout=False):
        """
        Stop Suricata services.  

        :return: Print output to console
        """
        self._stop("suricata")

    def restart_suricata(self, stdout=False):
        """
        Restart Suricata services.  

        :return: Print output to console
        """
        sys.stderr.write("Restarting Suricata\n")
        self._stop("suricata")
        self._start("suricata")
        
    def start_filebeat(self, stdout=False):
        """
        Start Filebeat services.  

        :return: Print output to console
        """
        self._start("filebeat")

    def stop_filebeat(self, stdout=False):
        """
        Stop Filebeat services.  

        :return: Print output to console
        """
        self._stop("filebeat")

    def restart_filebeat(self, stdout=False):
        """
        Restart Filebeat services.  

        :return: Print output to console
        """
        sys.stderr.write("Restarting Filebeat\n")
        self._stop("filebeat")
        self._start("filebeat")
        
    def install_agent_unit_files(self, stdout=False):
        """
        Install Dynamite Agent systemd unit files 
        """
        sys.stdout.write('[+] Installing Dynamite Agent services.\n')
        sys.stdout.flush()

        for sfile in self.AGENT_UNITS:
            try:
                copy(sfile, self.UNIT_FILE_DIR)
            except Exception as e:
                sys.stderr.write("[-] Failed to install unit file {}: {}\n".format(sfile, e))
                sys.stderr.flush()
                return False

        # Tell systemd to reload unit files 
        self.daemon_reload()

        if self.enable("dynamite.target"):
            sys.stdout.write('[+] Dynamite Agent services installed and enabled.\n')
            sys.stdout.flush()
            return True 
        else:
            sys.stderr.write("[-] Failed to enabled Dynamite Agent services\n".format(sfile, e))
            sys.stderr.flush()
            return False

    def uninstall_agent_unit_files(self, stdout=False):
        """
        Uninstall Dynamite Agent systemd services 
        """
        sys.stdout.write('[+] Uninstalling Dynamite Agent services.\n')
        sys.stdout.flush()

        if self.dynamite_running:
            self.stop_agent()
        self.disable_agent()
        for sfile in self.AGENT_UNITS:
            try:
                os.remove(os.path.join(self.UNIT_FILE_DIR, sfile))
            except Exception as e:
                sys.stderr.write("[-] Failed to delete unit file {}: {}\n".format(sfile, e))
                sys.stderr.flush()
        self.daemon_reload()


    
        