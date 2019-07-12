import sys

from lib import zeek
from lib import pf_ring
from lib import filebeat


def install_agent():
    """
    Installs the required agent components to module default directories
    """
    zeek_installer = zeek.ZeekInstaller()
    if not zeek_installer.install_dependencies():
        sys.stderr.write('[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
        sys.exit(1)
    zeek_installer.download_zeek(stdout=True)
    zeek_installer.extract_zeek(stdout=True)
    zeek_installer.setup_zeek(stdout=True)
    filebeat_installer = filebeat.FileBeatInstaller()
    filebeat_installer.download_filebeat(stdout=True)
    filebeat_installer.extract_filebeat(stdout=True)
    filebeat_installer.setup_filebeat(stdout=True)


def point_agent(host, port):
    """
    :param host: The logstash host to forward logs too
    :param port: The service port the logstash host is listening on [5044 standard]
    """
    filebeat_config = filebeat.FileBeatConfigurator()
    filebeat_config.set_logstash_targets(['{}:{}'.format(host, port)])
    filebeat_config.write_config()
    sys.stdout.write('[+] Agent is now pointing to Logstash [{}:{}]\n'.format(host, port))
    sys.stdout.write('[+] Agent must be restarted for changes to take effect.\n')


def prepare_agent():
    """
    Install the necessary build dependencies and kernel-headers
    *** IMPORTANT A REBOOT IS REQUIRED AFTER RUNNING THIS FUNCTION ***

    :return: True, if successfully prepared
    """
    pf_ring_install = pf_ring.PFRingInstaller()
    if not pf_ring_install.install_dependencies():
        sys.stderr.write('[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
        return False
    sys.stdout.write('[+] *** Development Kernel Packages & Build Tools Installed. Please Reboot ***\n\n')
    sys.stdout.write('[+] After reboot, continue installation with: \'dynamite.py install monitor\'.\n')
    sys.stdout.flush()
    return True


def start_agent():
    """
    Start the Zeek (BroCtl) and FileBeats processes
    :return: True, if started successfully
    """
    sys.stdout.write('[+] Starting agent processes.\n')
    zeek_p = zeek.ZeekProcess()
    if not zeek_p.start(stdout=True):
        sys.stderr.write('[-] Could not start agent.zeek_process.\n')
        return False
    filebeat_p = filebeat.FileBeatProcess()
    if not filebeat_p.start(stdout=True):
        sys.stderr.write('[-] Could not start agent.filebeat.\n')
        return False
    return True


def status_agent():
    """
    Retrieve the status of the agent processes
    :return: A tuple, where the first element is the zeek process status (string), and second element are
             the FileBeats and PF_RING status
    """
    zeek_p = zeek.ZeekProcess()
    filebeat_p = filebeat.FileBeatProcess()
    pf_ring_prof = pf_ring.PFRingProfiler()
    agent_status = dict(
        agent_processes={
            'pf_ring': pf_ring_prof.get_profile(),
            'filebeat': filebeat_p.status()
        }
    )
    return zeek_p.status(), agent_status


def stop_agent():
    """
    Stop the Zeek (BroCtl) and FileBeats processes
    :return: True, if stopped successfully
    """
    sys.stdout.write('[+] Stopping agent processes.\n')
    zeek_p = zeek.ZeekProcess()
    if not zeek_p.stop(stdout=True):
        sys.stderr.write('[-] Could not stop agent.zeek_process.\n')
        return True
    filebeat_p = filebeat.FileBeatProcess()
    if not filebeat_p.stop(stdout=True):
        sys.stderr.write('[-] Could not stop agent.filebeat.\n')
        return True
    return True
