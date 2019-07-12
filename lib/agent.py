import os
import sys
from datetime import datetime


from lib import zeek
from lib import pf_ring
from lib import filebeat


def is_agent_environment_prepared():
    return os.path.exists('/opt/dynamite/.agent_environment_prepared')


def install_agent(network_interface, agent_label, logstash_target):
    """
    :param network_interface: The network interface that the agent should analyze traffic on
    :param agent_label: A descriptive label representing the
    segment/location on your network that your agent is monitoring
    :param logstash_target: The host port combination for the target Logstash server (E.G "localhost:5044")
    :return: True, if install succeeded
    """
    if not is_agent_environment_prepared():
        sys.stderr.write('[-] The environment must first be prepared prior to agent installation. \n')
        sys.stderr.write('[-] This includes the installation of kernel development headers, '
                         'required for PF_RING kernel modules to be loaded. \n')
        sys.stderr.write('[-] To prepare the agent environment run \'dynamite.py prepare agent\'.\n')
        sys.stderr.flush()
        return False
    zeek_installer = zeek.ZeekInstaller()
    zeek_profiler = zeek.ZeekProfiler(stderr=True)
    filebeat_installer = filebeat.FileBeatInstaller()
    filebeat_profiler = filebeat.FileBeatProfiler()
    if zeek_profiler.is_running or filebeat_profiler.is_running:
        sys.stderr.write('[-] Please stop the agent before attempting re-installation.\n')
        return False
    if not zeek_profiler.is_downloaded:
        zeek_installer.download_zeek(stdout=True)
        zeek_installer.extract_zeek(stdout=True)
    else:
        sys.stdout.write('[+] Zeek has already been downloaded to local cache. Skipping Zeek Download.\n')
    if not zeek_profiler.is_installed:
        if not zeek_installer.install_dependencies():
            sys.stderr.write('[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
            return False
        zeek_installer.setup_zeek(network_interface=network_interface, stdout=True)
    else:
        sys.stdout.write('[+] Zeek has already been installed on this system. Skipping Zeek Installation.\n')
    if not filebeat_profiler.is_downloaded:
        filebeat_installer.download_filebeat(stdout=True)
        filebeat_installer.extract_filebeat(stdout=True)
    else:
        sys.stdout.write('[+] FileBeat has already been downloaded to local cache. Skipping FileBeat Download.\n')
    if not filebeat_profiler.is_installed:
        filebeat_installer.setup_filebeat(stdout=True)
        filebeat_config = filebeat.FileBeatConfigurator()
        filebeat_config.set_logstash_targets([logstash_target])
        filebeat_config.set_agent_tag(agent_label)
    else:
        sys.stdout.write('[+] FileBeat has already been installed on this system. Skipping FileBeat Installation.\n')

    pf_ring_post_install_profiler = pf_ring.PFRingProfiler()
    zeek_post_install_profiler = zeek.ZeekProfiler()
    filebeat_post_install_profiler = filebeat.FileBeatProfiler()
    if not pf_ring_post_install_profiler.is_running:
        sys.stderr.write('[-] PF_RING kernel module was not loaded properly.\n')
        return False
    if zeek_post_install_profiler.is_installed and filebeat_post_install_profiler.is_installed:
        sys.stdout.write('[+] Agent installation complete. Start the agent: \'dynamite.py start agent\'.\n')
        sys.stdout.flush()
        return True
    return False


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
    *** IMPORTANT A REBOOT IS REQUIRED AFTER RUNNING THIS METHOD ***

    :return: True, if successfully prepared
    """
    if is_agent_environment_prepared():
        agent_preparation_date = open('/opt/dynamite/.agent_environment_prepared').read()
        sys.stderr.write('[-] This environment has already been prepared ({}). '
                         'You can proceed with agent installation.\n'.format(agent_preparation_date))
        sys.stderr.write('[-] \'dynamite.py install agent\'.\n')
        sys.stderr.flush()
        return False
    pf_ring_install = pf_ring.PFRingInstaller()
    if not pf_ring_install.install_dependencies():
        sys.stderr.write('[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
        return False
    with open('/opt/dynamite/.agent_environment_prepared', 'w') as f:
        f.write(datetime.utcnow())
    sys.stdout.write('[+] *** Development Kernel Packages & Build Tools Installed. Please Reboot ***\n\n')
    sys.stdout.write('[+] After reboot, continue installation with: \'dynamite.py install monitor\'.\n')
    sys.stdout.flush()
    return True


def start_agent():
    """
    Start the Zeek (BroCtl) and FileBeats processes
    :return: True, if started successfully
    """
    pf_ring_profiler = pf_ring.PFRingProfiler(stderr=True)
    if not pf_ring_profiler.is_running:
        sys.stderr.write('[-] PF_RING kernel modules were not loaded. You may need to re-install the agent.\n')
        return False
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
