import sys
import json

from lib import zeek
from lib import pf_ring
from lib import filebeat


def install_agent():
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


def status_agent():
    zeek_p = zeek.ZeekProcess()
    filebeat_p = filebeat.FileBeatProcess()
    pf_ring_prof = pf_ring.PFRingProfiler()
    sys.stdout.write(zeek_p.status())
    agent_status = dict(
        agent_processes={
            'pf_ring': pf_ring_prof.get_profile(),
            'filebeat': filebeat_p.status()
        }
    )
    sys.stdout.write(json.dumps(agent_status, indent=1) + '\n')
    sys.stdout.flush()


def point_agent(host, port):
    filebeat_config = filebeat.FileBeatConfigurator()
    filebeat_config.set_logstash_targets(['{}:{}'.format(host, port)])
    filebeat_config.write_config()
    sys.stdout.write('[+] Agent is now pointing to Logstash [{}:{}]\n'.format(host, port))
    sys.stdout.write('[+] Agent must be restarted for changes to take effect.\n')


def start_agent():
    sys.stdout.write('[+] Starting agent processes.\n')
    zeek_p = zeek.ZeekProcess()
    if not zeek_p.start(stdout=True):
        sys.stderr.write('[-] Could not start agent.zeek_process.\n')
        sys.exit(1)
    filebeat_p = filebeat.FileBeatProcess()
    if not filebeat_p.start(stdout=True):
        sys.stderr.write('[-] Could not start agent.filebeat.\n')
        sys.exit(1)
    sys.exit(0)

def stop_agent():
    sys.stdout.write('[+] Stopping agent processes.\n')
    zeek_p = zeek.ZeekProcess()
    if not zeek_p.stop(stdout=True):
        sys.stderr.write('[-] Could not stop agent.zeek_process.\n')
        sys.exit(1)
    filebeat_p = filebeat.FileBeatProcess()
    if not filebeat_p.stop(stdout=True):
        sys.stderr.write('[-] Could not stop agent.filebeat.\n')
        sys.exit(1)
    sys.exit(0)


def prepare_agent():
    pf_ring_install = pf_ring.PFRingInstaller()
    if not pf_ring_install.install_dependencies():
        sys.stderr.write('[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
        sys.exit(1)
    sys.stdout.write('[+] *** Development Kernel Packages & Build Tools Installed. Please Reboot ***\n\n')
    sys.stdout.write('[+] After reboot, continue installation with: \'dynamite.py install monitor\'.\n')
    sys.stdout.flush()
    sys.exit(0)