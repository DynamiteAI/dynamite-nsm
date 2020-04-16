import os
import sys
from datetime import datetime
from dynamite_nsm import const
from dynamite_nsm.utilities import prompt_input
from dynamite_nsm.services.zeek.pf_ring import install
from dynamite_nsm.components.base import execution_strategy


def reboot_system(stdout):
    sys.stderr.write(
        '[-] You must REBOOT for changes to take affect.\n')
    resp = prompt_input('Reboot now? ([no]|yes): ')
    while resp not in ['', 'no', 'yes']:
        resp = prompt_input('Reboot now? ([no]|yes): ')
    if resp != 'yes':
        if stdout:
            sys.stdout.write('[+] Exiting\n')
        exit(0)
    os.system('reboot')


def mark_agent_dependencies_install():
    with open(os.path.join(const.CONFIG_PATH, '.agent_environment_prepared'), 'w') as f:
        f.write(str(datetime.utcnow()))


def check_agent_deps_installed():
    try:
        with open(os.path.join(const.CONFIG_PATH, '.agent_environment_prepared'), 'r') as f:
            install_time = f.read()
            print("[+] Agent dependencies were installed on {}. You may proceed with agent installation.".format(
                install_time))
            exit(0)
    except IOError:
        return


class AgentDependencyInstallStrategy(execution_strategy.BaseExecStrategy):

    def __init__(self, stdout, verbose):
        execution_strategy.BaseExecStrategy.__init__(
            self,
            strategy_name="agent_dependency_install",
            strategy_description="Install Linux kernel development headers.",
            functions=(
                check_agent_deps_installed,
                install.InstallManager.install_dependencies,
                mark_agent_dependencies_install,
                reboot_system
            ),
            arguments=(
                # check_agent_deps_installed,
                {},
                # install.InstallManager.install_dependencies
                {
                    "stdout": bool(stdout),
                    "verbose": bool(verbose)
                },
                # mark_agent_dependencies_install
                {},
                # reboot_system
                {
                    "stdout": bool(stdout)
                },
            ),
            return_formats=(
                None,
                None,
                None,
                None
            )
        )


# Test Functions


def run_install_strategy():
    agt_deps_install_strategy = AgentKernelModulesInstallStrategy(
        stdout=True,
        verbose=True
    )
    agt_deps_install_strategy.execute_strategy()


if __name__ == '__main__':
    run_install_strategy()
    pass
