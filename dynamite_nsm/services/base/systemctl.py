import os
import re
import pwd
import time
import psutil
import logging
import subprocess
from shutil import copy
from typing import Dict, List, Optional, Tuple

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger


UNIT_FILE_DIR = '/etc/systemd/system/'
PID_FILE_DIR = '/var/run/'


def install(path_to_svc: str) -> None:
    """Install a systemd service
    Args:
        path_to_svc: The path to the service/target file
    Returns:
        None
    """

    copy(path_to_svc, UNIT_FILE_DIR)


def uninstall(svc: str) -> None:
    """Uninstall a systemd service
    Args:
        svc: The name of the service or target
    Returns:
        None
    """

    svc = format_svc_string(svc)
    os.remove(os.path.join(UNIT_FILE_DIR, svc))


def format_svc_string(svc: str) -> str:
    """Given a service name add a .target or .service extension if one is not given
    Args:
        svc: The name of the service or target

    Returns:
        The full name of the systemd unit file

    """
    if not str(svc).endswith('.service'):
        svc = svc + '.service'
    return svc


def parse_unit_file(svc: str) -> Dict:
    """Given the name of a service returns a dictionary containing the following sections:
        - ExecStartPre: A list of commands run before the main process is started
        - ExecStart: A list of commands to invoke (main process)
        - ExecStartPost: A list of commands to run after the main process has been started
        - ExecStop: A list of commands to run to kill the main process
        - User: The User under which the process will be run
    Args:
        svc: The name of the service or target

    Returns:
        A dictionary containing relevant sections from the unit file
    """
    unit_file_path = f'{UNIT_FILE_DIR}/{format_svc_string(svc)}'
    user = 'root'
    exec_start_pre_cmds = []
    exec_start_cmds = []
    exec_start_post_cmds = []
    exec_stop_cmds = []

    def get_local_env_variables():
        local_env_variables = utilities.get_environment_file_dict()
        with open(unit_file_path) as unit_file_in:
            for line in unit_file_in.readlines():
                if line.startswith('Environment='):
                    env_var_name, env_var_value = line.replace('"', '').replace('\n', '').split('=')[1:]
                    local_env_variables[env_var_name] = env_var_value
        return local_env_variables

    def substitute_in_variable_values(s: str) -> str:
        for match in re.findall(r'\${[a-zA-Z0-9_]+}', s) + re.findall(r'\$[a-zA-Z0-9_]+', s):
            s = s.strip()
            replace_token, replace_lookup_key = \
                match.strip(), match.strip().replace('{', '').replace('}', '').replace('$', '')
            replace_value = env_variables.get(replace_lookup_key)
            if replace_value:
                s = s.replace(replace_token, replace_value)
        return s

    env_variables = get_local_env_variables()
    with open(unit_file_path) as unit_file_in:
        for line in unit_file_in:
            line = line.strip()
            line = line.replace('"', '').replace('/bin/bash -c', '')
            if line.startswith('ExecStartPre='):
                exec_start_pre_cmds.append('='.join(substitute_in_variable_values(line).split('=')[1:]).strip())
            elif line.startswith('ExecStart='):
                exec_start_cmds.append('='.join(substitute_in_variable_values(line).split('=')[1:]).strip())
            elif line.startswith('ExecStartPost='):
                exec_start_post_cmds.append('='.join(substitute_in_variable_values(line).split('=')[1:]).strip())
            elif line.startswith('User='):
                user = line.strip().split('=')[1]
            elif line.startswith('ExecStop='):
                exec_stop_cmds.append('='.join(substitute_in_variable_values(line).split('=')[1:]).strip())
    return {
        'ExecStartPre': exec_start_pre_cmds,
        'ExecStart': exec_start_cmds,
        'ExecStartPost': exec_start_post_cmds,
        'ExecStop': exec_stop_cmds,
        'User': user
    }


class CmdResult:
    """
    Container class for parsed and decoded systemctl command output
    """

    def __init__(self):
        self.out = None
        self.err = None
        self.exit = None
        self.cmd = None
        self.svc = None


class FallbackCtl:
    """
    Provides a method to enable and control services when systemctl is not available
    """

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('systemctl', level=log_level, stdout=stdout)
        utilities.makedirs(UNIT_FILE_DIR)

    @staticmethod
    def _demote_to_user(user: Optional[str] = 'root'):
        pwnam = pwd.getpwnam(user)
        uid, gid = pwnam.pw_uid, pwnam.pw_gid
        os.setgid(gid)
        os.setuid(uid)

    def search_process(self, proc_name) -> Optional[int]:
        """Search for a PID given a process name
        Args:
            proc_name: The name of the process you are looking for

        Returns:
            The PID if one is found; otherwise None

        """
        for proc in psutil.process_iter():
            try:
                if proc_name.lower() in proc.name().lower():
                    if proc.status() == 'zombie':
                        continue
                    self.logger.debug(f'Found {proc_name} running on {proc.pid}')
                    return proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return None

    def status(self, svc: str) -> CmdResult:
        """Displays the full systemctl status output for the given service.
        Args:
            svc: The name of the service or target
        Returns:
             The current status of the service
        """
        process_name = svc.replace(".service", "")
        cmd_result = CmdResult()
        for proc in psutil.process_iter():
            if process_name.lower() in proc.name().lower():
                cmd_result.cmd = ' '.join(proc.cmdline())
                cmd_result.exit = 0
                cmd_result.out = None
                cmd_result.err = None
        cmd_result.svc = svc
        return cmd_result

    def start(self, svc: str):
        """Start the specified service using the fallback method.
        Args:
            svc: The name of the service or target
        Returns:
             True if started
        """
        systemd_commands = parse_unit_file(svc)
        process_name = svc.replace(".service", "")
        pid_file_name = process_name + '.pid'
        process_name = svc.replace(".service", "")
        self.logger.debug(f'Attempting to start {svc}.')
        # with daemon.DaemonContext(
        #        pidfile=daemon.pidfile.PIDLockFile(f'{PID_FILE_DIR}/{pid_file_name}'), detach_process=True):
        for pre_start_cmd in systemd_commands['ExecStartPre']:
            subprocess.Popen(pre_start_cmd.split(' '), env=utilities.get_environment_file_dict(),
                             preexec_fn=self._demote_to_user(systemd_commands['User']))
        for start_cmd in systemd_commands['ExecStart']:
            subprocess.Popen(start_cmd.split(' '), env=utilities.get_environment_file_dict(),
                             preexec_fn=self._demote_to_user(systemd_commands['User']))
            time.sleep(5)
        return self.search_process(process_name) is not None

    def stop(self, svc: str):
        """Stop the specified service via fallback method.
        Args:
            svc: The name of the service or target
        Returns:
             True if stopped
        """
        systemd_commands = parse_unit_file(svc)
        process_name = svc.replace(".service", "")
        pid_file_name = process_name + '.pid'
        self.logger.debug(f'Attempting to stop {svc}.')
        try:
            with open(f'{PID_FILE_DIR}/{pid_file_name}') as pid_f_in:
                pid = int(pid_f_in.read().strip())
                self.logger.debug(f'Located PID file: {PID_FILE_DIR}/{pid_file_name}; PID: {pid}')
        except FileNotFoundError:
            pid = self.search_process(process_name)
            if pid:
                self.logger.debug(f'Could not locate PID file; found via search; PID: {pid}')
        if systemd_commands['ExecStop']:
            self.logger.debug('Killing via ExecStop')
            for stop_cmd in systemd_commands['ExecStop']:
                if pid and '$MAINPID' in stop_cmd:
                    stop_cmd = stop_cmd.replace('$MAINPID', str(pid))
                stop_p = subprocess.Popen(stop_cmd.split(' '), env=utilities.get_environment_file_dict(),
                                          preexec_fn=self._demote_to_user(systemd_commands['User']))
                stop_p.communicate()
        elif pid:
            self.logger.debug(f'Killing PID: {pid}')
            os.kill(pid, 9)
        utilities.safely_remove_file(f'{PID_FILE_DIR}/{pid_file_name}')
        self.logger.debug(f'Removing PID file: {PID_FILE_DIR}/{pid_file_name}')
        time.sleep(5)
        return self.search_process(process_name) is None


class SystemCtl(FallbackCtl):
    """
    Provides a wrapper for systemctl for managing Dynamite services.
    """

    # Map each role type to a list of associated service unit files

    def __init__(self, roles: Optional[Tuple] = ('agent',), stdout: Optional[bool] = True,
                 verbose: Optional[bool] = False):
        # Placeholder for statically selecting the currently supported roles
        # we need to replace this with some logic (utilities) that
        # get the active roles configured at install time and use that to
        # determine which services get loaded.

        # For now, if no list is provided to the roles kwarg assume
        # the agent role.
        # TODO: Pull Dynamite component role list from file system.
        # all roles.

        # Verify systemctl is installed and in path, bail if not
        super().__init__(stdout=stdout, verbose=verbose)
        p = subprocess.Popen('systemctl', stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        self.fallback_mode = False
        p.communicate()
        if p.returncode != 0:
            self.logger.warning('systemctl was not found. Dropping back into fallback mode; '
                                'you will not be able to enable or disable services.')
            self.fallback_mode = True
            # raise exceptions.CallProcessError('Systemctl not found, is it installed?  {}'.format(p.stderr.read()))

    def _get_svc_status(self, svc: str) -> CmdResult:
        """
        Retrieve the full status output from systemctl for a given service name.
        """
        return self._exec('status', svc, [])

    def _enable_svc(self, svc: str) -> CmdResult:
        """
        Execute the systemctl enable command for the given service.
        """
        return self._exec('enable', svc, [])

    def _disable_svc(self, svc: str) -> CmdResult:
        """
        Execute the systemctl disable command for the given service.
        """
        return self._exec('disable', svc, [])

    def _get_comp_state(self, component: str) -> Dict:
        """
        Retrieve the ActiveState and LoadState from systemctl for a given unit name.
        """
        state = {'LoadState': None, 'ActiveState': None}
        res = self._exec('show', component, ['-p ActiveState -p LoadState'])
        if res.exit == 0 and res.err == '' and res.out != '':
            state = {l.split('=')[0].strip(): l.split('=')[1].strip() for l in res.out.split('\n') if '=' in l}
        return state

    def _get_comp_status(self, component: str) -> Dict:
        """Convert ActiveState and LoadState to status report for a given component.
        Args:
            component: The name of the component
        Returns:
             dict() with keys 'RUNNING' and 'ENABLED'
        """
        status = {'enabled': False, 'running': False}
        res = self._exec('show', component, ['-p ActiveState -p LoadState'])
        if res.exit == 0 and res.err == '' and res.out != '':
            state = {l.split('=')[0].strip(): l.split('=')[1].strip() for l in res.out.split('\n') if '=' in l}
            if state['LoadState'] == 'loaded':
                status['enabled'] = True
            if state['ActiveState'] == 'active':
                status['running'] = True
        return status

    def _update_comp_status(self, component: str) -> Tuple[str, bool, bool]:
        """Update the status attributes of the given component based on the state reported by systemctl.
        Args:
            component: The name of the component
        Returns:
             A Tuple containing the running and enabled state of the component
        """
        state = self._get_comp_state(component)

        comp = component.split('.')[0]
        comp_enabled = comp + "_enabled"
        comp_running = comp + "_running"
        if state['LoadState'] == 'loaded':
            setattr(self, comp_enabled, True)
        else:
            setattr(self, comp_enabled, False)
        if state['ActiveState'] == 'active':
            setattr(self, comp_running, True)
        else:
            setattr(self, comp_running, False)
        return comp, getattr(self, comp_running), getattr(self, comp_enabled)

    @staticmethod
    def _exec(cmd: str, svc: str, args: Optional[List] = None) -> CmdResult:
        """Run commands against systemctl cli utility.
        Args:
            cmd: An action to perform start|stop|restart|reload|enable|disable
            svc: The name of the service or target
            args: An optional list of arguments to pass to systemctl
        Returns:
            A CmdResult instance
        """
        if not args:
            args = []
        res = CmdResult()
        res.svc = svc
        res.cmd = " ".join(["sudo", "systemctl", cmd, svc])
        if args and len(args) > 0:
            for arg in args:
                res.cmd += " " + arg
        p = subprocess.Popen(res.cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        try:
            res.err = err.decode().strip()
            res.out = out.decode().strip()
        except UnicodeDecodeError:
            pass
        res.exit = p.returncode
        return res

    def _exec_update(self, cmd, svc):
        """Executes the given systemctl cmd for the given component and updates the component's status
        in the instance object.

        Args:
            cmd: An action to perform start|stop|restart|reload|enable|disable
            svc: The name of the service or target
        Returns:
              A tuple in the form of (<"service name">, Running (T/F), Enabled (T/F))
        """
        self._exec(cmd, svc, [])
        return self._update_comp_status(svc)

    @staticmethod
    def daemon_reload() -> bool:
        """Executes `systemctl daemon-reload` to reload all systemd unit files.

        Returns:
              True if successful.  False otherwise.
        """
        p = subprocess.Popen('systemctl daemon-reload', stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        p.communicate()
        return p.returncode == 0

    def is_enabled(self, svc: str) -> bool:
        """Determine if a service (or target) is enabled
        Args:
            svc: The name of the service
        Returns:
             True if enabled
        """
        if self.fallback_mode:
            return False
        svc = format_svc_string(svc)
        cmd = self._exec("is-enabled", svc)
        return cmd.out == "enabled"

    def disable(self, svc: str, daemon_reload: Optional[bool] = True) -> bool:
        """Disable the given service. This will prevent it from running at boot.
        Args:
            svc: The name of the service or target
            daemon_reload: If True, reload the daemon configurations
        Returns:
             True if successful. False otherwise.
        """
        svc = format_svc_string(svc)
        if self.fallback_mode:
            self.logger.warning(f'Cannot disable {svc} in fallback mode.')
            return False
        _, _, enabled = self._exec_update("disable", svc)
        if daemon_reload and not enabled:
            self.daemon_reload()
        return enabled

    def enable(self, svc, daemon_reload: Optional[bool] = True) -> bool:
        """Enable the given service. This will cause it to run at boot after network services have started.
        Args:
            svc: The name of the service or target
            daemon_reload: If True, reload the daemon configurations
        Returns:
             True if successful. False otherwise.
        """
        svc = format_svc_string(svc)
        if self.fallback_mode:
            self.logger.warning(f'Cannot enable {svc} in fallback mode.')
            return False
        _, _, enabled = self._exec_update("enable", svc)
        if daemon_reload and enabled:
            self.daemon_reload()
        return enabled

    def install(self, path_to_svc: str) -> None:
        """Install a service to the systemd path
        Args:
            path_to_svc: The path to the service/target file

        Returns:
            None
        """
        self.logger.debug(f'Installing {path_to_svc}.')
        install(path_to_svc)

    def install_and_enable(self, path_to_svc: str) -> bool:
        """Enable and Install a systemd service
        Args:
            path_to_svc: The path to the service/target file
        Returns:
            True if enabled
        """

        copy(path_to_svc, UNIT_FILE_DIR)
        self.logger.debug(f'Copying {path_to_svc} -> {UNIT_FILE_DIR}')
        return self.enable(os.path.basename(path_to_svc))

    def start(self, svc: str) -> bool:
        """Start the specified service.
        Args:
            svc: The name of the service or target
        Returns:
             True if started
        """
        if self.fallback_mode:
            return super().start(svc)
        svc = format_svc_string(svc)
        _, running, _ = self._exec_update("start", svc)
        return running

    def status(self, svc: str) -> CmdResult:
        """Displays the full systemctl status output for the given service.
        Args:
            svc: The name of the service or target
        Returns:
             A the current status of the service
        """
        if self.fallback_mode:
            return super().status(svc)
        svc = format_svc_string(svc)
        return self._get_svc_status(svc)

    def stop(self, svc: str) -> bool:
        """Stop the specified service.
        Args:
            svc: The name of the service or target
        Returns:
             True if stopped
        """
        if self.fallback_mode:
            return super().stop(svc)
        svc = format_svc_string(svc)
        _, running, _ = self._exec_update("stop", svc)
        return not running

    def restart(self, svc: str) -> bool:
        """Restart the specified service.
        Args:
            svc: The name of the service or target
        Returns:
             True if restarted
        """

        return self.stop(svc) and self.start(svc)

    def reload(self, svc: str) -> None:
        """Reload the service
        Args:
            svc: The name of the service or target

        Returns:
            None
        """
        if self.fallback_mode:
            self.logger.warning(f'Cannot reload {svc} in fallback mode.')
            return None
        self._exec('reload', svc)

    def uninstall(self, svc: str) -> None:
        """Uninstall a systemd service
        Args:
            svc: The name of the service or target
        Returns:
            None
        """
        self.logger.debug(f'Uninstalling {svc}.')
        uninstall(svc)

    def uninstall_and_disable(self, svc: str) -> bool:
        """Disable and Uninstall a systemd service
        Args:
            svc: The name of the service or target
        Returns:
            True if disabled
        """

        svc = format_svc_string(svc)
        res = self.disable(svc)
        self.logger.debug(f'Removing {svc} from {UNIT_FILE_DIR}')
        os.remove(os.path.join(UNIT_FILE_DIR, svc))

        return res
