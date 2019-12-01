import os
import pty
import sys
import time
import json
import base64
import shutil
import signal
import tarfile
import traceback
import subprocess
from multiprocessing import Process
from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.services.data import embedded_images
from dynamite_nsm.services.elasticsearch import ElasticProfiler

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

try:
    from urllib2 import urlopen
    from urllib2 import URLError
    from urllib2 import HTTPError
    from urllib2 import Request
except Exception:
    from urllib.request import urlopen
    from urllib.error import URLError
    from urllib.error import HTTPError
    from urllib.request import Request
    from urllib.parse import urlencode

CONFIGURATION_DIRECTORY = '/etc/dynamite/dynamite_sdk/'
NOTEBOOK_HOME = '/home/jupyter/lab/'


class DynamiteLabConfigurator:
    """
    Wrapper for configuring dynamite-sdk-lite config.cfg
    """

    tokens = {
        'elasticsearch_url': 'AUTHENTICATION',
        'elasticsearch_user': 'AUTHENTICATION',
        'elasticsearch_password': 'AUTHENTICATION',
        'timeout': 'SEARCH',
        'max_results': 'SEARCH'
    }

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        """
        :param configuration_directory: The directory that stores the JupyterHub and DynamiteSDK configurations
        """
        self.configuration_directory = configuration_directory
        self.elasticsearch_url = None
        self.elasticsearch_user = None
        self.elasticsearch_password = None
        self.timeout = None
        self.max_results = None
        self.config = self._parse_lab_config()

    def _parse_lab_config(self):
        """
        :return: A dictionary representing the configurations stored within node.cfg
        """
        config_parser = ConfigParser()
        config_parser.readfp(open(os.path.join(self.configuration_directory, 'config.cfg')))
        for section in config_parser.sections():
            for item in config_parser.items(section):
                key, value = item
                setattr(self, key, value)
        return config_parser

    def write_config(self):
        """
        Write the DynamiteSDK config file
        """
        for k, v in vars(self).items():
            if k not in self.tokens.keys():
                continue
            section = self.tokens[k]
            self.config.set(section, k, v)
        with open(os.path.join(self.configuration_directory, 'config.cfg'), 'w') as configfile:
            self.config.write(configfile)


class DynamiteLabInstaller:
    """
    Provides a simple interface for installing a new Installing the DynamiteLab environment
        - Jupyterhub
        - dynamite-sdk-lite
    """
    def __init__(self,
                 elasticsearch_host=None,
                 elasticsearch_port=None,
                 elasticsearch_password='changeme',
                 jupyterhub_host=None,
                 jupyterhub_password='changeme',
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 notebook_home=NOTEBOOK_HOME,
                 download_dynamite_sdk_archive=True,
                 stdout=False,
                 verbose=False):
        """
        :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
        :param elasticsearch_port: A port number for the target elasticsearch instance
        :param elasticsearch_password: The password used for authentication across all builtin ES users
        :param jupyterhub_host: The host by which users can access this instance;
                                (Used for creating kibana -> Jupyter hyperlinks)
        :param jupyterhub_password: The password used for authenticating to jupyterhub (via jupyter user)
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/dynamite_sdk/)
        :param notebook_home: The path where Jupyter notebooks are stored
        :param download_dynamite_sdk_archive: If True, download the DynamiteSDK archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include output from system utilities
        """

        self.elasticsearch_host = elasticsearch_host
        self.elasticsearch_port = elasticsearch_port
        self.elasticsearch_password = elasticsearch_password
        self.jupyterhub_host = jupyterhub_host
        self.jupyterhub_password = jupyterhub_password
        self.configuration_directory = configuration_directory
        self.notebook_home = notebook_home
        if download_dynamite_sdk_archive:
            self.download_dynamite_sdk(stdout=stdout)
            self.extract_dynamite_sdk(stdout=stdout)
        if not self.install_jupyterhub_dependencies(stdout=stdout, verbose=verbose):
            raise Exception("Could not install jupyterhub dependencies.")
        if not self.install_jupyterhub(stdout=stdout):
            raise Exception("Could not install jupyterhub.")
        if stdout:
            sys.stdout.write('[+] Creating jupyter user in dynamite group.\n')
            sys.stdout.flush()
        utilities.create_jupyter_user(password=self.jupyterhub_password)
        self.stdout = stdout
        self.verbose = verbose

        if not elasticsearch_host:
            if ElasticProfiler().is_installed:
                self.elasticsearch_host = 'localhost'
            else:
                raise Exception("Elasticsearch must either be installed locally, or a remote host must be specified.")

    @staticmethod
    def _link_jupyterhub_binaries():
        paths = [
            ('/usr/local/bin/jupyter', '/usr/bin/jupyter'),
            ('/usr/local/bin/jupyterhub', '/usr/bin/jupyterhub'),
            ('/usr/local/bin/jupyterhub-singleuser', '/usr/bin/jupyterhub-singleuser'),
            ('/usr/local/bin/jupyter-bundlerextension', '/usr/bin/jupyter-bundlerextension'),
            ('/usr/local/bin/jupyter-kernel', '/usr/bin/jupyter-kernel'),
            ('/usr/local/bin/jupyter-migrate', '/usr/bin/jupyter-migrate'),
            ('/usr/local/bin/jupyter-nbconvert', '/usr/bin/jupyter-nbconvert'),
            ('/usr/local/bin/jupyter-nbextension', '/usr/bin/jupyter-nbextension'),
            ('/usr/local/bin/jupyter-notebook', '/usr/bin/jupyter-notebook'),
            ('/usr/local/bin/jupyter-run', '/usr/bin/jupyter-run'),
            ('/usr/local/bin/jupyter-serverextension', '/usr/bin/jupyter-serverextension'),
            ('/usr/local/bin/jupyter-troubleshoot', '/usr/bin/jupyter-troubleshoot'),
            ('/usr/local/bin/jupyter-trust', '/usr/bin/jupyter-trust')
        ]
        for path in paths:
            src, dst = path
            try:
                os.symlink(src, dst)
            except OSError:
                pass

    @staticmethod
    def download_dynamite_sdk(stdout=False):
        """
        Download DynamiteSDK archive

        :param stdout: Print output to console
        """
        for url in open(const.DYNAMITE_SDK_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.DYNAMITE_SDK_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_dynamite_sdk(stdout=False):
        """
        Extract DynamiteSDK to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.DYNAMITE_SDK_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.DYNAMITE_SDK_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    @staticmethod
    def install_jupyterhub_dependencies(stdout=False, verbose=False):
        """
        Install the required dependencies required by Jupyterhub

        :param stdout: Print output to console
        :param verbose: Include output from system utilities
        :return: True, if all packages installed successfully
        """
        pacman = package_manager.OSPackageManager(verbose=verbose)
        if not pacman.refresh_package_indexes():
            return False
        packages = None
        if stdout:
            sys.stdout.write('[+] Updating Package Indexes.\n')
            sys.stdout.flush()
        pacman.refresh_package_indexes()
        if stdout:
            sys.stdout.write('[+] Installing dependencies.\n')
            sys.stdout.flush()
        if pacman.package_manager == 'apt-get':
            packages = ['python3', 'python3-pip', 'python3-dev', 'nodejs', 'npm']
        elif pacman.package_manager == 'yum':
            pacman.install_packages(['curl', 'gcc-c++', 'make'])
            p = subprocess.Popen('curl --silent --location https://rpm.nodesource.com/setup_10.x | sudo bash -',
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, close_fds=True)
            p.communicate()
            if p.returncode != 0:
                sys.stderr.write('[-] Could not install nodejs source rpm.\n')
                return False
            packages = ['nodejs', 'python36', 'python36-devel']
            pacman.install_packages(packages)
        if packages:
            pacman.install_packages(packages)
        else:
            sys.stderr.write('[-] A valid package manager could not be found. Currently supports only YUM '
                             'and apt-get.\n')
            return False
        if stdout:
            sys.stdout.write('[+] Installing configurable-http-proxy. This may take some time.\n')
            sys.stdout.flush()
        p = subprocess.Popen('npm install -g configurable-http-proxy', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             shell=True)
        p.communicate()
        if p.returncode != 0:
            sys.stderr.write('[-] Failed to install configurable-http-proxy, ensure npm is installed and in $PATH: {}\n'
                             ''.format(p.stderr.read()))
            return False
        return True

    @staticmethod
    def install_jupyterhub(stdout=False):
        """
        Installs Jupyterhub and ipython[notebook]

        :param stdout: Print the output to console
        :return: True, if installation succeeded
        """
        if stdout:
            sys.stdout.write('[+] Installing JupyterHub and ipython[notebook] via pip3.\n')
            sys.stdout.flush()
        p = subprocess.Popen('python3 -m pip install jupyterhub notebook', stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        p.communicate()
        if p.returncode != 0:
            sys.stderr.write('[-] Failed to install Jupyterhub. '
                             'Ensure python3 and pip3 are installed and in $PATH: {}\n'.format(p.stderr.read()))
            return False
        return True

    def install_kibana_lab_icon(self):
        """
        Install a colored (and linkable) version of the JupyterHub icon across Kibana dashboards

        :return: True, if installed successfully
        """
        try:
            base64string = base64.b64encode('%s:%s' % ('elastic', self.elasticsearch_password))
        except TypeError:
            encoded_bytes = '{}:{}'.format('elastic', self.elasticsearch_password).encode('utf-8')
            base64string = base64.b64encode(encoded_bytes).decode('utf-8')
        # Search for the greyed out Jupyter Notebook Icon in the .kibana index
        if self.stdout:
            sys.stdout.write('[+] Installing DynamiteLab Kibana icon.\n')
            sys.stdout.flush()
        url_request = Request(
            url='http://{}:{}/'.format(self.elasticsearch_host, self.elasticsearch_port) +
                '.kibana/_search?q=visualization.title:"Jupyter:%20Link"',
            headers={'Content-Type': 'application/json', 'kbn-xsrf': True}
        )
        url_request.add_header("Authorization", "Basic %s" % base64string)
        try:
            res = json.loads(urlopen(url_request).read())
        except TypeError as e:
            sys.stderr.write('[-] Could not decode existing DynamiteLab Kibana icon - {}\n'.format(e))
            return False
        except HTTPError as e:
            sys.stderr.write('[-] An error occurred while querying ElasticSearch (.kibana index) - {}'.format(e.read()))
            return False
        except URLError as e:
            sys.stderr.write('[-] Unable to connect to ElasticSearch cluster (.kibana index) - {}\n'.format(e))
            return False
        try:
            # Patch the icon with the new (colored) icon and link
            if self.jupyterhub_host:
                jupyterhub_link = 'http://{}:{}'.format(self.jupyterhub_host, 8000)
            else:
                # If not specified, assume that JupyterHub is hosted on the same server as ElasticSearch
                jupyterhub_link = 'http://{}:{}'.format(self.elasticsearch_host, 8000)
            _id = res['hits']['hits'][0]['_id']
            new_markdown = '[![DynamiteLab](data:image/png;base64,{})]({})'.format(
                embedded_images.JUPYTER_HUB_IMG_ACTIVATED, jupyterhub_link)

            # Visualization Hacking (Document manipulation)
            vis_stats_loaded = json.loads(res['hits']['hits'][0]['_source']['visualization']['visState'])
            doc_params_loaded = vis_stats_loaded['params']
            doc_params_loaded['openLinksInNewTab'] = True
            doc_params_loaded['markdown'] = new_markdown
            vis_stats_loaded['params'] = doc_params_loaded
            res['hits']['hits'][0]['_source']['visualization']['visState'] = json.dumps(vis_stats_loaded)
            url_post_request = Request(
                url='http://{}:{}/'.format(self.elasticsearch_host, self.elasticsearch_port) + '.kibana/_update/' + _id,
                headers={'Content-Type': 'application/json', 'kbn-xsrf': True},
                data=json.dumps({"doc": res['hits']['hits'][0]['_source']})
            )
            url_post_request.add_header("Authorization", "Basic %s" % base64string)
            try:
                urlopen(url_post_request)
            except TypeError:
                url_post_request = Request(
                    url='http://{}:{}/'.format(self.elasticsearch_host,
                                               self.elasticsearch_port) + '.kibana/_update/' + _id,
                    headers={'Content-Type': 'application/json', 'kbn-xsrf': True},
                    data=json.dumps({"doc": res['hits']['hits'][0]['_source']}).encode('utf-8')
                )
                url_post_request.add_header("Authorization", "Basic %s" % base64string)
                urlopen(url_post_request)
        except (IndexError, TypeError) as e:
            sys.stderr.write('[-] An error occurred while patching DynamiteLab Kibana icon {}\n'.format(e))
            return False
        except HTTPError as e:
            sys.stderr.write('[-] An error occurred while querying ElasticSearch (.kibana index) - {}\n'.format(
                e.read()))
            return False
        except URLError as e:
            sys.stderr.write('[-] Unable to connect to ElasticSearch cluster (.kibana index) - {}\n'.format(e))
            return False
        return True

    def setup_dynamite_sdk(self):
        """
        Sets up sdk files; and installs globally
        """
        if self.stdout:
            sys.stdout.write('[+] Copying DynamiteSDK into lab environment.\n')
            sys.stdout.flush()
        subprocess.call('mkdir -p {}'.format(self.notebook_home), shell=True)
        if 'NOTEBOOK_HOME' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating Notebook home path [{}]\n'.format(
                    self.notebook_home))
                subprocess.call('echo NOTEBOOK_HOME="{}" >> /etc/dynamite/environment'.format(
                    self.notebook_home), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        if 'DYNAMITE_LAB_CONFIG' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating Dynamite Lab Config path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo DYNAMITE_LAB_CONFIG="{}" >> /etc/dynamite/environment'.format(
                self.configuration_directory), shell=True)
        sdk_install_cache = os.path.join(const.INSTALL_CACHE, const.DYNAMITE_SDK_DIRECTORY_NAME)
        utilities.copytree(os.path.join(sdk_install_cache, 'notebooks'), self.notebook_home)
        shutil.copy(os.path.join(sdk_install_cache, 'dynamite_sdk', 'config.cfg.example'),
                           os.path.join(self.configuration_directory, 'config.cfg'))
        utilities.set_ownership_of_file(self.notebook_home, user='jupyter', group='jupyter')
        if self.stdout:
            sys.stdout.write('[+] Installing dynamite-sdk-lite (https://github.com/DynamiteAI/dynamite-sdk-lite)\n')
            sys.stdout.write('[+] Depending on your distribution it may take some time to install all requirements.\n')
            sys.stdout.flush()
        if self.verbose:
            p = subprocess.Popen(['python3', 'setup.py', 'install'], cwd=sdk_install_cache)
        else:
            p = subprocess.Popen(['python3', 'setup.py', 'install'], cwd=sdk_install_cache, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        p.communicate()
        dynamite_sdk_config = DynamiteLabConfigurator(configuration_directory=self.configuration_directory)
        dynamite_sdk_config.elasticsearch_url = 'http://{}:{}'.format(self.elasticsearch_host, self.elasticsearch_port)
        dynamite_sdk_config.elasticsearch_user = 'elastic'
        dynamite_sdk_config.elasticsearch_password = self.elasticsearch_password
        dynamite_sdk_config.write_config()

    def setup_jupyterhub(self):
        """
        Sets up jupyterhub configuration; and creates required user for initial login
        """
        if self.stdout:
            sys.stdout.write('[+] Creating lab directories and files.\n')
            sys.stdout.flush()
        source_config = os.path.join(const.DEFAULT_CONFIGS, 'dynamite_lab', 'jupyterhub_config.py')
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        if 'DYNAMITE_LAB_CONFIG' not in open('/etc/dynamite/environment').read():
            if self.stdout:
                sys.stdout.write('[+] Updating Dynamite Lab Config path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo DYNAMITE_LAB_CONFIG="{}" >> /etc/dynamite/environment'.format(
                self.configuration_directory), shell=True)
        shutil.copy(source_config, self.configuration_directory)
        self._link_jupyterhub_binaries()

    def uninstall_kibana_lab_icon(self):
        """
        Restore the greyed out JupyterHub icon across Kibana dashboards

        :return: True, if restored successfully
        """
        try:
            base64string = base64.b64encode('%s:%s' % ('elastic', self.elasticsearch_password))
        except TypeError:
            encoded_bytes = '{}:{}'.format('elastic', self.elasticsearch_password).encode('utf-8')
            base64string = base64.b64encode(encoded_bytes).decode('utf-8')
        # Search for the colored Jupyter Notebook Icon in the .kibana index
        if self.stdout:
            sys.stdout.write('[+] Installing DynamiteLab Kibana icon.\n')
            sys.stdout.flush()
        url_request = Request(
            url='http://{}:{}/'.format(self.elasticsearch_host, self.elasticsearch_port) +
                '.kibana/_search?q=visualization.title:"Jupyter:%20Link"',
            headers={'Content-Type': 'application/json', 'kbn-xsrf': True}
        )
        url_request.add_header("Authorization", "Basic %s" % base64string)
        try:
            res = json.loads(urlopen(url_request).read())
        except TypeError as e:
            sys.stderr.write('[-] Could not decode existing DynamiteLab Kibana icon - {}\n'.format(e))
            return False
        except HTTPError as e:
            sys.stderr.write('[-] An error occurred while querying ElasticSearch (.kibana index) - {}'.format(e.read()))
            return False
        except URLError as e:
            sys.stderr.write('[-] Unable to connect to ElasticSearch cluster (.kibana index) - {}\n'.format(e))
            return False
        try:
            # Patch the icon with the greyed out icon and link
            _id = res['hits']['hits'][0]['_id']
            new_markdown = '![DynamiteLab](data:image/png;base64,{})'.format(
                embedded_images.JUPYTER_HUB_IMG_DEACTIVATED)

            # Visualization Hacking (Document manipulation)
            vis_stats_loaded = json.loads(res['hits']['hits'][0]['_source']['visualization']['visState'])
            doc_params_loaded = vis_stats_loaded['params']
            doc_params_loaded['openLinksInNewTab'] = True
            doc_params_loaded['markdown'] = new_markdown
            vis_stats_loaded['params'] = doc_params_loaded
            res['hits']['hits'][0]['_source']['visualization']['visState'] = json.dumps(vis_stats_loaded)
            url_post_request = Request(
                url='http://{}:{}/'.format(self.elasticsearch_host, self.elasticsearch_port) + '.kibana/_update/' + _id,
                headers={'Content-Type': 'application/json', 'kbn-xsrf': True},
                data=json.dumps({"doc": res['hits']['hits'][0]['_source']})
            )
            url_post_request.add_header("Authorization", "Basic %s" % base64string)
            try:
                urlopen(url_post_request)
            except (IndexError, TypeError):
                url_post_request = Request(
                    url='http://{}:{}/'.format(self.elasticsearch_host,
                                               self.elasticsearch_port) + '.kibana/_update/' + _id,
                    headers={'Content-Type': 'application/json', 'kbn-xsrf': True},
                    data=json.dumps({"doc": res['hits']['hits'][0]['_source']}).encode('utf-8')
                )
                url_post_request.add_header("Authorization", "Basic %s" % base64string)
                urlopen(url_post_request)
        except TypeError as e:
            sys.stderr.write('[-] An error occurred while patching DynamiteLab Kibana icon {}\n'.format(e))
            return False
        except HTTPError as e:
            sys.stderr.write('[-] An error occurred while querying ElasticSearch (.kibana index) - {}\n'.format(
                e.read()))
            return False
        except URLError as e:
            sys.stderr.write('[-] Unable to connect to ElasticSearch cluster (.kibana index) - {}\n'.format(e))
            return False
        return True


class DynamiteLabProfiler:
    """
    Interface for determining whether JupyterHub is installed/configured/running properly.
    """
    def __init__(self, stderr=False):
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_configured = self._is_configured(stderr=stderr)
        self.is_running = self._is_running()

    def __str__(self):
        return json.dumps({
            'INSTALLED': self.is_installed,
            'CONFIGURED': self.is_configured,
            'RUNNING': self.is_running,
        }, indent=1)

    @staticmethod
    def _is_installed(stderr=False):
        try:
            p = subprocess.Popen('jupyterhub --version', shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            p.communicate()
            if p.returncode != 0:
                sys.stderr.write('[-] Jupyterhub is not installed.\n')
                return False
            if not utilities.check_user_exists('jupyter'):
                sys.stderr.write('[-] jupyter user was not created.\n')
                return False
        except OSError:
            if stderr:
                sys.stderr.write('[-] Could not locate JupyterHub in $PATH.')
            return False
        return True

    @staticmethod
    def _is_configured(stderr=False):
        try:
            env_dict = utilities.get_environment_file_dict()
        except IOError:
            if stderr:
                sys.stderr.write('[-] DynamiteLab environment variables haven\'t been created.\n')
            return False
        dynamite_lab_config = env_dict.get('DYNAMITE_LAB_CONFIG')
        if not dynamite_lab_config:
            if stderr:
                sys.stderr.write('[-] DynamiteLab configuration directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not os.path.exists(dynamite_lab_config):
            if stderr:
                sys.stderr.write('[-] DynamiteLab configuration directory could not be located at {}.\n'.format(
                    dynamite_lab_config))
            return False
        try:
            DynamiteLabConfigurator(configuration_directory=dynamite_lab_config)
        except Exception:
            if stderr:
                sys.stderr.write('[-] Un-parsable config.cfg \n')
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return JupyterHubProcess().status()['RUNNING']
        except Exception:
            return False

    def get_profile(self):
        return {
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }


class JupyterHubProcess:
    """
    An interface for start|stop|status|restart of the JupyterHub process
    """
    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.configuration_directory = self.environment_variables.get('DYNAMITE_LAB_CONFIG')
        try:
            self.pid = int(open('/var/run/dynamite/jupyterhub/jupyterhub.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start the JupyterHub process
        :param stdout: Print output to console
        :return: True, if started successfully
        """
        def start_shell_out():
            subprocess.call('jupyterhub -f {} &>/dev/null &'.format(
                os.path.join(self.configuration_directory, 'jupyterhub_config.py')), shell=True, stderr=subprocess.PIPE,
                stdout=None)

        if not os.path.exists('/var/run/dynamite/jupyterhub/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/jupyterhub/'), shell=True)

        if not utilities.check_pid(self.pid):
            Process(target=start_shell_out).start()
        else:
            sys.stderr.write('[-] JupyterHub is already running on PID [{}]\n'.format(self.pid))
            return True
        retry = 0
        self.pid = -1
        time.sleep(5)
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting JupyterHub on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/jupyterhub/jupyterhub.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting JupyterHub on PID [{}]\n'.format(retry + 1, self.pid)
                if stdout:
                    sys.stdout.write(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(5)
                else:
                    return True
            except IOError:
                if stdout:
                    sys.stdout.write(start_message)
                retry += 1
                time.sleep(3)
        return False

    def stop(self, stdout=False):
        """
        Stop the Jupyterhub process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop JupyterHub [{}]\n'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGKILL
                else:
                    # Kill the zombie after the third attempt of asking it to kill itself
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)

                alive = utilities.check_pid(self.pid)
            except Exception as e:
                sys.stderr.write('[-] An error occurred while attempting to stop JupyterHub: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the JupyterHub process

        :param stdout: Print output to console
        :return: True if started successfully
        """
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

    def status(self):
        """
        Check the status of the JupyterHub process

        :return: A dictionary containing the run status and relevant configuration options
        """

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'USER': 'root'
        }


def change_sdk_elasticsearch_password(password='changeme', prompt_user=True, stdout=False):
    """
    Change the DynamiteSDK to ElasticSearch password

    :param password: The password that the SDK will use to connect to ElasticSearch
    :param prompt_user: Whether or not to warn the user
    :param stdout: Print output to console
    :return: True if changed successfully
    """
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('DYNAMITE_LAB_CONFIG')
    if prompt_user:
        resp = utilities.prompt_input(
            'Changing the SDK password can cause your notebooks to lose communication with ElasticSearch. '
            'Are you sure you wish to continue? [no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    dynamite_lab_config = DynamiteLabConfigurator(configuration_directory=configuration_directory)
    dynamite_lab_config.elasticsearch_password = password
    dynamite_lab_config.write_config()
    return True


def install_dynamite_lab(elasticsearch_host='localhost', elasticsearch_port=9200, elasticsearch_password='changeme',
                         jupyterhub_host=None, jupyterhub_password='changeme', stdout=True, verbose=False):
    """
    Install the DynamiteLab environment

    :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
    :param elasticsearch_port: A port number for the target elasticsearch instance
    :param elasticsearch_password: The password used for authentication across all builtin ES users
    :param jupyterhub_host: The host by which users can access this instance;
                            (Used for creating kibana -> Jupyter hyperlinks)
    :param jupyterhub_password: The password used for authenticating to jupyterhub (via jupyter user)
    :param stdout: Print output to console
    :param verbose: Include output from system utilities
    :return: True, if installation was successful
    """

    dynamite_lab_installer = DynamiteLabInstaller(elasticsearch_host=elasticsearch_host,
                                                  elasticsearch_port=elasticsearch_port,
                                                  elasticsearch_password=elasticsearch_password,
                                                  jupyterhub_host=jupyterhub_host,
                                                  jupyterhub_password=jupyterhub_password,
                                                  stdout=stdout, verbose=verbose)
    dynamite_lab_installer.setup_dynamite_sdk()
    dynamite_lab_installer.setup_jupyterhub()
    if not dynamite_lab_installer.install_kibana_lab_icon():
        sys.stderr.write('[-] Failed to install DynamiteLab Kibana icon.\n')
    return DynamiteLabProfiler(stderr=True).is_installed


def prompt_password_change_options():
    """
    Provide the user with a choice between changing the jupyter user password (logging into jupyterhub)
    or changing the password that the SDK uses to connect to ElasticSearch.

    :return: True, if successfully changed
    """
    resp = utilities.prompt_input(
        '1. Change the password the SDK uses to connect to Elasticsearch.\n'
        '2. Change the password for logging into Jupyterhub (jupyter user).\n\n'
        'Select an option [1, 2]: ')
    while str(resp) not in ['', '1', '2']:
        resp = utilities.prompt_input('Select an option [1, 2]: ')
    if str(resp) == '1':
        return change_sdk_elasticsearch_password(utilities.prompt_password('Enter the new Elasticsearch password: '),
                                          prompt_user=False)
    else:
        pty.spawn(['passwd', 'jupyter'])
    return True


def uninstall_dynamite_lab(stdout=False, prompt_user=True):
    """
    Uninstall DynamiteLab

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    :return: True, if uninstall succeeded
    """
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('DYNAMITE_LAB_CONFIG')
    notebook_home = environment_variables.get('NOTEBOOK_HOME')
    dynamite_lab_profiler = DynamiteLabProfiler()
    if not (dynamite_lab_profiler.is_installed and dynamite_lab_profiler.is_configured):
        sys.stderr.write('[-] DynanmiteLab is not installed.\n')
        return False
    dynamite_lab_config = DynamiteLabConfigurator(configuration_directory)
    if prompt_user:
        sys.stderr.write('[-] WARNING! REMOVING DYNAMITE LAB WILL REMOVE ALL JUPYTER NOTEBOOKS.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    if dynamite_lab_profiler.is_running:
        JupyterHubProcess().stop(stdout=stdout)
    try:
        shutil.rmtree(configuration_directory)
        shutil.rmtree(notebook_home)
        shutil.rmtree('/tmp/dynamite/install_cache/', ignore_errors=True)
        env_lines = ''
        for line in open('/etc/dynamite/environment').readlines():
            if 'DYNAMITE_LAB_CONFIG' in line:
                continue
            elif 'NOTEBOOK_HOME' in line:
                continue
            elif line.strip() == '':
                continue
            env_lines += line.strip() + '\n'
        open('/etc/dynamite/environment', 'w').write(env_lines)
        if stdout:
            sys.stdout.write('[+] Uninstalling DynamiteLab Kibana Icon.\n')
        icon_remove_result = DynamiteLabInstaller(elasticsearch_host=dynamite_lab_config.elasticsearch_url.split(
            '//')[1].split(':')[0], elasticsearch_password=dynamite_lab_config.elasticsearch_password,
                                                  elasticsearch_port=dynamite_lab_config.elasticsearch_url.split(
                                 '//')[1].split(':')[1].replace('/', ''),
                                                  download_dynamite_sdk_archive=False).uninstall_kibana_lab_icon()
        if not icon_remove_result:
            sys.stderr.write('[-] Failed to restore DynamiteLab Kibana icon.\n')
            # Not fatal...just annoying;
        if stdout:
            sys.stdout.write('[+] DynamiteLab uninstalled successfully.\n')

    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to uninstall DynamiteLab: ')
        traceback.print_exc(file=sys.stderr)
        return False
    return True
