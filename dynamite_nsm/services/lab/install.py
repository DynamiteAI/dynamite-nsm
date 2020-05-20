import os
import sys
import json
import base64
import shutil
import logging
import tarfile
import subprocess

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

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.lab.data import embedded_images
from dynamite_nsm.services.lab import config as lab_configs
from dynamite_nsm.services.lab import profile as lab_profile
from dynamite_nsm.services.lab import process as lab_process
from dynamite_nsm.services.lab import exceptions as lab_exceptions
from dynamite_nsm.services.elasticsearch import profile as elastic_profile


class InstallManager:
    """
    Provides a simple interface for installing a new Installing the DynamiteLab environment
        - Jupyterhub
        - dynamite-sdk-lite
    """

    def __init__(self, configuration_directory, notebook_home, elasticsearch_host=None, elasticsearch_port=None,
                 elasticsearch_password='changeme', jupyterhub_host=None, jupyterhub_password='changeme',
                 download_dynamite_sdk_archive=True, extract_dynamite_sdk_archive=True, stdout=True, verbose=False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/dynamite_sdk/)
        :param notebook_home: The path where Jupyter notebooks are stored
        :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
        :param elasticsearch_port: A port number for the target elasticsearch instance
        :param elasticsearch_password: The password used for authentication across all builtin ES users
        :param jupyterhub_host: The host by which users can access this instance;
                                (Used for creating kibana -> Jupyter hyperlinks)
        :param jupyterhub_password: The password used for authenticating to jupyterhub (via jupyter user)
        :param download_dynamite_sdk_archive: If True, download the DynamiteSDK archive from a mirror
        :param extract_dynamite_sdk_archive: If True, extracts the DynamiteSDK archive
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('LAB', level=log_level, stdout=stdout)

        self.elasticsearch_host = elasticsearch_host
        self.elasticsearch_port = elasticsearch_port
        self.elasticsearch_password = elasticsearch_password
        self.jupyterhub_host = jupyterhub_host
        self.jupyterhub_password = jupyterhub_password
        self.configuration_directory = configuration_directory
        self.notebook_home = notebook_home
        if download_dynamite_sdk_archive:
            try:
                self.download_dynamite_sdk(stdout=stdout)
            except general_exceptions.DownloadError:
                self.logger.error('Failed to download DynamiteSDK archive.')
                raise lab_exceptions.InstallLabError("Failed to download DynamiteSDK archive.")
        if extract_dynamite_sdk_archive:
            try:
                self.extract_dynamite_sdk()
            except general_exceptions.ArchiveExtractionError:
                self.logger.error('Failed to extract DynamiteSDK archive.')
                raise lab_exceptions.InstallLabError("Failed to extract DynamiteSDK archive.")
        try:
            self.install_dependencies(stdout=stdout, verbose=verbose)
            self.install_jupyterhub(stdout=stdout)
        except (general_exceptions.InvalidOsPackageManagerDetectedError,
                general_exceptions.OsPackageManagerInstallError, general_exceptions.OsPackageManagerRefreshError):
            self.logger.error('One or more OS dependencies failed to install.')
            raise lab_exceptions.InstallLabError("One or more OS dependencies failed to install.")
        self.logger.info('Creating jupyter user in dynamite group.')
        utilities.create_jupyter_user(password=self.jupyterhub_password)
        self.stdout = stdout
        self.verbose = verbose

        if not elasticsearch_host:
            if elastic_profile.ProcessProfiler().is_installed:
                self.elasticsearch_host = 'localhost'
            else:
                raise lab_exceptions.InstallLabError(
                    "Elasticsearch must either be installed locally, or a remote host must be specified.")

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

        url = None
        try:
            with open(const.DYNAMITE_SDK_MIRRORS, 'r') as sdk_archive:
                for url in sdk_archive.readlines():
                    if utilities.download_file(url, const.DYNAMITE_SDK_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading DynamiteSDK from {}; {}".format(url, e))

    @staticmethod
    def extract_dynamite_sdk():
        """
        Extract DynamiteSDK to local install_cache
        """

        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.DYNAMITE_SDK_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract DynamiteSDK archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract DynamiteSDK archive; {}".format(e))

    @staticmethod
    def install_dependencies(stdout=True, verbose=False):
        """
        Install the required dependencies required by Jupyterhub

        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('LAB', level=log_level, stdout=stdout)

        pkt_mng = package_manager.OSPackageManager(stdout=stdout, verbose=verbose)
        packages = None
        logger.info('Updating Package Indexes.')
        pkt_mng.refresh_package_indexes()
        logger.info('Installing dependencies.')
        if pkt_mng.package_manager == 'apt-get':
            packages = ['build-essential', 'python3', 'python3-pip', 'python3-dev', 'nodejs', 'npm']
        elif pkt_mng.package_manager == 'yum':
            p = subprocess.Popen('curl --silent --location https://rpm.nodesource.com/setup_10.x | sudo bash -',
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, close_fds=True)
            p.communicate()
            if p.returncode != 0:
                logger.error('Could not install nodejs source rpm.')
                raise general_exceptions.OsPackageManagerInstallError(
                    "Could not install nodejs from third-party RPM; https://rpm.nodesource.com/setup_10.x")
            packages = ['gcc72-c++', 'gcc', 'gcc-c++', 'nodejs', 'python36', 'python36-devel']
        logger.info('Installing the following packages: {}.'.format(packages))
        try:
            pkt_mng.install_packages(packages)
        except general_exceptions.OsPackageManagerInstallError as e:
            logger.warning("Failed to install one or more packages: {}".format(e))
        logger.info('Installing configurable-http-proxy. This may take some time.')
        p = subprocess.Popen('npm install -g configurable-http-proxy', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             shell=True)
        p.communicate()
        if p.returncode != 0:
            try:
                err_msg = p.stderr.read()
            except ValueError:
                err_msg = p.returncode
            logger.error('Failed to install configurable-http-proxy, ensure npm is installed and in $PATH: {}'
                         ''.format(err_msg))
            raise general_exceptions.OsPackageManagerInstallError(
                "Could not install configurable-http-proxy via npm; {}".format(err_msg))

    @staticmethod
    def install_jupyterhub(stdout=True, verbose=False):
        """
        Installs Jupyterhub and ipython[notebook]

        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('LAB', level=log_level, stdout=stdout)
        logger.info('Installing JupyterHub and ipython[notebook] via pip3.')
        p = subprocess.Popen('python3 -m pip install cython numpy jupyterhub notebook', stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        p.communicate()
        if p.returncode != 0:
            logger.error(
                'Failed to install Jupyterhub. Ensure python3 and pip3 are installed and in $PATH: {}'.format(
                    p.returncode))
            general_exceptions.OsPackageManagerInstallError(
                "Failed to install Jupyterhub via pip3. Python3 is required for this component; {}".format(
                    p.returncode))

    def install_kibana_lab_icon(self):
        """
        Install a colored (and linkable) version of the JupyterHub icon across Kibana dashboards
        """

        self.logger.info("Patching JupyterHub Kibana icon.")
        try:
            base64string = base64.b64encode('%s:%s' % ('elastic', self.elasticsearch_password))
        except TypeError:
            encoded_bytes = '{}:{}'.format('elastic', self.elasticsearch_password).encode('utf-8')
            base64string = base64.b64encode(encoded_bytes).decode('utf-8')
        # Search for the greyed out Jupyter Notebook Icon in the .kibana index
        url_request = Request(
            url='http://{}:{}/'.format(self.elasticsearch_host, self.elasticsearch_port) +
                '.kibana/_search?q=visualization.title:"Jupyter:%20Link"',
            headers={'Content-Type': 'application/json', 'kbn-xsrf': True}
        )
        url_request.add_header("Authorization", "Basic %s" % base64string)
        try:
            res = json.loads(urlopen(url_request).read())
        except TypeError as e:
            self.logger.error('Could not decode existing DynamiteLab Kibana icon - {}'.format(e))
            raise lab_exceptions.InstallLabError(
                "Failed to install Kibana icon; Could not decode DynamiteLab Kibana icon image.")
        except HTTPError as e:
            err_msg = e.read()
            self.logger.error('An error occurred while querying ElasticSearch (.kibana index) - {}'.format(err_msg))
            raise lab_exceptions.InstallLabError(
                "Failed to install Kibana icon; An error occurred while querying ElasticSearch (.kibana index) - {}"
                "".format(err_msg))
        except URLError as e:
            self.logger.error('Unable to connect to ElasticSearch cluster (.kibana index) - {}'.format(e))
            raise lab_exceptions.InstallLabError(
                "Failed to install Kibana icon; Unable to connect to ElasticSearch cluster (.kibana index) - {}"
                "".format(e))
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
            self.logger.info("Kibana Icon Links to {}.".format(jupyterhub_link))
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
            self.logger.error('An error occurred while patching DynamiteLab Kibana icon {}\n'.format(e))
            raise lab_exceptions.InstallLabError(
                "Failed to install Kibana icon; Unable to connect to ElasticSearch cluster (.kibana index) - {}"
                "".format(e))
        except HTTPError as e:
            err_msg = e.read()
            self.logger.error('An error occurred while querying ElasticSearch (.kibana index) - {}'.format(err_msg))
            raise lab_exceptions.InstallLabError(
                "Failed to install Kibana icon; An error occurred while querying ElasticSearch (.kibana index) - {}"
                "".format(err_msg))
        except URLError as e:
            self.logger.error('Unable to connect to ElasticSearch cluster (.kibana index) - {}'.format(e))
            raise lab_exceptions.InstallLabError(
                "Failed to install Kibana icon; Unable to connect to ElasticSearch cluster (.kibana index) - {}".format(
                    e))

    def setup_dynamite_sdk(self):
        """
        Sets up sdk files; and installs globally
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Copying DynamiteSDK into lab environment.')
        try:
            utilities.makedirs(self.notebook_home, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
        except Exception as e:
            self.logger.error('General error occurred while attempting to create root directories.')
            self.logger.debug("General error occurred while attempting to create root directories; {}".format(e))
            raise lab_exceptions.InstallLabError(
                "General error occurred while attempting to create root directories; {}".format(e))
        try:
            with open(env_file) as env_f:
                env_str = env_f.read()
                if 'NOTEBOOK_HOME' not in env_str:
                    self.logger.info('Updating Notebook home path [{}]'.format(self.notebook_home))
                    subprocess.call('echo NOTEBOOK_HOME="{}" >> {}'.format(
                        self.notebook_home, env_file), shell=True)
                if 'DYNAMITE_LAB_CONFIG' not in env_str:
                    self.logger.info('Updating Dynamite Lab Config path [{}]'.format(
                        self.configuration_directory))
                    subprocess.call('echo DYNAMITE_LAB_CONFIG="{}" >> {}'.format(
                        self.configuration_directory, env_file), shell=True)
        except IOError:
            self.logger.error("Failed to open {} for reading.".format(env_file))
            raise lab_exceptions.InstallLabError(
                "Failed to open {} for reading.".format(env_file))
        except Exception as e:
            self.logger.error("General error while creating environment variables in {}.")
            self.logger.debug("General error while creating environment variables in {}; {}".format(env_file, e))
            raise lab_exceptions.InstallLabError(
                "General error while creating environment variables in {}; {}".format(env_file, e))
        sdk_install_cache = os.path.join(const.INSTALL_CACHE, const.DYNAMITE_SDK_DIRECTORY_NAME)
        utilities.copytree(os.path.join(sdk_install_cache, 'notebooks'), self.notebook_home)
        shutil.copy(os.path.join(sdk_install_cache, 'dynamite_sdk', 'config.cfg.example'),
                    os.path.join(self.configuration_directory, 'config.cfg'))
        try:
            utilities.set_ownership_of_file(self.notebook_home, user='jupyter', group='jupyter')
        except Exception as e:
            raise lab_exceptions.InstallLabError(
                "General error occurred while attempting to set permissions on root directories; {}".format(e))
        self.logger.info(
            'Installing dynamite-sdk-lite (https://github.com/DynamiteAI/dynamite-sdk-lite), '
            'Depending on your distribution it may take some time to install all requirements.')

        if self.verbose:
            p = subprocess.Popen(['python3', 'setup.py', 'install'], cwd=sdk_install_cache)
        else:
            p = subprocess.Popen(['python3', 'setup.py', 'install'], cwd=sdk_install_cache, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        try:
            p.communicate()
        except Exception as e:
            self.logger.error("General error occurred while installing DynamiteSDK.")
            self.logger.debug("General error occurred while installing DynamiteSDK; {}".format(e))
            raise lab_exceptions.InstallLabError("General error occurred while installing DynamiteSDK; {}".format(e))
        if p.returncode != 0:
            self.logger.error("DynamiteSDK install process returned non-zero exit-code: {}".format(p.returncode))
            raise lab_exceptions.InstallLabError(
                "DynamiteSDK install process returned non-zero exit-code: {}".format(p.returncode))
        try:
            dynamite_sdk_config = lab_configs.ConfigManager(configuration_directory=self.configuration_directory)
        except lab_exceptions.ReadLabConfigError:
            self.logger.error("Failed to read DynamiteSDK config.cfg.")
            raise lab_exceptions.InstallLabError("Failed to read DynamiteSDK config.cfg.")
        dynamite_sdk_config.elasticsearch_url = 'http://{}:{}'.format(self.elasticsearch_host, self.elasticsearch_port)
        dynamite_sdk_config.elasticsearch_user = 'elastic'
        dynamite_sdk_config.elasticsearch_password = self.elasticsearch_password
        try:
            dynamite_sdk_config.write_config()
        except lab_exceptions.WriteLabConfigError:
            self.logger.error("Failed to write DynamiteSDK config.cfg.")
            raise lab_exceptions.InstallLabError("Failed to write DynamiteSDK config.cfg.")

    def setup_jupyterhub(self):
        """
        Sets up jupyterhub configuration; and creates required user for initial login
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info("Creating lab directories and files.")
        source_config = os.path.join(const.DEFAULT_CONFIGS, 'dynamite_lab', 'jupyterhub_config.py')
        try:
            utilities.makedirs(self.configuration_directory, exist_ok=True)
        except Exception as e:
            self.logger.error("General error occurred while attempting to create root directories.")
            self.logger.debug("General error occurred while attempting to create root directories; {}".format(e))
            raise lab_exceptions.InstallLabError(
                "General error occurred while attempting to create root directories; {}".format(e))
        try:
            with open(env_file) as env_f:
                if 'DYNAMITE_LAB_CONFIG' not in env_f.read():
                    self.logger.info('Updating Dynamite Lab Config path [{}]'.format(
                        self.configuration_directory))
                    subprocess.call('echo DYNAMITE_LAB_CONFIG="{}" >> {}'.format(
                        self.configuration_directory, env_file), shell=True)
        except IOError:
            self.logger.error("Failed to open {} for reading.".format(env_file))
            raise lab_exceptions.InstallLabError("Failed to open {} for reading.".format(env_file))
        except Exception as e:
            self.logger.error("General error while creating environment variables in {}.".format(env_file))
            self.logger.debug("General error while creating environment variables in {}; {}".format(env_file, e))
            raise lab_exceptions.InstallLabError(
                "General error while creating environment variables in {}; {}".format(env_file, e))
        shutil.copy(source_config, self.configuration_directory)
        self._link_jupyterhub_binaries()

    def uninstall_kibana_lab_icon(self):
        """
        Restore the greyed out JupyterHub icon across Kibana dashboards

        :return: True, if restored successfully
        """
        self.logger.info("Uninstalling DynamiteLab Kibana icon.")
        try:
            base64string = base64.b64encode('%s:%s' % ('elastic', self.elasticsearch_password))
        except TypeError:
            encoded_bytes = '{}:{}'.format('elastic', self.elasticsearch_password).encode('utf-8')
            base64string = base64.b64encode(encoded_bytes).decode('utf-8')
        # Search for the colored Jupyter Notebook Icon in the .kibana index
        url_request = Request(
            url='http://{}:{}/'.format(self.elasticsearch_host, self.elasticsearch_port) +
                '.kibana/_search?q=visualization.title:"Jupyter:%20Link"',
            headers={'Content-Type': 'application/json', 'kbn-xsrf': True}
        )
        url_request.add_header("Authorization", "Basic %s" % base64string)
        try:
            res = json.loads(urlopen(url_request).read())
        except TypeError as e:
            self.logger.error("Failed to uninstall Kibana icon; Could not decode DynamiteLab Kibana icon image.")
            self.logger.debug("Could not decode existing DynamiteLab Kibana icon - {}".format(e))
            raise lab_exceptions.UninstallLabError(
                "Failed to uninstall Kibana icon; Could not decode DynamiteLab Kibana icon image.")
        except HTTPError as e:
            err_msg = e.read()
            self.logger.error('An error occurred while querying ElasticSearch (.kibana index).')
            self.logger.debug('An error occurred while querying ElasticSearch (.kibana index) - {}'.format(err_msg))
            raise lab_exceptions.UninstallLabError(
                "Failed to uninstall Kibana icon; An error occurred while querying ElasticSearch (.kibana index) - {}"
                "".format(err_msg))
        except URLError as e:
            self.logger.error(
                'Failed to uninstall Kibana icon; Unable to connect to ElasticSearch cluster (.kibana index)')
            self.logger.debug('Unable to connect to ElasticSearch cluster (.kibana index) - {}'.format(e))
            raise lab_exceptions.UninstallLabError(
                "Failed to uninstall Kibana icon; Unable to connect to ElasticSearch cluster (.kibana index) - {}"
                "".format(e))
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
            self.logger.error(
                'Failed to uninstall Kibana icon; An error occurred while patching DynamiteLab Kibana icon.')
            self.logger.debug('General error occurred while patching DynamiteLab Kibana icon {}.'.format(e))
            raise lab_exceptions.UninstallLabError(
                "Failed to uninstall Kibana icon; An error occurred while patching DynamiteLab Kibana icon {}"
                "".format(e))
        except HTTPError as e:
            err_msg = e.read()
            self.logger.error(
                'Failed to uninstall Kibana icon; An error occurred while querying ElasticSearch (.kibana index)')
            self.logger.debug('An error occurred while querying ElasticSearch (.kibana index) - {}'.format(err_msg))
            raise lab_exceptions.UninstallLabError(
                "Failed to uninstall Kibana icon; An error occurred while querying ElasticSearch (.kibana index) - {}"
                "".format(err_msg))
        except URLError as e:
            self.logger.error(
                'Failed to uninstall Kibana icon; Unable to connect to ElasticSearch cluster (.kibana index)')
            self.logger.debug('Unable to connect to ElasticSearch cluster (.kibana index) - {}'.format(e))
            raise lab_exceptions.InstallLabError(
                "Failed to uninstall Kibana icon; Unable to connect to ElasticSearch cluster (.kibana index) - {}"
                "".format(e))


def install_dynamite_lab(configuration_directory, notebook_home, elasticsearch_host='localhost',
                         elasticsearch_port=9200, elasticsearch_password='changeme',
                         jupyterhub_host=None, jupyterhub_password='changeme', stdout=True, verbose=False):
    """
    Install the DynamiteLab environment
    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/dynamite_sdk/)
    :param notebook_home: The path where Jupyter notebooks are stored
    :param elasticsearch_host: A hostname/IP of the target elasticsearch instance
    :param elasticsearch_port: A port number for the target elasticsearch instance
    :param elasticsearch_password: The password used for authentication across all builtin ES users
    :param jupyterhub_host: The host by which users can access this instance;
                            (Used for creating kibana -> Jupyter hyperlinks)
    :param jupyterhub_password: The password used for authenticating to jupyterhub (via jupyter user)
    :param stdout: Print output to console
    :param verbose: Include detailed debug messages
    :return: True, if installation was successful
    """

    dynamite_lab_installer = InstallManager(configuration_directory, notebook_home,
                                            elasticsearch_host=elasticsearch_host,
                                            elasticsearch_port=elasticsearch_port,
                                            elasticsearch_password=elasticsearch_password,
                                            jupyterhub_host=jupyterhub_host, jupyterhub_password=jupyterhub_password,
                                            stdout=stdout, verbose=verbose)
    dynamite_lab_installer.setup_dynamite_sdk()
    dynamite_lab_installer.setup_jupyterhub()
    dynamite_lab_installer.install_kibana_lab_icon()


def uninstall_dynamite_lab(prompt_user=True, stdout=True, verbose=False):
    """
    Uninstall DynamiteLab

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('LAB', level=log_level, stdout=stdout)

    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('DYNAMITE_LAB_CONFIG')
    notebook_home = environment_variables.get('NOTEBOOK_HOME')
    dynamite_lab_profiler = lab_profile.ProcessProfiler()
    if not (dynamite_lab_profiler.is_installed and dynamite_lab_profiler.is_configured):
        raise lab_exceptions.UninstallLabError("DynamiteLab is not installed.")
    dynamite_lab_config = lab_configs.ConfigManager(configuration_directory)
    if prompt_user:
        sys.stderr.write('\n\033[93m[-] WARNING! Removing Dynamite Lab Will Remove All Jupyter Notebooks\033[0m\n')
        resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            return
    if dynamite_lab_profiler.is_running:
        lab_process.ProcessManager().stop()
    shutil.rmtree(configuration_directory)
    shutil.rmtree(notebook_home)
    shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
    env_lines = ''
    try:
        with open(env_file) as env_fr:
            for line in env_fr.readlines():
                if 'DYNAMITE_LAB_CONFIG' in line:
                    continue
                elif 'NOTEBOOK_HOME' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'

        with open(env_file, 'w') as env_fw:
            env_fw.write(env_lines)
    except Exception as e:
        logger.error('General error occurred while attempting to uninstall lab.')
        logger.debug("General error occurred while attempting to uninstall lab; {}".format(e))
        raise lab_exceptions.UninstallLabError(
            "General error occurred while attempting to uninstall lab; {}".format(e))
    InstallManager(
        configuration_directory,
        notebook_home,
        elasticsearch_host=dynamite_lab_config.elasticsearch_url.split('//')[1].split(':')[0],
        elasticsearch_password=dynamite_lab_config.elasticsearch_password,
        elasticsearch_port=dynamite_lab_config.elasticsearch_url.split('//')[1].split(':')[1].replace('/', ''),
        download_dynamite_sdk_archive=False, extract_dynamite_sdk_archive=False).uninstall_kibana_lab_icon()
