import os
import shutil
import tarfile
import requests

from typing import List, Optional, Tuple


from dynamite_nsm import const
from dynamite_nsm import exceptions
from dynamite_nsm import utilities
from dynamite_nsm.services.base import install


def get_deltas(delta_set_name: Optional[str] = const.CONFIG_DELTA_CHANGE_SET,
               configurations_directory: Optional[str] = f'{const.INSTALL_CACHE}/configurations/') \
        -> List[Tuple[str, str, str]]:
    """Get the differences between the base configuration set and a delta change-set as list of changes.

    Args:
        delta_set_name: The name of the change-set (A sub-folder found in `deltas/`) directory
        configurations_directory: The root directory containing both a `base/` directory and `deltas/` sub-directories
    Returns:
        A list of changes
    """
    base_root_dir = f'{configurations_directory}/base/'
    overwrite_root_dir = f'{configurations_directory}/deltas/{delta_set_name}/'
    deltas = []

    # Iterate through our overwrite_directory; this directory will be merged into base_directory
    for overwrite_root, overwrite_dirs, overwrite_files in os.walk(overwrite_root_dir, topdown=True):
        relative_directory = overwrite_root.replace(overwrite_root_dir, '')
        base_directory = os.path.join(base_root_dir, relative_directory)
        if relative_directory.startswith('.git'):
            continue
        # Check if the equivalent overwrite path exists in the base directory
        if not os.path.exists(base_directory):
            # If it doesn't mark the directory for creation
            deltas.append(('directory', 'create', relative_directory))
        for overwrite_file in overwrite_files:
            relative_file = os.path.join(relative_directory, overwrite_file)
            base_file_path = os.path.join(base_root_dir, relative_file)
            overwrite_file_path = os.path.join(overwrite_root_dir, relative_file)
            if not os.path.exists(base_file_path):
                deltas.append(('file', 'write', relative_file))
            else:
                if utilities.get_filepath_md5_hash(overwrite_file_path) != \
                        utilities.get_filepath_md5_hash(base_file_path):
                    deltas.append(('file', 'overwrite', relative_file))
    return deltas


class InstallManager(install.BaseInstallManager):

    def __init__(self, stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        super().__init__('updates.install', verbose, stdout)
        self.stdout = stdout
        self.verbose = verbose

    @staticmethod
    def download_configurations_package(url: Optional[str] = const.DEFAULT_CONFIGURATIONS_URL) -> None:
        """Download a configurations package from a URL
        Args:
            url: A URL where a configurations archive can be downloaded
        Returns:
            None
        """
        try:
            configuration_archive = f'{const.INSTALL_CACHE}/configurations.tar.gz'
            if os.path.exists(configuration_archive):
                utilities.safely_remove_file(configuration_archive)
            response = requests.get(url, stream=True)
            if response.status_code == 200:
                with open(configuration_archive, 'wb') as f:
                    f.write(response.raw.read())
            else:
                raise exceptions.DownloadError(f'Download {url} failed; status: {response.status_code}')
        except PermissionError:
            raise exceptions.RequiresRootError()

    @staticmethod
    def extract_configurations_package(
            archive_path: Optional[str] = f'{const.INSTALL_CACHE}/configurations.tar.gz') -> None:
        """Extract the relevant files from the dynamite `configurations` archive to the install_cache.
        Args:
            archive_path: The path to the archive
        Returns:
            None
        """
        try:
            shutil.rmtree(f'{const.INSTALL_CACHE}/configurations')
            shutil.rmtree(const.DEFAULT_CONFIGS)
        except FileNotFoundError:
            pass
        with tarfile.open(archive_path) as tar:
            members = tar.getmembers()
            if not members:
                raise exceptions.ArchiveExtractionError('Unable to find any members.')
            if not members[0].isdir():
                raise exceptions.ArchiveExtractionError('Root directory not found.')
            selected_members = [member for member in members if
                                member.name.startswith(f'{members[0].name}/base') or member.name.startswith(
                                    f'{members[0].name}/delta')]
            try:
                tar.extractall(members=selected_members, path=const.INSTALL_CACHE)
            except IOError as e:
                raise exceptions.ArchiveExtractionError(f'General extraction error: {e}')
            shutil.move(f'{const.INSTALL_CACHE}/{members[0].name}', f'{const.INSTALL_CACHE}/configurations')

    @staticmethod
    def install_default_mirrors_and_configurations(
            configurations_directory: Optional[str] = f'{const.INSTALL_CACHE}/configurations/',
            dynamite_config_root: Optional[str] = const.CONFIG_PATH, delta_set_name: Optional[str] = None):
        base_root_dir = f'{configurations_directory}/base/'
        for base_root, base_dirs, base_files in os.walk(base_root_dir):
            relative_directory = base_root.replace(base_root_dir, '')
            utilities.makedirs(f'{dynamite_config_root}/{relative_directory}')
            for base_file in base_files:
                relative_file = os.path.join(relative_directory, base_file)
                base_file_path = os.path.join(base_root_dir, relative_file)
                destination_file = f'{dynamite_config_root}/{relative_file}'
                shutil.copy2(base_file_path, destination_file)

        overwrite_root_dir = f'{configurations_directory}/deltas/{delta_set_name}/'
        if os.path.exists(overwrite_root_dir):
            for _type, action, overwrite_relative_path in get_deltas(delta_set_name, configurations_directory):
                if _type == 'directory':
                    if action == 'create':
                        create_dir_path = f'{dynamite_config_root}/{overwrite_relative_path}'
                        utilities.makedirs(create_dir_path)
                elif _type == 'file':
                    if action in ['create', 'overwrite']:
                        source_create_overwrite_file_path = f'{overwrite_root_dir}/{overwrite_relative_path}'
                        dest_create_overwrite_file_path = f'{dynamite_config_root}/{overwrite_relative_path}'
                        shutil.copy2(source_create_overwrite_file_path, dest_create_overwrite_file_path)

    def setup(self, url: Optional[str] = const.DEFAULT_CONFIGURATIONS_URL):
        """Download updates and setup them up.
        Args:
            url: The path to the configuration tar.gz archive.
        Returns:
            None
        """
        self.logger.info(
            'Attempting to download the latest mirrors and default configurations for installable components.')
        self.download_configurations_package(url=url)
        self.extract_configurations_package()
        self.install_default_mirrors_and_configurations()
        self.logger.info(
            'Updates have been applied. The next time you install: elasticsearch, logstash, kibana, zeek, suricata, '
            'or filebeat these updates will be applied to that component.')


if __name__ == '__main__':
    install_mngr = InstallManager(
        stdout=True,
        verbose=True
    )
    install_mngr.setup()
