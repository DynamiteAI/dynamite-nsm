import json
import logging
import os
from time import sleep
from typing import List, Optional, TextIO, Union

import requests

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger


def kibana_api_up(kibana_url, username: Optional[str] = 'admin', password: Optional[str] = 'admin'):
    """
    Check if Kibana API is accessible

    :param kibana_url: The full URL to your Kibana instance including the protocol and port
    :param username: The username for logging into Kibana instance
    :param password: The password for logging into Kibana instance
    """
    try:
        r = requests.get(
            url=f'{kibana_url}/api',
            auth=(username, password),
            headers={'kbn-xsrf': 'true'},
            verify=False
        )
    except requests.ConnectionError:
        return False
    return r.status_code == 404


def import_saved_object(file_path: Union[str, TextIO], kibana_url: str, import_attempts: Optional[int] = 10,
                        username: Optional[str] = 'admin', password: Optional[str] = 'admin', 
                        stdout: Optional[bool] = False, verbose: Optional[bool] = False) -> List[str]:
    """
    Install a Kibana Saved Object from Kibana's _export API (Installs to default tenant [space])

    :param file_path: The path to a Kibana saved_objects export
    :param kibana_url: The full URL to your Kibana instance including the protocol and port
    :param import_attempts: The number of times to attempt to contact the API before giving up
    :param username: The username for logging into Kibana instance
    :param password: The password for logging into Kibana instance
    :param stdout: Print output to console
    :param verbose: Include detailed debug messages

    :return: A list of installed object_ids.
    """
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('kibana.saved_objects_setup', level=log_level, stdout=stdout)
    obj_keys = []
    if not isinstance(file_path, TextIO):
        import_fh = open(file_path, 'r')
        file_name = file_path
    else:
        import_fh = file_path
        file_name = import_fh.name
    file_lines = import_fh.readlines()
    for import_object in file_lines:
        serialized_obj = json.loads(import_object)
        try:
            _id = serialized_obj['id']
            _type = serialized_obj['type']
            obj_keys.append(_id)
            logger.debug(f'Importing {_type} ({_id})')
        except KeyError:
            pass
    import_fh.seek(0)
    logger.info(f'Importing Kibana Object from {file_name}.')
    attempts = 0
    while not kibana_api_up(kibana_url=kibana_url, username=username, password=password) and attempts < import_attempts:
        logger.info(f'Waiting for Kibana API to become available - attempt {attempts + 1}.')
        attempts += 1
        sleep(10)
    r = requests.post(
        url=f'{kibana_url}/api/saved_objects/_import?createNewCopies=false',
        auth=('admin', 'admin'),
        files={'file': import_fh},
        headers={'kbn-xsrf': 'true'},
        verify=False
    )
    logger.debug(r.json())
    if r.status_code != 200:
        logger.warning(
            f"Saved object import failed."
            f"You can install these objects yourself via: curl -X POST --insecure -H kbn-xsrf: true "
            f"--user: admin:admin' --form file=@{file_name} "
            f"{kibana_url}//api/saved_objects/_import?createNewCopies=false "
        )
    import_fh.close()
    return obj_keys


def post_install_saved_objects(saved_objects_directory: str, bootstrap_attempts: Optional[int] = 10,
                               stdout: Optional[bool] = False,
                               verbose: Optional[bool] = False):
    log_level = logging.INFO
    kibana_url = f'http://{utilities.get_primary_ip_address()}:5601'
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('kibana.saved_objects_setup', level=log_level, stdout=stdout)
    from dynamite_nsm.services.kibana import process, profile
    kibana_process_profile = profile.ProcessProfiler()
    process.ProcessManager(stdout=stdout, verbose=verbose).start()
    if not kibana_process_profile.is_running():
        logger.warning(f'Could not start Kibana instance. Check the Kibana log.')
    for import_file in os.listdir(saved_objects_directory):
        full_path = f'{saved_objects_directory}/{import_file}'
        import_saved_object(file_path=full_path, kibana_url=kibana_url, import_attempts=bootstrap_attempts,
                            stdout=stdout, verbose=verbose)
    process.ProcessManager(stdout=stdout, verbose=verbose).stop()
