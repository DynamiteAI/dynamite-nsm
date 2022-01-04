import os
from dynamite_nsm import const
from dynamite_nsm.logger import get_logger
from dynamite_nsm import utilities


def check_updates():
    utilities.makedirs(const.INSTALL_CACHE, exist_ok=True)
    utilities.makedirs(const.INSTALL_PATH, exist_ok=True)
    utilities.makedirs(const.CONFIG_PATH, exist_ok=True)
    if not os.path.exists(const.DEFAULT_CONFIGS):
        from dynamite_nsm.services.updates import install as update_installer
        utilities.create_dynamite_user()
        update_mng = update_installer.InstallManager(stdout=True)
        update_mng.setup()
