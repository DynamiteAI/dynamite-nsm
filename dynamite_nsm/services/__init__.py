from dynamite_nsm import const
from dynamite_nsm import utilities

utilities.makedirs(const.INSTALL_CACHE, exist_ok=True)
utilities.makedirs(const.INSTALL_PATH, exist_ok=True)
utilities.makedirs(const.CONFIG_PATH, exist_ok=True)
