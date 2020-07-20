import os
import json
import base64
import shutil
import hashlib

from jsmin import jsmin
from zipfile import ZipFile
from htmlmin import minify as html_minify
from csscompressor import compress as cssmin

from dynamite_nsm import const

MANIFEST_FILE = 'manifest.json'
PLUGIN_HTML = 'plugin.html'
JS_DIRECTORY = "js/"
CSS_DIRECTORY = "css/"

UNKNOWN_ICON = "iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAABhGlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AcxV9TpSKVIlYQcchQn" \
               "ayIijhqFYpQIdQKrTqYXPoFTRqSFhdHwbXg4Mdi1cHFWVcHV0EQ/ABxcnRSdJES/5cUWsR4cNyPd/ced+8AoV5imtUxDmh6xUzGY2" \
               "I6syoGXhFAL0IYQ7/MLGNOkhLwHF/38PH1LsqzvM/9OXrUrMUAn0g8ywyzQrxBPL1ZMTjvE4dZQVaJz4lHTbog8SPXFZffOOcdFnh" \
               "m2Ewl54nDxGK+jZU2ZgVTI54ijqiaTvlC2mWV8xZnrVRlzXvyFwaz+soy12kOIY5FLEGCCAVVFFFCBVFadVIsJGk/5uEfdPwSuRRy" \
               "FcHIsYAyNMiOH/wPfndr5SYn3KRgDOh8se2PYSCwCzRqtv19bNuNE8D/DFzpLX+5Dsx8kl5raZEjILQNXFy3NGUPuNwBBp4M2ZQdy" \
               "U9TyOWA9zP6pgzQdwt0r7m9Nfdx+gCkqKvEDXBwCIzkKXvd491d7b39e6bZ3w9zF3KnwWHhSgAAAAlwSFlzAAAuIwAALiMBeKU/dg" \
               "AAAAd0SU1FB+QHEhElEZaWiWIAAAAZdEVYdENvbW1lbnQAQ3JlYXRlZCB3aXRoIEdJTVBXgQ4XAAAD0ElEQVRo3uWaz0vUQRTAP7s" \
               "aK9ghrMwFzUuXXAzKVWnDjIL8EyQIvJXnDhmE0K2rdLJAuoRKJw8FWhh5UTGKSvSQl1alcsWlxEJS1w6+hWGYXf3Od77fzB68ZXa+" \
               "M+/Hd973zXtvJoIbKAPKgTogBdQCJwVrgQiQBuYF08A4MAP8BNb9ChDxOb8ROAdcAi4DlR7nLwOjwBjwFnhDyFAHDAEZYNsRZoRmX" \
               "RgKlAE9YgrbAeG68CgLyrSuAgNAheHZFvANWABGgGlpLwBfZUwcqBGsB9qkXQWUGGhmgWvAC1erUAJ0A7kCb3AQ6AASFrQTMnewAO" \
               "2c8C5xoUh/ASZTQDMQc8AjJrSmCvDq98tg0kA0C7QH+B22Cw+d76StOZlW4h2QDMGpJIWXaWU8mVl3ASLxEF18vMDL7PbinXIGJWK" \
               "EDzGDMjmRcdd9YsVgTnH+HsQNZray2z7TY/iwkz4EaAVuCLb6eCFJgwPoKRZ26Du2rXfqBb4I8w3BrPT1+vBmegRgDGeGDPuEVzgN" \
               "zO0hDJmTsV5B32eGTFGsHgA2e2RSCcx6iKlmLaLlZkOg2agO6DSEHV69VJ9B2DHgruCY4XmfhRfTw5mbqqcaUB5sSvzjBRoMQt4GS" \
               "oGoYKn06eMaPPLqEBnz8wfyHuyoZlaLFgFglybccJGxw9rYLotAc1GZvyQ6cFEjPGHxEb708JbPamNtwvQJjUZLVHJsFUYsCB9T2r" \
               "+B90XGftb+n7Lgp8uYikpxQIVpC8L3lfYDSbQKwQUH/PQ5tQDPtWVqsixgxPfgsg+JECq/OxaKNGk0nmEgHFRc1SQMVV4bwAnL8Ee" \
               "l8xFgVet0CdXAQ/GKqwbXe8sHbZXOD+QnCEUiwNMiO/uIFPVcKLKKLEsQplUNfDAosAE8AY74DO1VmtNRKWGqUONwRaKaW34MtEhY" \
               "/90HbV3G+SAV0eETcE+KCL980jIqktY66wPM9lx9g7qM6Sg7VXEV2hyaVqTIfz+gyzgelbwgoy1bwgGzrFIuRdpZB3QTmmktAzNRd" \
               "s4nXikPqhzVrtaARxKdLkl7zVHNq0r5Pyo6gCQnfhOrsMpDemLV6TrVLVSxvC7oohC9a6rrqvigQoUs+5bgKOYjCafFB9flIIDzWk" \
               "q6KX22sOdykOsCXcqgSCqMAp3rkulhragxIH2hlEzBfRH7jKCtl7IqYufhQBwr5N3mgTjoycM/f/SmwoE4DM2b2b4/nv6vLgzo+8y" \
               "+vMJhC/vuUo2La04N7JwPXgGOe5yfkVzotbhb62tOEYcmVy4fr+ni2Tbmi2ezOLp49gcyJmZPmH3E4AAAAABJRU5ErkJggg=="


class PluginLoadError(Exception):
    """
    Thrown when plugin fails to load
    """

    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "Plugin Load Error: {}".format(message)
        super(PluginLoadError, self).__init__(msg)


class Plugin:
    """
    API Plugin
    """

    def __init__(self, plugin_directory, disable_load=False):
        if plugin_directory:
            self.validate_plugin(plugin_directory)
        self.plugin_directory = plugin_directory

        self.plugin_id = None
        self.meta_name = None
        self.meta_description = None
        self.meta_version = None
        self.meta_role = None
        self.meta_author = None
        self.meta_website = None
        self.meta_code_repo_url = None

        self.permissions_require = None
        self.toolbar_icon = None
        self.toolbar_show = True

        self.files_javascript = []
        self.files_css = []

        self._load_manifest()
        if not disable_load:
            self.css = self.optimize_css([os.path.join(plugin_directory, CSS_DIRECTORY, f) for f in self.files_css])
            self.html = self.optimize_html(os.path.join(plugin_directory, PLUGIN_HTML))
            self.javascript = self.optimize_javascript(
                [os.path.join(plugin_directory, JS_DIRECTORY, f) for f in self.files_javascript])
        if self.toolbar_icon:
            self.icon_base64 = self.encode_icon(os.path.join(plugin_directory, self.toolbar_icon))
        else:
            self.icon_base64 = UNKNOWN_ICON

    def _load_manifest(self):
        manifest_json = {}
        with open(os.path.join(self.plugin_directory, 'manifest.json')) as manifest_f:
            try:
                manifest_json = json.loads(manifest_f.read())
            except ValueError:
                raise PluginLoadError("'manifest.json' must be valid .json.")
        if "meta" not in manifest_json:
            raise PluginLoadError("manifest.json must include 'meta' section.")
        if "permissions" not in manifest_json:
            raise PluginLoadError("manifest.json must include 'meta' section.")
        if "files" not in manifest_json:
            raise PluginLoadError("manifest.json must include 'files' section.")

        self.meta_name = manifest_json['meta'].get('name')  # REQUIRED
        self.meta_description = manifest_json['meta'].get('description')  # REQUIRED
        self.meta_version = manifest_json['meta'].get('version')  # REQUIRED
        self.meta_role = manifest_json['meta'].get('role')  # REQUIRED
        self.meta_author = manifest_json['meta'].get('author')
        self.meta_website = manifest_json['meta'].get('website')
        self.meta_code_repo_url = manifest_json['meta'].get('code_repo_url')

        self.files_javascript = manifest_json['files'].get('javascript', [])
        self.files_css = manifest_json['files'].get('css', [])

        self.permissions_require = manifest_json['permissions'].get('requires')  # REQUIRED
        self.toolbar_icon = manifest_json['toolbar'].get('icon')
        self.toolbar_show = manifest_json['toolbar'].get('show')

        # Required fields validation

        if not self.meta_name:
            raise PluginLoadError("manifest.json meta.name required.")
        elif 5 > len(self.meta_name) > 30:
            raise PluginLoadError("manifest.json meta.name must be between 5 and 30 characters.")
        elif not self.meta_description:
            raise PluginLoadError("manifest.json meta.description required.")
        elif 20 > len(self.meta_description) > 255:
            raise PluginLoadError("manifest.json meta.description must be between 20 and 255 characters.")
        elif not self.meta_version:
            raise PluginLoadError("manifest.json meta.version required.")
        elif 1 > len(self.meta_version) > 10:
            raise PluginLoadError("manifest.json meta.version must be between 1 and 10 characters.")
        elif not self.meta_role:
            raise PluginLoadError("manifest.json meta.role required; either: 'agent' or 'monitor'.")
        elif self.meta_role not in ['agent', 'monitor']:
            raise PluginLoadError("manifest.json meta.role invalid; either: 'agent' or 'monitor'.")
        elif not self.permissions_require:
            raise PluginLoadError(
                "manifest.json permissions.require required; either: 'admin', 'superuser', 'analyst'.")
        elif self.permissions_require not in ['admin', 'superuser', 'analyst']:
            raise PluginLoadError("manifest.json permissions.require invalid; either: 'admin', 'superuser', 'analyst.")

        # Optional fields validation
        if self.meta_author:
            if 1 > len(self.meta_author) > 30:
                raise PluginLoadError("manifest.json meta.author must be between 1 and 30 characters.")
        if self.meta_website:
            if 5 > len(self.meta_website) > 50:
                raise PluginLoadError("manifest.json meta.website must be between 5 and 50 characters.")
        if self.meta_code_repo_url:
            if 5 > len(self.meta_code_repo_url) > 50:
                raise PluginLoadError("manifest.json meta.meta_code_repo_url must be between 5 and 50 characters.")
        if self.toolbar_icon:
            if 5 > len(self.toolbar_icon) > 50:
                raise PluginLoadError("manifest.json toolbar.icon must be between 5 and 50 characters.")

        # File validation
        _import_bytes = b""
        with open(os.path.join(self.plugin_directory, PLUGIN_HTML), 'rb') as f:
            _import_bytes += f.read()
        for js_file in self.files_javascript:
            js_path = os.path.join(self.plugin_directory, 'js', js_file)
            if not os.path.exists(js_path):
                raise PluginLoadError(
                    "manifest.json files.javascript references: {}, but this file does not exist.".format(js_path))
            with open(js_path, 'rb') as f:
                _import_bytes += f.read()

        for css_file in self.files_css:
            css_path = os.path.join(self.plugin_directory, 'css', css_file)
            if not os.path.exists(css_path):
                raise PluginLoadError(
                    "manifest.json files.css references: {}, but this file does not exist.".format(css_path))
            with open(css_path, 'rb') as f:
                _import_bytes += f.read()
        self.plugin_id = hashlib.sha512(_import_bytes).hexdigest()[96:]

    @staticmethod
    def validate_plugin(plugin_directory):
        """
        Determine whether the required files are found within plugin.

        :param plugin_directory: TThe root of the plugin directory
        """
        if not os.path.exists(os.path.join(plugin_directory, MANIFEST_FILE)):
            raise PluginLoadError('Plugin root must contain a {} file.'.format(MANIFEST_FILE))
        if not os.path.exists(os.path.join(plugin_directory, PLUGIN_HTML)):
            raise PluginLoadError('Plugin root must contain {} directory'.format(PLUGIN_HTML))

    @staticmethod
    def optimize_javascript(file_paths):
        """
        Minimize and return a concatenated version of all JS scripts passed in.

        :param file_paths: A list of file paths (relative to plugin root directory)
        :return: A concatenated and minimized JS string
        """
        js_string = ''
        for f in file_paths:
            if f.endswith('.js'):
                with open(f) as js_file:
                    minified = jsmin(js_file.read())
                    js_string += minified
        return js_string

    @staticmethod
    def optimize_css(file_paths):
        """
        Minimize and return a concatenated version of all CSS styles passed in.

        :param file_paths: A list of file paths (relative to plugin root directory)
        :return: A concatenated and minimized CSS string
        """
        css_string = ''
        for f in file_paths:
            if f.endswith('.css'):
                with open(f) as css_file:
                    minified = cssmin(css_file.read())
                    css_string += minified
        return css_string

    @staticmethod
    def optimize_html(file_path):
        """
        Minimize HTML (plugin.html) and return as a string

        :param file_path: A file path (relative to plugin root directory) to plugin.html file
        :return: A minimized plugin.html string
        """
        with open(file_path) as html_file:
            return html_minify(html_file.read())

    @staticmethod
    def encode_icon(file_path):
        """
        Encode icon file as base64 string.

        :param file_path: A file path (relative to plugin root directory) to icon.png file
        :return: The base64 string equivalent to the icon.png
        """
        with open(file_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
        return encoded_string.decode('utf-8')


def load_plugin(plugin_root_directory, disable_load=False):
    """
    Convenience function for loading plugin into Plugin class

    :param plugin_root_directory: The top-level containing plugin code/configs.
    :param disable_load: If True, will not attempt to optimize JS/CSS/HTML, only parse the manifest.json and derive a
                         plugin_id
    :return: A Plugin instance
    """
    return Plugin(os.path.join(const.UI_PLUGINS_DIRECTORY, plugin_root_directory), disable_load=disable_load)


def load_plugins(disable_load=False):
    """
    Convenience function for loading all available plugin into a list of Plugin classes

    :param disable_load: If True, will not attempt to optimize JS/CSS/HTML, only parse the manifest.json and derive a
                         plugin_id
    :return: A list of Plugin instances
    """
    return [load_plugin(f, disable_load=disable_load) for f in os.listdir(const.UI_PLUGINS_DIRECTORY)]


def install_plugin(plugin_path):
    """
    Convenience function for installing a plugin from a .zip file.

    :param plugin_path: The path to the zip file
    """
    found_manifest = False
    with ZipFile(plugin_path, "r") as zip_obj:
        top_directories = list({item.split('/')[0] for item in zip_obj.namelist()})
        if len(top_directories) != 1:
            raise PluginLoadError("This archive contains more than one root-directory.")
        for f in zip_obj.infolist():
            if f.filename == os.path.join(top_directories[0], 'manifest.json'):
                found_manifest = True
                break
        if not found_manifest:
            raise PluginLoadError('Could not locate manifest.json in expected location. Should be in plugin root.')
        zip_obj.extractall(const.INSTALL_CACHE)
        temp_plugin_path = os.path.join(const.INSTALL_CACHE, top_directories[0])
        try:
            loaded_plugin = load_plugin(temp_plugin_path)
            shutil.move(temp_plugin_path, os.path.join(const.UI_PLUGINS_DIRECTORY, loaded_plugin.plugin_id))
        except PluginLoadError as e:
            shutil.rmtree(temp_plugin_path)
            raise e


def uninstall_plugin(plugin_id):
    """
    Convenience function for uninstalling a plugin.

    :param plugin_id: The unique identifier associated with a plugin (E.G Plugin.plugin_id)
    """
    for plugin in load_plugins(disable_load=True):
        if plugin.plugin_id == plugin_id:
            shutil.rmtree(plugin.plugin_directory)
