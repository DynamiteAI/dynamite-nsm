import os
import json
import base64
import hashlib

from jsmin import jsmin
from csscompressor import compress as cssmin

from dynamite_nsm import const

MANIFEST_FILE = 'manifest.json'
PLUGIN_HTML = 'plugin.html'
JS_DIRECTORY = "js/"
CSS_DIRECTORY = "css/"


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

    def __init__(self, plugin_directory=None, disable_load=False):
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

    def _load_manifest(self):
        with open(os.path.join(self.plugin_directory, 'manifest.json')) as manifest_f:
            manifest_json = json.loads(manifest_f.read())
        if "meta" not in manifest_json:
            raise PluginLoadError("manifest.json must include 'meta' section.")
        if "permissions" not in manifest_json:
            raise PluginLoadError("manifest.json must include 'meta' section.")
        if "files" not in manifest_json:
            raise PluginLoadError("manifest.json must include 'files' section.")

        self.meta_name = manifest_json['meta'].get('name')                       # REQUIRED
        self.meta_description = manifest_json['meta'].get('description')         # REQUIRED
        self.meta_version = manifest_json['meta'].get('version')                 # REQUIRED
        self.meta_role = manifest_json['meta'].get('role')                       # REQUIRED
        self.meta_author = manifest_json['meta'].get('author')
        self.meta_website = manifest_json['meta'].get('website')
        self.meta_code_repo_url = manifest_json['meta'].get('code_repo_url')

        self.files_javascript = manifest_json['files'].get('javascript', [])     # REQUIRED
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
        elif not self.files_javascript:
            raise PluginLoadError("manifest.json files.javascript required.")

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
        if not os.path.exists(os.path.join(plugin_directory, MANIFEST_FILE)):
            raise PluginLoadError('Plugin root must contain a {} file.'.format(MANIFEST_FILE))
        if not os.path.exists(os.path.join(plugin_directory, PLUGIN_HTML)):
            raise PluginLoadError('Plugin root must contain {} directory'.format(PLUGIN_HTML))
        if not os.path.join(plugin_directory, JS_DIRECTORY):
            raise PluginLoadError('Plugin root must contain {} directory'.format(JS_DIRECTORY))
        if not os.path.join(plugin_directory, CSS_DIRECTORY):
            raise PluginLoadError('Plugin root must contain {} directory'.format(CSS_DIRECTORY))

    @staticmethod
    def optimize_javascript(file_paths):
        js_string = ''
        for f in file_paths:
            if f.endswith('.js'):
                with open(f) as js_file:
                    minified = jsmin(js_file.read())
                    js_string += minified
        return js_string

    @staticmethod
    def optimize_css(file_paths):
        css_string = ''
        for f in file_paths:
            if f.endswith('.css'):
                with open(f) as css_file:
                    minified = cssmin(css_file.read())
                    css_string += minified
        return css_string

    @staticmethod
    def optimize_html(file_path):
        with open(file_path) as html_file:
            return html_file.read()

    @staticmethod
    def encode_icon(file_path):
        with open(file_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
        return encoded_string.decode('utf-8')


def load_plugin(plugin_root_directory, disable_load=False):
    return Plugin(os.path.join(const.UI_PLUGINS_DIRECTORY, plugin_root_directory), disable_load=disable_load)


def load_plugins(disable_load=False):
    return [load_plugin(f, disable_load=disable_load) for f in os.listdir(const.UI_PLUGINS_DIRECTORY)]

