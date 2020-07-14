import os
from dynamite_nsm import const
from jsmin import jsmin
from csscompressor import compress as cssmin

PLUGIN_HTML = 'plugin.html'
ICON_FILE = 'icon.png'
JS_DIRECTORY = "js/"
CSS_DIRECTORY = "css/"
IMAGE_DIRECTORY = "img/"


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
    def __init__(self, plugin_directory=None, plugin_archive=None):
        if plugin_directory:
            self.validate_plugin(plugin_directory)

        self.css = self.optimize_css(plugin_directory)
        self.html = self.optimize_html(plugin_directory)
        self.javascript = self.optimize_javascript(plugin_directory)

    @staticmethod
    def validate_plugin(plugin_directory):
        if not os.path.exists(os.path.join(plugin_directory, PLUGIN_HTML)):
            raise PluginLoadError('Plugin root must contain {} directory'.format(PLUGIN_HTML))
        if not os.path.join(plugin_directory, JS_DIRECTORY):
            raise PluginLoadError('Plugin root must contain {} directory'.format(JS_DIRECTORY))
        if not os.path.join(plugin_directory, CSS_DIRECTORY):
            raise PluginLoadError('Plugin root must contain {} directory'.format(CSS_DIRECTORY))
        if not os.path.join(plugin_directory, IMAGE_DIRECTORY):
            raise PluginLoadError('Plugin root must contain {} directory'.format(IMAGE_DIRECTORY))

    @staticmethod
    def optimize_javascript(plugin_directory):
        js_string = ''
        for f in os.listdir(os.path.join(plugin_directory, 'js')):
            if f.endswith('.js'):
                with open(os.path.join(plugin_directory, 'js', f)) as js_file:
                    minified = jsmin(js_file.read())
                    js_string += minified
        return js_string

    @staticmethod
    def optimize_css(plugin_directory):
        css_string = ''
        for f in os.listdir(os.path.join(plugin_directory, 'css')):
            if f.endswith('.css'):
                with open(os.path.join(plugin_directory, 'css', f)) as css_file:
                    minified = cssmin(css_file.read())
                    css_string += minified
        return css_string

    @staticmethod
    def optimize_html(plugin_directory):
        with open(os.path.join(plugin_directory, 'plugin.html')) as html_file:
            return html_file.read()


def load_plugin(plugin_name):
    return Plugin(os.path.join(const.UI_PLUGINS_DIRECTORY, plugin_name))

