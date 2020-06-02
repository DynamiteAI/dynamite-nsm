from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.zeek import config as zeek_config

api = Namespace(
    name='Zeek Scripts',
    description='Enable/Disable Zeek Scripts.',
)

env_vars = utilities.get_environment_file_dict()
ZEEK_SCRIPT_DIRECTORY = env_vars.get('ZEEK_SCRIPTS')


@api.route('/', endpoint='zeek-scripts')
class ZeekScriptConfig(Resource):

    def get(self):
        script_config = zeek_config.ScriptConfigManager(configuration_directory=ZEEK_SCRIPT_DIRECTORY)
        enabled_scripts = script_config.list_enabled_scripts()
        disabled_scripts = script_config.list_disabled_scripts()
        return dict(
            enabled=[{"id": i+1, "name": name} for i, name in enumerate(enabled_scripts)],
            disabled=[{"id": len(enabled_scripts) + j+1, "name": name} for j, name in enumerate(disabled_scripts)]
        )
