from flask_restplus import fields, reqparse, Namespace, Resource

from dynamite_nsm import utilities
from dynamite_nsm.services.zeek import config as zeek_config

api = Namespace(
    name='Zeek Scripts',
    description='Enable/Disable Zeek Scripts.',
)

env_vars = utilities.get_environment_file_dict()
ZEEK_SCRIPT_DIRECTORY = env_vars.get('ZEEK_SCRIPTS')


@api.route('/', endpoint='scripts-config')
class ZeekScriptConfig(Resource):

    @staticmethod
    def hash_and_id_scripts(enabled_scripts, disabled_scripts):
        # Hashing algo isn't perfect could possibly have collisions, but we're programmers not
        # mathematicians the chances of this happening are relatively low.
        script_count = len(enabled_scripts) + len(disabled_scripts)

        return dict(
            enabled=sorted([{"id": hash(name) % (script_count ** 3), "name": name} for name in
                            enabled_scripts], key=lambda i: i['id']),
            disabled=sorted([{"id": hash(name) % (script_count ** 3), "name": name} for name in
                             disabled_scripts], key=lambda i: i['id'])
        )

    def get(self):
        script_config = zeek_config.ScriptConfigManager(configuration_directory=ZEEK_SCRIPT_DIRECTORY)
        scripts_and_ids = self.hash_and_id_scripts(script_config.list_enabled_scripts(),
                                                   script_config.list_disabled_scripts())
        return scripts_and_ids, 200


@api.route('/<script_id>', endpoint='script-manager')
class ZeekScriptManager(Resource):

    def get(self, script_id):
        script_config = zeek_config.ScriptConfigManager(configuration_directory=ZEEK_SCRIPT_DIRECTORY)
        scripts_and_ids = ZeekScriptConfig.hash_and_id_scripts(script_config.list_enabled_scripts(),
                                                               script_config.list_disabled_scripts())
        enabled_scripts = [script['id'] for script in scripts_and_ids['enabled']]
        disabled_scripts = [script['id'] for script in scripts_and_ids['disabled']]
        if not script_id:
            return scripts_and_ids, 200

        if script_id in enabled_scripts:
            idx = enabled_scripts.index(script_id)
            enabled_scripts[idx].update({'status': 'enabled'})
            return enabled_scripts[idx], 200
        elif script_id in disabled_scripts:
            idx = disabled_scripts.index(script_id)
            disabled_scripts[idx].update({'status': 'disabled'})
            return disabled_scripts[idx], 200
        else:
            return dict(message='Could not find script {}'.format(script_id)), 404
