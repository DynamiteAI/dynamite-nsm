import npyscreen
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.services.zeek import ZeekScriptConfigurator


class ZeekScriptSettingsForm(npyscreen.ActionForm):
    """
    Main Zeek Script Settings Form
    """
    def __init__(self, *args, **keywords):
        self.rendered_scripts = []
        super(ZeekScriptSettingsForm, self).__init__(*args, **keywords)

    def create(self):
        self.add(npyscreen.TitleText, name='Pick your Zeek Scripts',
                 value='Zeek scripts can generate real-time alerts, infer connection information, '
                       'provide highlevel application summaries, and even extract files.',
                 color='LABELBOLD',
                 editable=False
                )
        enabled_scripts = self.parentApp.zeek_script_config.list_enabled_scripts()
        disabled_scripts = self.parentApp.zeek_script_config.list_disabled_scripts()
        combined_scripts = list(enabled_scripts)
        combined_scripts.extend(disabled_scripts)
        error = 0
        for i, script in enumerate(sorted(combined_scripts)):
            try:
                if i == 0:
                    self.rendered_scripts.append(
                        self.add(npyscreen.RoundCheckBox, name=script, value=script in enabled_scripts, rely=5,
                                 relx=2 + (70 * error))
                    )
                else:
                    self.rendered_scripts.append(
                        self.add(npyscreen.RoundCheckBox, name=script, value=script in enabled_scripts,
                                 relx=2 + (70 * error))
                    )
            except npyscreen.wgwidget.NotEnoughSpaceForWidget:
                error += 1
                self.rendered_scripts.append(
                    self.add(npyscreen.RoundCheckBox, name=script, value=script in enabled_scripts, rely=5,
                             relx=2 + (70 * error))
                )

    def on_ok(self):
        npyscreen.notify_wait(
            'Be sure to restart the agent for changes to take effect!', form_color='WARNING'
        )
        for script in self.rendered_scripts:
            if script.value:
                self.parentApp.zeek_script_config.enable_script(script.name)
            else:
                self.parentApp.zeek_script_config.disable_script(script.name)

        self.parentApp.zeek_script_config.write_config()
        self.parentApp.setNextForm(None)


class ZeekScriptConfiguratorApp(npyscreen.NPSAppManaged):
    """
    App Entry Point
    """
    def __init__(self):
        self.zeek_script_config = None

        super(ZeekScriptConfiguratorApp, self).__init__()

    def onStart(self):
        env_vars = get_environment_file_dict()
        self.zeek_script_config = ZeekScriptConfigurator(env_vars['ZEEK_SCRIPTS'])
        self.addForm('MAIN', ZeekScriptSettingsForm, name='Zeek Script Configuration')