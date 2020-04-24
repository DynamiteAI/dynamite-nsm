import npyscreen

from dynamite_nsm.services.filebeat import config
from dynamite_nsm.services.filebeat.install import InstallManager

INSTALL_DIRECTORY = '/Users/jaminbecker/PycharmProjects/dynamite-nsm-project/utils/default_configs/filebeat'


class LogstashTargetSelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting LogStash Targets
    """

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.parentApp.getForm('EDITTARGETFM').value = act_on_this
        self.parent.parentApp.switchForm('EDITTARGETFM')


class FilebeatInstanceSettingsForm(npyscreen.ActionForm):
    """
    Main Filebeat Instance Settings Form
    """
    def __init__(self, *args, **keywords):
        super(FilebeatInstanceSettingsForm, self).__init__(*args, **keywords)

    def create(self):
        target_names = self.parentApp.filebeat_config.get_logstash_targets()
        target_names = list(set(target_names))
        target_names.append('<create new LogStash target>')

        self.add(npyscreen.TitleText, name='LogStash Targets', editable=False)
        self.add(LogstashTargetSelect, values=target_names, max_height=5)

    def on_ok(self):
        npyscreen.notify_wait(
            'Be sure to restart the agent for changes to take effect!', form_color='WARNING'
        )
        self.parentApp.setNextForm(None)


class EditTargetsForm(npyscreen.ActionForm):
    """
    Logstash Targets Edit Form
    """

    def __init__(self, *args, **keywords):
        self.value = None
        self.logstash_target_text = None
        self.message = None
        self.delete_button = None
        super(EditTargetsForm, self).__init__(*args, **keywords)

    def create(self):
        self.message = self.add(npyscreen.TitleText,
                                name='Description',
                                value='Configure an Upstream LogStash Server.',
                                color='LABELBOLD',
                                editable=False)
        self.logstash_target_text = self.add(npyscreen.TitleText, name='LogStash Target')

    def beforeEditing(self):
        if self.value == '<create new LogStash target>':
            self.value = None
        if self.value:
            self.logstash_target_text.value = self.value

    def on_ok(self):

        if not InstallManager.validate_logstash_targets(logstash_targets=[self.logstash_target_text.value]):
            npyscreen.notify_ok_cancel(
                'LogStash target must be given in the format: host:port (E.G 192.168.0.100:5044)',
                form_color='DANGER'
            )
            return
        original_targets = list(self.parentApp.filebeat_config.get_logstash_targets())
        if self.value:
            edit_target_index = original_targets.index(self.value)
            original_targets[edit_target_index] = self.logstash_target_text.value
            npyscreen.notify_wait(
                self.logstash_target_text.value + ' has been updated!', form_color='GOOD'
            )
        else:
            original_targets.append(self.logstash_target_text.value)
            npyscreen.notify_wait(
                self.logstash_target_text.value + ' has been created!', form_color='GOOD'
            )
        self.parentApp.filebeat_config.set_logstash_targets(original_targets)
        # Switch back to the main interface

        self.parentApp.filebeat_config.write_config()
        self.parentApp.removeForm('MAIN')
        self.parentApp.addForm('MAIN', FilebeatInstanceSettingsForm, name='FileBeat Instance Configuration')
        self.parentApp.switchForm('MAIN')


class FilebeatConfiguratorApp(npyscreen.NPSAppManaged):
    """
    App Entry Point
    """
    def __init__(self):
        self.filebeat_config = None

        super(FilebeatConfiguratorApp, self).__init__()

    def onStart(self):
        # env_vars = get_environment_file_dict()
        self.filebeat_config = config.ConfigManager(INSTALL_DIRECTORY)
        self.addForm('MAIN', FilebeatInstanceSettingsForm, name='FileBeat Instance Configuration')
        self.addForm('EDITTARGETFM', EditTargetsForm, name='Edit FileBeat LogStash Targets')

FilebeatConfiguratorApp().run()