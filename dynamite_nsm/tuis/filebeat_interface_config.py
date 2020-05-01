import npyscreen

from dynamite_nsm.services.filebeat import config
from dynamite_nsm.services.filebeat import exceptions
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.services.filebeat.install import InstallManager


class RemoveTargeteButton(npyscreen.ButtonPress):
    """
    Button Component for removing upstream Filebeat target
    """

    def __init__(self, *args, **keywords):
        super(RemoveTargeteButton, self).__init__(*args, **keywords)
        self.delete_value = keywords.get('delete_value')

    def whenPressed(self):
        kafka_enabled = self.parent.parentApp.filebeat_config.is_kafka_output_enabled()
        if kafka_enabled:
            target_type = 'Kafka'
        else:
            target_type = 'LogStash'
        res = npyscreen.notify_ok_cancel(
            'Are you sure you want to delete this target - {} {}?'.format(target_type, self.delete_value),
            form_color='WARNING',
        )
        if not res:
            return

        if kafka_enabled:
            kafka_config = self.parent.parentApp.filebeat_config.get_kafka_target_config()
            kafka_config['hosts'].remove(self.delete_value)
            self.parent.parentApp.filebeat_config.kafka_targets = kafka_config
        else:
            logstash_config = self.parent.parentApp.filebeat_config.get_logstash_target_config()
            logstash_config['hosts'].remove(self.delete_value)
            self.parent.parentApp.filebeat_config.logstash_targets = logstash_config

        self.parent.parentApp.filebeat_config.write_config()
        self.parent.parentApp.removeForm('MAIN')
        self.parent.parentApp.addForm('MAIN', FilebeatInstanceSettingsForm, name='FileBeat Configuration')
        self.parent.parentApp.switchForm('MAIN')


class OpenToggleTypeFormButton(npyscreen.ButtonPress):
    """
    Button opens a settings form for toggling between Logstash/Kafka target types
    """

    def whenPressed(self):
        self.parent.parentApp.removeForm('EDITTARGETTYPEFM')
        self.parent.parentApp.addForm('EDITTARGETTYPEFM', EditTargetTypeOutputForm,
                                      name='Select between LogStash or Kafka Output.')
        self.parent.parentApp.switchForm('EDITTARGETTYPEFM')


class ToggleKafkaOrLogstashTargetOutputsButton(npyscreen.ButtonPress):
    def whenPressed(self):

        if self.parent.parentApp.filebeat_config.is_kafka_output_enabled():
            self.parent.parentApp.filebeat_config.enable_logstash_output()
            output_type = 'LogStash'
        else:
            self.parent.parentApp.filebeat_config.enable_kafka_output()
            output_type = 'Kafka'

        npyscreen.notify_wait(
            'Enabling {} output mode.'.format(output_type), form_color='GOODHL'
        )
        self.parent.parentApp.filebeat_config.write_config()

        self.parent.parentApp.removeForm('MAIN')
        self.parent.parentApp.addForm('MAIN', FilebeatInstanceSettingsForm, name='FileBeat Configuration')
        self.parent.parentApp.removeForm('EDITTARGETFM')
        self.parent.parentApp.addForm('EDITTARGETFM', EditTargetsForm, name='Edit FileBeat Targets')
        self.parent.parentApp.switchForm('MAIN')


class TargetMultiSelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting target hosts
    """

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.parentApp.getForm('EDITTARGETFM').value = act_on_this
        self.parent.parentApp.switchForm('EDITTARGETFM')


class FilebeatInstanceSettingsForm(npyscreen.ActionForm):
    """
    Main Filebeat Instance Settings Form
    """

    def __init__(self, *args, **keywords):
        self.agent_tag = None
        super(FilebeatInstanceSettingsForm, self).__init__(*args, **keywords)

    def beforeEditing(self):
        self.agent_tag.value = self.parentApp.filebeat_config.get_agent_tag()

    def create(self):
        is_kafka_enabled = self.parentApp.filebeat_config.is_kafka_output_enabled()
        self.agent_tag = self.add(npyscreen.TitleText, name="Agent Tag")
        self.nextrely += 2
        self.add(npyscreen.TitleText, name="Toggle between LogStash and Kafka output modes.", editable=False)
        self.add_widget(OpenToggleTypeFormButton, name='[Toggle Between Output Modes]', relx=0)
        self.nextrely += 2
        ls_target_names = self.parentApp.filebeat_config.get_logstash_target_hosts()
        ls_target_names = list(set(ls_target_names))
        ls_target_names.append('<create new target>')

        kf_target_names = self.parentApp.filebeat_config.get_kafka_target_hosts()
        kf_target_names = list(set(kf_target_names))
        kf_target_names.append('<create new target>')
        if not is_kafka_enabled:
            self.add(npyscreen.TitleText, name='LogStash Targets', editable=False)
            self.add(TargetMultiSelect, values=ls_target_names, max_height=5)
        else:
            self.add(npyscreen.TitleText, name='Kafka Targets', editable=False)
            self.add(TargetMultiSelect, values=kf_target_names, max_height=5)

    def on_ok(self):
        try:
            self.parentApp.filebeat_config.set_agent_tag(self.agent_tag.value)
            self.parentApp.filebeat_config.write_config()
        except exceptions.InvalidAgentTag as e:
            res = npyscreen.notify_ok_cancel(
                e.message,
                form_color='DANGER',
            )
            if not res:
                return
        npyscreen.notify_wait(
            'Be sure to restart the agent for changes to take effect!', form_color='WARNING'
        )
        self.parentApp.setNextForm(None)

    def on_cancel(self):
        self.parentApp.setNextForm(None)


class EditTargetsForm(npyscreen.ActionForm):
    """
    Targets Edit Form
    """

    def __init__(self, *args, **keywords):
        self.value = None
        self.target_text = None
        self.topic_text = None
        self.username_text = None
        self.password_text = None
        self.message = None
        self.delete_button = None
        self.kafka_is_enabled = None

        super(EditTargetsForm, self).__init__(*args, **keywords)

    def create(self):

        self.message = self.add(npyscreen.TitleText,
                                name='Description',
                                value='Configure an upstream server.',
                                color='LABELBOLD',
                                editable=False)
        self.target_text = self.add(npyscreen.TitleText, name='Target')
        if self.parentApp.filebeat_config.is_kafka_output_enabled():
            self.topic_text = self.add(npyscreen.TitleText, name='Kafka Topic')
            self.username_text = self.add(npyscreen.TitleText, name='Kafka Username')
            self.password_text = self.add(npyscreen.TitlePassword, name='Kafka Password')
        self.delete_button = self.add_widget(RemoveTargeteButton,
                                             name='Delete Target', rely=10, color='DANGER')

    def beforeEditing(self):
        kafka_enabled = self.parentApp.filebeat_config.is_kafka_output_enabled()
        if self.value == '<create new target>':
            self.value = None
        if self.value:
            self.target_text.value = self.value
            if kafka_enabled:
                kafka_config = self.parentApp.filebeat_config.get_kafka_target_config()
                self.topic_text.value = kafka_config.get('topic')
                if kafka_config.get('username'):
                    self.username_text.value = kafka_config.get('username')
                if kafka_config.get('password'):
                    self.password_text.value = kafka_config.get('password')
            self.delete_button.delete_value = self.value
            self.delete_button.hidden = False
        else:
            self.delete_button.hidden = True

    def on_ok(self):
        kafka_enabled = self.parentApp.filebeat_config.is_kafka_output_enabled()
        if not InstallManager.validate_targets(targets=[self.target_text.value]):
            npyscreen.notify_ok_cancel(
                'Target must be given in the format: host:port (E.G 192.168.0.100:5044)',
                form_color='DANGER'
            )
            return
        if kafka_enabled:
            kafka_config = self.parentApp.filebeat_config.get_kafka_target_config()
            original_targets = list(kafka_config.get('hosts', []))

        else:
            original_targets = list(self.parentApp.filebeat_config.get_logstash_target_hosts())
        if self.value:
            edit_target_index = original_targets.index(self.value)
            original_targets[edit_target_index] = self.target_text.value
            npyscreen.notify_wait(
                self.target_text.value + ' has been updated!', form_color='GOOD'
            )
        else:
            original_targets.append(self.target_text.value)
            npyscreen.notify_wait(
                self.target_text.value + ' has been created!', form_color='GOOD'
            )
        if kafka_enabled:
            username, password = self.username_text.value, self.password_text.value
            if self.username_text.value.strip() == '':
                username = None
            if self.password_text.value.strip() == '':
                password = None
            self.parentApp.filebeat_config.set_kafka_targets(original_targets, topic=self.topic_text.value,
                                                             username=username, password=password)
        else:
            self.parentApp.filebeat_config.set_logstash_targets(original_targets)
        # Switch back to the main interface

        self.parentApp.filebeat_config.write_config()
        self.parentApp.removeForm('MAIN')
        self.parentApp.addForm('MAIN', FilebeatInstanceSettingsForm, name='FileBeat Configuration')
        self.parentApp.switchForm('MAIN')

    def on_cancel(self):
        self.parentApp.switchForm('MAIN')


class EditTargetTypeOutputForm(npyscreen.ActionForm):
    def __init__(self, *args, **keywords):
        super(EditTargetTypeOutputForm, self).__init__(*args, **keywords)

    def create(self):
        if self.parentApp.filebeat_config.is_kafka_output_enabled():
            self.add(npyscreen.TitleText, name="Kafka outputs are currently enabled. Enable LogStash instead?",
                     editable=False)
            self.add_widget(ToggleKafkaOrLogstashTargetOutputsButton, name='[Enable Logstash Outputs]')
        else:
            self.add(npyscreen.TitleText, name="LogStash outputs are currently enabled. Enable Kafka instead?",
                     editable=False)
            self.add_widget(ToggleKafkaOrLogstashTargetOutputsButton, name='[Enable Kafka Outputs]')

    def on_ok(self):
        self.parentApp.switchForm('MAIN')

    def on_cancel(self):
        self.parentApp.switchForm('MAIN')


class FilebeatConfiguratorApp(npyscreen.NPSAppManaged):
    """
    App Entry Point
    """

    def __init__(self):
        self.filebeat_config = None

        super(FilebeatConfiguratorApp, self).__init__()

    def onStart(self):
        env_vars = get_environment_file_dict()
        npyscreen.setTheme(npyscreen.Themes.ColorfulTheme)
        self.filebeat_config = config.ConfigManager(env_vars.get('FILEBEAT_HOME'))
        self.addForm('MAIN', FilebeatInstanceSettingsForm, name='FileBeat Configuration')
        self.addForm('EDITTARGETTYPEFM', EditTargetTypeOutputForm, name='Select between LogStash or Kafka Output.')
        self.addForm('EDITTARGETFM', EditTargetsForm, name='Edit FileBeat Targets')
