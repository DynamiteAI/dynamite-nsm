import npyscreen

from dynamite_nsm.services.suricata import config
from dynamite_nsm.utilities import get_environment_file_dict


class RemoveNetworkInterfaceButton(npyscreen.ButtonPress):
    """
    Button Component for removing Suricata Network Interfaces
    """
    def __init__(self, *args, **keywords):
        super(RemoveNetworkInterfaceButton, self).__init__(*args, **keywords)
        self.delete_value = keywords.get('delete_value')

    def whenPressed(self):
        res = npyscreen.notify_ok_cancel(
            'Are you sure you want to delete this network interface - {}?'.format(self.delete_value),
            form_color='WARNING',
        )
        if not res:
            return

        self.parent.parentApp.suricata_config.remove_afpacket_interface(self.delete_value)
        self.parent.parentApp.suricata_config.write_config()
        self.parent.parentApp.removeForm('MAIN')
        self.parent.parentApp.addForm('MAIN', SuricataInstanceSettingsForm, name='Suricata Instance Configuration')
        self.parent.parentApp.switchForm('MAIN')


class NetworkInterfaceSelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting network interfaces
    """

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.parentApp.getForm('EDITINTERFACEFM').value = act_on_this
        self.parent.parentApp.switchForm('EDITINTERFACEFM')


class SuricataInstanceSettingsForm(npyscreen.ActionForm):
    """
    Main Suricata Instance Settings Form
    """
    def __init__(self, *args, **keywords):
        super(SuricataInstanceSettingsForm, self).__init__(*args, **keywords)

    def create(self):
        interface_names = list(set([interface_config['interface']
                                    for interface_config in self.parentApp.suricata_config.af_packet_interfaces]))
        interface_names.append('<create new interface>')

        self.add(npyscreen.TitleText, name='Network Interfaces', editable=False)
        self.add(NetworkInterfaceSelect, values=interface_names, max_height=5)

    def on_ok(self):
        npyscreen.notify_wait(
            'Be sure to restart the agent for changes to take effect!', form_color='WARNING'
        )
        self.parentApp.setNextForm(None)


class EditInterfaceForm(npyscreen.ActionForm):
    """
    Suricata Network Interface Edit Form
    """
    def __init__(self, *args, **keywords):
        self.value = None
        self.interface_config = None
        self.net_interface_text = None
        self.threads_text = None
        self.cluster_id = None
        self.bpf_filter = None
        self.message = None
        self.delete_button = None
        super(EditInterfaceForm, self).__init__(*args, **keywords)

    def create(self):
        self.message = self.add(npyscreen.TitleText,
                                name='Description',
                                value='Configure a Suricata Interface',
                                color='LABELBOLD',
                                editable=False)
        self.net_interface_text = self.add(npyscreen.TitleText, name='Network Interface')
        self.threads_text = self.add(npyscreen.TitleText, name='Worker Threads')
        self.cluster_id = self.add(npyscreen.TitleText, name='Cluster Id')
        self.bpf_filter = self.add(npyscreen.TitleText, name='BPF Filter')
        self.delete_button = self.add_widget(RemoveNetworkInterfaceButton,
                                             name='[Delete Network Interface]', rely=13, color='DANGER')

    def beforeEditing(self):
        if self.value == '<create new interface>':
            self.value = None

        if self.value:
            interface_configs = self.parentApp.suricata_config.af_packet_interfaces
            for interface_config in interface_configs:
                if interface_config['interface'] == self.value:
                    self.interface_config = interface_config
                    break
            if not self.interface_config:
                self.delete_button.hidden = True
                return
            self.net_interface_text.value = self.interface_config['interface']
            self.threads_text.value = self.interface_config.get('threads')
            self.cluster_id.value = str(self.interface_config.get('cluster-id'))
            self.bpf_filter.value = self.interface_config.get('bpf-filter')
            self.delete_button.delete_value = self.value
            self.delete_button.hidden = False
        else:
            self.delete_button.hidden = True

    def on_ok(self):
        try:
            if self.threads_text.value == '':
                self.threads_text.value = 'auto'
            int(self.threads_text.value)
        except ValueError:
            if self.threads_text.value != 'auto':
                npyscreen.notify_ok_cancel(
                    'Worker Threads must be given as an integer.',
                    form_color='DANGER'
                )
                return
        if not self.net_interface_text.value:
            npyscreen.notify_ok_cancel(
                'Network Interface cannot be blank.',
                form_color='DANGER'
            )
            return
        if self.value:
            self.parentApp.suricata_config.remove_afpacket_interface(self.value)
        self.parentApp.suricata_config.add_afpacket_interface(
            interface=self.net_interface_text.value,
            threads=self.threads_text.value,
            cluster_id=self.cluster_id.value,
            bpf_filter=self.bpf_filter.value
        )

        # Switch back to the main interface
        npyscreen.notify_wait(
            self.net_interface_text.value + ' has been updated!', form_color='GOOD'
        )
        self.parentApp.suricata_config.write_config()
        self.parentApp.removeForm('MAIN')
        self.parentApp.addForm('MAIN', SuricataInstanceSettingsForm, name='Suricata Instance Configuration')
        self.parentApp.switchForm('MAIN')

    def on_cancel(self):
        self.parentApp.setNextFormPrevious()


class SuricataInstanceConfiguratorApp(npyscreen.NPSAppManaged):
    """
    App Entry Point
    """
    def __init__(self):
        self.suricata_config = None

        super(SuricataInstanceConfiguratorApp, self).__init__()

    def onStart(self):
        npyscreen.setTheme(npyscreen.Themes.ColorfulTheme)
        env_vars = get_environment_file_dict()
        self.suricata_config = config.ConfigManager(env_vars['SURICATA_CONFIG'])
        self.addForm('MAIN', SuricataInstanceSettingsForm, name='Suricata Instance Configuration')
        self.addForm('EDITINTERFACEFM', EditInterfaceForm, name='Edit Suricata Network Interface')