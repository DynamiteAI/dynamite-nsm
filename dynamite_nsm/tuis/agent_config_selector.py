import npyscreen

from dynamite_nsm.services.zeek import profile as zeek_profile
from dynamite_nsm.services.filebeat import profile as filebeat_profile
from dynamite_nsm.services.suricata import profile as suricata_profile

from dynamite_nsm.tuis import zeek_node_config
from dynamite_nsm.tuis import zeek_script_config
from dynamite_nsm.tuis import suricata_rule_config
from dynamite_nsm.tuis import suricata_interface_config
from dynamite_nsm.tuis import filebeat_interface_config

zeek_and_suricata_mapping = {
    'Configure Upstream Processors.': filebeat_interface_config.FilebeatConfiguratorApp,
    'Configure Zeek Network Settings.': zeek_node_config.ZeekNodeConfiguratorApp,
    'Configure Suricata Network Settings.': suricata_interface_config.SuricataInstanceConfiguratorApp,
    'Enable/Disable Zeek Scripts.': zeek_script_config.ZeekScriptConfiguratorApp,
    'Enable/Disable Suricata Rules.': suricata_rule_config.SuricataRuleConfiguratorApp,
}

zeek_only_mapping = {
    'Configure Upstream Processors.': filebeat_interface_config.FilebeatConfiguratorApp,
    'Configure Zeek Network Settings.': zeek_node_config.ZeekNodeConfiguratorApp,
    'Enable/Disable Zeek Scripts.': zeek_script_config.ZeekScriptConfiguratorApp
}

suricata_only_mapping = {
    'Configure Upstream Processors.': filebeat_interface_config.FilebeatConfiguratorApp,
    'Configure Suricata Network Settings.': suricata_interface_config.SuricataInstanceConfiguratorApp,
    'Enable/Disable Suricata Rules.': suricata_rule_config.SuricataRuleConfiguratorApp
}


class AgentConfigMultiSelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting target hosts
    """

    def actionHighlighted(self, act_on_this, keypress):
        npyscreen.notify_wait(
            'Entering {} configuration.'.format(act_on_this), form_color='GOODHL'
        )
        zeek_and_suricata_mapping[act_on_this]().run()


class AgentConfigForm(npyscreen.ActionForm):

    def create(self):

        zeek_installed, suricata_installed, filebeat_installed = True, True, True
        """
        zeek_profile.ProcessProfiler().is_installed, \
        suricata_profile.ProcessProfiler().is_installed, \
        filebeat_profile.ProcessProfiler().is_installed
        """
        app_mapping = {}
        if filebeat_installed:
            if zeek_installed and suricata_installed:
                app_mapping = zeek_and_suricata_mapping
            elif zeek_installed:
                app_mapping = zeek_only_mapping
            elif suricata_installed:
                app_mapping = suricata_only_mapping

        self.add(AgentConfigMultiSelect, values=app_mapping.keys(), max_height=5)


class AgentConfigApp(npyscreen.NPSAppManaged):
    """
    App Entry Point
    """

    def __init__(self):
        super(AgentConfigApp, self).__init__()

    def onStart(self):
        self.addForm('MAIN', AgentConfigForm, name='Agent Configurations')


AgentConfigApp().run()
