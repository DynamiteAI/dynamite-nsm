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
    '[1] Configure Upstream Processors.': filebeat_interface_config.FilebeatConfiguratorApp,
    '[2] Configure Zeek Network Settings.': zeek_node_config.ZeekNodeConfiguratorApp,
    '[3] Configure Suricata Network Settings.': suricata_interface_config.SuricataInstanceConfiguratorApp,
    '[4] Enable/Disable Zeek Scripts.': zeek_script_config.ZeekScriptConfiguratorApp,
    '[5] Enable/Disable Suricata Rules.': suricata_rule_config.SuricataRuleConfiguratorApp,
}

zeek_only_mapping = {
    '[1] Configure Upstream Processors.': filebeat_interface_config.FilebeatConfiguratorApp,
    '[2] Configure Zeek Network Settings.': zeek_node_config.ZeekNodeConfiguratorApp,
    '[3] Enable/Disable Zeek Scripts.': zeek_script_config.ZeekScriptConfiguratorApp
}

suricata_only_mapping = {
    '[1] Configure Upstream Processors.': filebeat_interface_config.FilebeatConfiguratorApp,
    '[2] Configure Suricata Network Settings.': suricata_interface_config.SuricataInstanceConfiguratorApp,
    '[3] Enable/Disable Suricata Rules.': suricata_rule_config.SuricataRuleConfiguratorApp
}


class AgentConfigMultiSelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting target hosts
    """

    def actionHighlighted(self, act_on_this, keypress):
        zeek_installed, suricata_installed, filebeat_installed = zeek_profile.ProcessProfiler().is_installed, \
                                                                 suricata_profile.ProcessProfiler().is_installed, \
                                                                 filebeat_profile.ProcessProfiler().is_installed
        app_mapping = {}
        if filebeat_installed:
            if zeek_installed and suricata_installed:
                app_mapping = zeek_and_suricata_mapping
            elif zeek_installed:
                app_mapping = zeek_only_mapping
            elif suricata_installed:
                app_mapping = suricata_only_mapping

        npyscreen.notify_wait(
            act_on_this, form_color='GOODHL'
        )
        app_mapping[act_on_this]().run()
        exit(0)


class AgentConfigForm(npyscreen.ActionForm):

    def create(self):

        zeek_installed, suricata_installed, filebeat_installed = zeek_profile.ProcessProfiler().is_installed, \
                                                                 suricata_profile.ProcessProfiler().is_installed, \
                                                                 filebeat_profile.ProcessProfiler().is_installed
        app_mapping = {}
        if filebeat_installed:
            if zeek_installed and suricata_installed:
                app_mapping = zeek_and_suricata_mapping
            elif zeek_installed:
                app_mapping = zeek_only_mapping
            elif suricata_installed:
                app_mapping = suricata_only_mapping

        self.add(AgentConfigMultiSelect, values=sorted(app_mapping.keys()), max_height=5)


class AgentConfigApp(npyscreen.NPSAppManaged):
    """
    App Entry Point
    """

    def __init__(self):
        super(AgentConfigApp, self).__init__()

    def onStart(self):
        self.addForm('MAIN', AgentConfigForm, name='Agent Configurations')


def run_gui():
    AgentConfigApp().run()
