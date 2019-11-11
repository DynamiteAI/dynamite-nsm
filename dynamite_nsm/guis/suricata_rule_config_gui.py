import npyscreen
from dynamite_nsm.utilities import get_environment_file_dict
from dynamite_nsm.services.suricata import SuricataConfigurator


class SuricataRuleSettingsForm(npyscreen.ActionForm):
    """
    Main Suricata Script Settings Form
    """
    def __init__(self, *args, **keywords):
        self.rendered_rules = []
        super(SuricataRuleSettingsForm, self).__init__(*args, **keywords)

    def create(self):
        self.add(npyscreen.TitleText, name='Pick your Suricata Rules',
                 value='Suricata rules provide signature based detection and alerting.',
                 color='LABELBOLD',
                 editable=False
                )
        enabled_rules = self.parentApp.suricata_rule_config.list_enabled_rules()
        disabled_rules = self.parentApp.suricata_rule_config.list_disabled_rules()
        combined_rules = list(enabled_rules)
        combined_rules.extend(disabled_rules)
        error = 0
        for i, rule in enumerate(sorted(combined_rules)):
            try:
                if i == 0:
                    self.rendered_rules.append(
                        self.add(npyscreen.RoundCheckBox, name=rule, value=rule in enabled_rules, rely=5,
                                 relx=2 + (70 * error))
                    )
                else:
                    self.rendered_rules.append(
                        self.add(npyscreen.RoundCheckBox, name=rule, value=rule in enabled_rules,
                                 relx=2 + (70 * error))
                    )
            except npyscreen.wgwidget.NotEnoughSpaceForWidget:
                error += 1
                self.rendered_rules.append(
                    self.add(npyscreen.RoundCheckBox, name=rule, value=rule in enabled_rules, rely=5,
                             relx=2 + (70 * error))
                )

    def on_ok(self):
        npyscreen.notify_wait(
            'Be sure to restart the agent for changes to take effect!', form_color='WARNING'
        )
        for rule in self.rendered_rules:
            if rule.value:
                self.parentApp.suricata_rule_config.enable_rule(rule.name)
            else:
                self.parentApp.suricata_rule_config.disable_rule(rule.name)

        self.parentApp.suricata_rule_config.write_config()
        self.parentApp.setNextForm(None)


class SuricataRuleConfiguratorApp(npyscreen.NPSAppManaged):
    """
    App Entry Point
    """
    def __init__(self):
        self.suricata_rule_config = None

        super(SuricataRuleConfiguratorApp, self).__init__()

    def onStart(self):
        env_vars = get_environment_file_dict()
        self.suricata_rule_config = SuricataConfigurator(env_vars['SURICATA_CONFIG'])
        self.addForm('MAIN', SuricataRuleSettingsForm, name='Suricata Rule Configuration')