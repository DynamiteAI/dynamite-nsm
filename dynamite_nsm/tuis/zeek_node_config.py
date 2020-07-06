import npyscreen
from dynamite_nsm.services.zeek import config
from dynamite_nsm.utilities import get_environment_file_dict


class RemoveWorkerButton(npyscreen.ButtonPress):
    """
    Button Component for removing Zeek Workers
    """

    def __init__(self, *args, **keywords):
        super(RemoveWorkerButton, self).__init__(*args, **keywords)
        self.delete_value = keywords.get('delete_value')

    def whenPressed(self):
        res = npyscreen.notify_ok_cancel(
            'Are you sure you want to delete this worker - {}?'.format(self.delete_value),
            form_color='WARNING',
        )
        if not res:
            return

        self.parent.parentApp.zeek_config.remove_worker(self.delete_value)
        self.parent.parentApp.zeek_config.write_config()
        self.parent.parentApp.removeForm('MAIN')
        self.parent.parentApp.addForm('MAIN', ZeekNodeSettingsForm, name='Zeek Node Configuration')
        self.parent.parentApp.switchForm('MAIN')


class RemoveLoggerButton(npyscreen.ButtonPress):
    """
    Button Component for removing Zeek Loggers
    """

    def __init__(self, *args, **keywords):
        super(RemoveLoggerButton, self).__init__(*args, **keywords)
        self.delete_value = keywords.get('delete_value')

    def whenPressed(self):
        res = npyscreen.notify_ok_cancel(
            'Are you sure you want to delete this logger - {}?'.format(self.delete_value),
            form_color='WARNING',
        )
        if not res:
            return

        self.parent.parentApp.zeek_config.remove_logger(self.delete_value)

        self.parent.parentApp.zeek_config.write_config()
        self.parent.parentApp.removeForm('MAIN')
        self.parent.parentApp.addForm('MAIN', ZeekNodeSettingsForm, name='Zeek Node Configuration')
        self.parent.parentApp.switchForm('MAIN')


class RemoveProxyButton(npyscreen.ButtonPress):
    """
    Button Component for removing Zeek Proxies
    """

    def __init__(self, *args, **keywords):
        super(RemoveProxyButton, self).__init__(*args, **keywords)
        self.delete_value = keywords.get('delete_value')

    def whenPressed(self):
        res = npyscreen.notify_ok_cancel(
            'Are you sure you want to delete this proxy - {}?'.format(self.delete_value),
            form_color='WARNING',
        )
        if not res:
            return

        self.parent.parentApp.zeek_config.remove_proxy(self.delete_value)

        self.parent.parentApp.zeek_config.write_config()
        self.parent.parentApp.removeForm('MAIN')
        self.parent.parentApp.addForm('MAIN', ZeekNodeSettingsForm, name='Zeek Node Configuration')
        self.parent.parentApp.switchForm('MAIN')


class WorkerSelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting workers
    """

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.parentApp.getForm('EDITWORKERFM').value = act_on_this
        self.parent.parentApp.switchForm('EDITWORKERFM')


class LoggerSelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting loggers
    """

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.parentApp.getForm('EDITLOGGERFM').value = act_on_this
        self.parent.parentApp.getForm('EDITLOGGERFM').component_type = 'logger'
        self.parent.parentApp.switchForm('EDITLOGGERFM')


class ManagerSelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting manager
    """

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.parentApp.getForm('EDITMANAGERFM').value = act_on_this
        self.parent.parentApp.getForm('EDITMANAGERFM').component_type = 'manager'
        self.parent.parentApp.switchForm('EDITMANAGERFM')


class ProxySelect(npyscreen.MultiLineAction):
    """
    Multi-line selection component for selecting proxies
    """

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.parentApp.getForm('EDITPROXYFM').value = act_on_this
        self.parent.parentApp.getForm('EDITPROXYFM').component_type = 'proxy'
        self.parent.parentApp.switchForm('EDITPROXYFM')


class ZeekNodeSettingsForm(npyscreen.ActionForm):
    """
    Main Zeek Node Settings Form
    """

    def __init__(self, *args, **keywords):
        super(ZeekNodeSettingsForm, self).__init__(*args, **keywords)

    def create(self):
        workers = self.parentApp.zeek_config.list_workers()
        loggers = self.parentApp.zeek_config.list_loggers()
        proxies = self.parentApp.zeek_config.list_proxies()
        manager = [self.parentApp.zeek_config.get_manager()]
        if not any(manager):
            manager = []
        workers.append('<create new worker>')
        loggers.append('<create new logger>')
        proxies.append('<create new proxy>')
        self.add(npyscreen.TitleText, name='Workers', editable=False)
        self.add(WorkerSelect, values=workers, max_height=5)

        self.add(npyscreen.TitleText, name='Loggers', editable=False)
        self.add(LoggerSelect, values=loggers, max_height=5)
        self.add(npyscreen.TitleText, name='Proxies', editable=False)
        self.add(ProxySelect, values=proxies, max_height=5)
        self.add(npyscreen.TitleText, name='Manager', editable=False, max_height=3)
        self.add(ManagerSelect, values=manager)

    def on_ok(self):
        npyscreen.notify_wait(
            'Be sure to restart the agent for changes to take effect!', form_color='WARNING'
        )
        self.parentApp.setNextForm(None)


class EditWorkerForm(npyscreen.ActionForm):
    """
    Zeek Worker Edit Form
    """

    def __init__(self, *args, **keywords):
        self.value = None
        self.worker_config = None
        self.worker_name_text = None
        self.net_interface_text = None
        self.host_text = None
        self.threads_text = None
        self.cpus_text = None
        self.message = None
        self.delete_button = None
        super(EditWorkerForm, self).__init__(*args, **keywords)

    def create(self):
        self.message = self.add(npyscreen.TitleText,
                                name='Description',
                                value='Zeek workers analyze network traffic on a given interface.',
                                color='LABELBOLD',
                                editable=False)
        self.worker_name_text = self.add(npyscreen.TitleText, name='Worker Name', editable=True, rely=4)
        self.net_interface_text = self.add(npyscreen.TitleText, name='Network Interface')
        self.host_text = self.add(npyscreen.TitleText, name='Host')
        self.threads_text = self.add(npyscreen.TitleText, name='Worker Threads')
        self.cpus_text = self.add(npyscreen.TitleText, name='CPU Affinity')
        self.delete_button = self.add_widget(RemoveWorkerButton, name='Delete Worker', rely=13, color='DANGER')

    def beforeEditing(self):
        if self.value == '<create new worker>':
            self.value = None

        if self.value:
            self.worker_config = self.parentApp.zeek_config.node_config[self.value]
            self.worker_name_text.value = self.value
            self.net_interface_text.value = self.worker_config['interface']
            self.host_text.value = self.worker_config['host']
            self.threads_text.value = self.worker_config['lb_procs']
            self.cpus_text.value = self.worker_config['pin_cpus']
            self.delete_button.delete_value = self.value
            self.delete_button.hidden = False
        else:
            self.delete_button.hidden = True

    def on_ok(self):
        pin_cpus = []
        for cpu in self.cpus_text.value.split(','):
            try:
                pin_cpus.append(int(cpu.strip()))
            except ValueError:
                npyscreen.notify_ok_cancel(
                    'CPU Affinity must be given as a list of integers separated by commas.',
                    form_color='DANGER'
                )
                return
        try:
            int(self.threads_text.value)
        except ValueError:
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
        if not self.worker_name_text.value:
            npyscreen.notify_ok_cancel(
                'Worker name cannot be blank.',
                form_color='DANGER'
            )
            return
        if not self.host_text.value:
            npyscreen.notify_ok_cancel(
                'Host name cannot be blank.',
                form_color='DANGER'
            )
            return
        if self.value:
            self.parentApp.zeek_config.remove_worker(self.value)
        self.parentApp.zeek_config.add_worker(
            name=self.worker_name_text.value,
            interface=self.net_interface_text.value,
            host=self.host_text.value,
            lb_procs=self.threads_text.value,
            pin_cpus=tuple(pin_cpus)
        )

        # Switch back to the main interface
        npyscreen.notify_wait(
            self.worker_name_text.value + ' has been updated!', form_color='GOOD'
        )
        self.parentApp.zeek_config.write_config()
        self.parentApp.removeForm('MAIN')
        self.parentApp.addForm('MAIN', ZeekNodeSettingsForm, name='Zeek Node Configuration')
        self.parentApp.switchForm('MAIN')

    def on_cancel(self):
        self.parentApp.setNextFormPrevious()


class EditLoggerManagerProxy(npyscreen.ActionForm):
    """
    Zeek Logger/Manager/Proxy Edit Form
    """

    def __init__(self, *args, **keywords):
        self.value = None
        self.component_config = None
        self.logger_manager_proxy_config = None
        self.host_text = None
        self.component_name_text = None
        self.component_type = keywords.get('component_type')
        self.delete_button = None
        self.message = None
        self.logger_delete_created = False
        self.proxy_delete_created = False
        super(EditLoggerManagerProxy, self).__init__(*args, **keywords)

    def create(self):
        self.message = self.add(npyscreen.TitleText, color='LABELBOLD', name='Description', editable=False, wrap=True)

        self.component_name_text = self.add(npyscreen.TitleText, name='Component Name', rely=4)
        self.host_text = self.add(npyscreen.TitleText, name='Host')

    def beforeEditing(self):
        if self.value == '<create new logger>':
            self.value = None
        if self.value == '<create new proxy>':
            self.value = None

        if self.component_type == 'logger':
            self.message.value = 'If a logger is defined in your cluster configuration, ' \
                                 'then it will receive logs instead of the manager process.'
            if not self.logger_delete_created:
                self.delete_button = self.add_widget(
                    RemoveLoggerButton, name='Delete Logger', rely=10, color='DANGER')
                self.delete_button.delete_value = self.value
                self.logger_delete_created = True
        elif self.component_type == 'manager':
            self.message.value = 'The manager is a Zeek process that has two primary jobs. ' \
                                 'It receives log messages and notices from the rest of the nodes in the cluster, ' \
                                 'facilitates analysis which requires a centralized, global view of events or data.'
        elif self.component_type == 'proxy':
            if not self.proxy_delete_created:
                self.delete_button = self.add_widget(
                    RemoveProxyButton, name='Delete Proxy', rely=10, color='DANGER')
                self.delete_button.delete_value = self.value
                self.proxy_delete_created = True
            self.message.value = 'A proxy is a Zeek process that may be used to offload data storage or any arbitrary '\
                                 'workload. '

        if self.value:
            self.component_config = self.parentApp.zeek_config.node_config[self.value]
            self.component_name_text.value = self.value
            self.host_text.value = self.component_config['host']
        else:
            self.delete_button.hidden = True

    def on_ok(self):
        if not self.host_text.value:
            npyscreen.notify_ok_cancel(
                'Host name cannot be blank.',
                form_color='DANGER'
            )
            return
        if not self.component_name_text.value:
            npyscreen.notify_ok_cancel(
                '{} name cannot be blank.'.format(self.component_type.capitalize()),
                form_color='DANGER'
            )
            return
        if self.value:
            if self.component_type == 'logger':
                self.parentApp.zeek_config.remove_logger(self.value)
            if self.component_type == 'proxy':
                self.parentApp.zeek_config.remove_proxy(self.value)
            elif self.component_type == 'manager':
                self.parentApp.zeek_config.remove_manager(self.value)
                self.parentApp.zeek_config.add_manager(
                    name=self.component_name_text.value,
                    host=self.host_text.value,
                )
        if self.component_type == 'logger':
            self.parentApp.zeek_config.add_logger(
                name=self.component_name_text.value,
                host=self.host_text.value,
            )
        elif self.component_type == 'proxy':
            self.parentApp.zeek_config.add_proxy(
                name=self.component_name_text.value,
                host=self.host_text.value,
            )

        # Switch back to the main interface
        self.parentApp.zeek_config.write_config()
        npyscreen.notify_wait(
            self.component_name_text.value + ' has been updated!', form_color='GOOD'
        )
        self.parentApp.removeForm('MAIN')
        self.parentApp.addForm('MAIN', ZeekNodeSettingsForm, name='Zeek Node Configuration')
        self.parentApp.switchForm('MAIN')

    def on_cancel(self):
        self.parentApp.setNextFormPrevious()


class ZeekNodeConfiguratorApp(npyscreen.NPSAppManaged):
    """
    App Entry Point
    """

    def __init__(self):
        self.zeek_config = None

        super(ZeekNodeConfiguratorApp, self).__init__()

    def onStart(self):
        npyscreen.setTheme(npyscreen.Themes.ColorfulTheme)
        env_vars = get_environment_file_dict()
        self.zeek_config = config.NodeConfigManager(env_vars['ZEEK_HOME'])
        self.addForm('MAIN', ZeekNodeSettingsForm, name='Zeek Cluster Configuration')
        self.addForm('EDITWORKERFM', EditWorkerForm, name='Edit Zeek Worker')
        self.addForm('EDITLOGGERFM', EditLoggerManagerProxy, name='Edit Logger', component_type='logger')
        self.addForm('EDITMANAGERFM', EditLoggerManagerProxy, name='Edit Manager', component_type='manager')
        self.addForm('EDITPROXYFM', EditLoggerManagerProxy, name='Edit Proxy', component='proxy')
