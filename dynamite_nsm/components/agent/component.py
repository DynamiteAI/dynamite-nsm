from dynamite_nsm.components.base import component
from dynamite_nsm.components.agent import execution_strategy


class AgentComponent(component.BaseComponent):
    """
    Agent Component Wrapper intended for general use
    """

    def __init__(self, capture_network_interfaces, targets, kafka_topic=None, kafka_username=None, kafka_password=None,
                 agent_analyzers=('zeek', 'suricata'), tag=None, prompt_on_uninstall=True, stdout=True, verbose=False):

        self.agent_update_strategy = execution_strategy.AgentSuricataUpdateStrategy()

        component.BaseComponent.__init__(
            self,
            component_name="Agent",
            component_description="Get context around activity on your network, discover threats and gain visibility.",
            config_strategy=execution_strategy.AgentConfigStrategy(),
            install_strategy=execution_strategy.AgentInstallStrategy(
                capture_network_interfaces=capture_network_interfaces,
                targets=targets,
                kafka_topic=kafka_topic,
                kafka_username=kafka_username,
                kafka_password=kafka_password,
                agent_analyzers=agent_analyzers,
                tag=tag,
                stdout=stdout,
                verbose=verbose
            ),
            uninstall_strategy=execution_strategy.AgentUninstallStrategy(
                prompt_user=prompt_on_uninstall,
                stdout=stdout,
                verbose=verbose
            ),
            process_start_strategy=execution_strategy.AgentProcessStartStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_stop_strategy=execution_strategy.AgentProcessStopStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_restart_strategy=execution_strategy.AgentProcessRestartStrategy(
                stdout=stdout,
                verbose=verbose,
                status=True
            ),
            process_status_strategy=execution_strategy.AgentProcessStatusStrategy(
                include_subprocesses=verbose
            )
        )


class AgentCommandlineComponent(component.BaseComponent):
    """
    Agent Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        self.agent_update_strategy = None

        component.BaseComponent.__init__(
            self,
            component_name="Agent",
            component_description="Get context around activity on your network, discover threats and gain visibility.",
            config_strategy=None,
            install_strategy=None,
            uninstall_strategy=None,
            process_start_strategy=None,
            process_stop_strategy=None,
            process_restart_strategy=None,
            process_status_strategy=None,
            agent_update_strategy=None
        )
        if args.action_name == "config":
            self.register_config_strategy(execution_strategy.AgentConfigStrategy())
            self.execute_config_strategy()
        if args.action_name == "install":
            self.register_install_strategy(
                execution_strategy.AgentInstallStrategy(
                    capture_network_interfaces=args.agent_capture_interfaces,
                    targets=args.targets,
                    kafka_topic=args.kafka_topic,
                    kafka_username=args.kafka_username,
                    kafka_password=args.kafka_password,
                    agent_analyzers=args.agent_analyzers,
                    tag=args.agent_tag,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                ))
            self.execute_install_strategy()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.AgentUninstallStrategy(
                    prompt_user=not args.skip_agent_uninstall_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_uninstall_strategy()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.AgentProcessStartStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_process_start_strategy()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.AgentProcessStopStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_process_stop_strategy()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.AgentProcessRestartStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_process_restart_strategy()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.AgentProcessStatusStrategy(
                    include_subprocesses=args.verbose
                )
            )
            self.execute_process_status_strategy()
        elif args.action_name == "update":
            self.register_agent_update_strategy(
                execution_strategy.AgentSuricataUpdateStrategy()
            )
            self.execute_agent_update_strategy()


if __name__ == '__main__':
    agt_component = AgentComponent(
        capture_network_interfaces=['eth0'],
        targets=['localhost:5044']
    )
    agt_component.execute_install_strategy()
    agt_component.execute_process_start_strategy()
    agt_component.execute_process_stop_strategy()
    agt_component.execute_process_status_strategy()
    agt_component.execute_uninstall_strategy()
