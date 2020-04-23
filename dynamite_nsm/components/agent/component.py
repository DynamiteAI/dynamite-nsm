from dynamite_nsm.components.base import component
from dynamite_nsm.components.agent import execution_strategy


class AgentComponent(component.BaseComponent):
    """
    Agent Component Wrapper intended for general use
    """

    def __init__(self, capture_network_interfaces, logstash_targets, agent_analyzers=('zeek', 'suricata'), tag=None,
                 prompt_on_uninstall=True, stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="Agent",
            component_description="Get context around activity on your network, discover threats and gain visibility.",
            install_strategy=execution_strategy.AgentInstallStrategy(
                capture_network_interfaces=capture_network_interfaces,
                logstash_targets=logstash_targets,
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
        component.BaseComponent.__init__(
            self,
            component_name="Agent",
            component_description="Get context around activity on your network, discover threats and gain visibility.",
        )

        if args.action_name == "install":
            self.register_install_strategy(
                execution_strategy.AgentInstallStrategy(
                    capture_network_interfaces=args.agent_capture_interfaces,
                    logstash_targets=args.logstash_targets,
                    agent_analyzers=args.agent_analyzers,
                    tag=args.agent_tag,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                ))
            self.install()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.AgentUninstallStrategy(
                    prompt_user=not args.skip_agent_uninstall_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.uninstall()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.AgentProcessStartStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.start()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.AgentProcessStopStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.stop()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.AgentProcessRestartStrategy(
                    stdout=not args.no_stdout,
                    status=True,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.restart()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.AgentProcessStatusStrategy(
                    include_subprocesses=args.verbose
                )
            )
            self.status()


if __name__ == '__main__':
    agt_component = AgentComponent(
        capture_network_interfaces=['eth0'],
        logstash_targets=['localhost:5044']
    )
    agt_component.install()
    agt_component.start()
    agt_component.stop()
    agt_component.status()
    agt_component.uninstall()
