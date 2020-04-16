from dynamite_nsm.components.base import component
from dynamite_nsm.components.agent_dependencies import execution_strategy


class AgentDependencyComponent(component.BaseComponent):
    """
    Agent Dependency Component Wrapper intended for general use
    """

    def __init__(self, stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="Agent_Dependencies",
            component_description="Linux kernel development headers required for PF_RING modules to be installed.",
            install_strategy=execution_strategy.AgentDependencyInstallStrategy(
                stdout=stdout,
                verbose=verbose
            )
        )


class AgentDependencyCommandlineComponent(component.BaseComponent):
    """
    Agent Dependency Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="Agent_Dependencies",
            component_description="Linux kernel development headers required for PF_RING modules to be installed.",
        )

        if args.action_name == "install":

            self.register_install_strategy(
                execution_strategy.AgentDependencyInstallStrategy(
                    stdout=args.stdout,
                    verbose=args.verbose
                ))
            self.install()


if __name__ == '__main__':
    agt_dep_component = AgentDependencyComponent()
    agt_dep_component.install()
