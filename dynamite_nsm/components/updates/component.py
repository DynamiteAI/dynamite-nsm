from dynamite_nsm.components.base import component
from dynamite_nsm.components.updates import execution_strategy


class UpdatesComponent(component.BaseComponent):
    """
    Updates Component Wrapper intended for general use
    """

    def __init__(self, stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="Update_Configs_Mirrors",
            component_description="Fetch the latest default configurations/mirrors for agent and monitor components.",
            install_strategy=execution_strategy.AgentDependencyInstallStrategy(
                stdout=stdout,
                verbose=verbose
            )
        )


class UpdatesCommandlineComponent(component.BaseComponent):
    """
    Updates Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="Update_Configs_Mirrors",
            component_description="Fetch the latest default configurations/mirrors for agent and monitor components.",
            install_strategy=None
        )

        if args.action_name == "install":

            self.register_install_strategy(
                execution_strategy.UpdateInstallStrategy(
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                ))
            self.execute_install_strategy()


if __name__ == '__main__':
    updt_component = UpdatesComponent()
    updt_component.execute_install_strategy()
