from dynamite_nsm.components.base import component
from dynamite_nsm.components.managerd import execution_strategy


class ManagerdComponent(component.BaseComponent):
    """
    Manager Daemon Component Wrapper intended for general use
    """

    def __init__(self, prompt_on_uninstall=True, stdout=True, verbose=False):
        component.BaseComponent.__init__(
            self,
            component_name="Manager_Daemon",
            component_description="Gather local performance metrics.",
            install_strategy=execution_strategy.ManagerdInstallStrategy(
                stdout=stdout,
                verbose=verbose
            ),
            uninstall_strategy=execution_strategy.ManagerdUninstallStrategy(
                prompt_user=prompt_on_uninstall,
                stdout=stdout,
                verbose=verbose
            ),
            process_start_strategy=execution_strategy.ManagerdProcessStartStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_stop_strategy=execution_strategy.ManagerdProcessStopStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_restart_strategy=execution_strategy.ManagerdProcessRestartStrategy(
                status=True,
                stdout=stdout,
                verbose=verbose
            ),
            process_status_strategy=execution_strategy.ManagerdProcessStatusStrategy(stdout=stdout, verbose=verbose)
        )


class ManagerdCommandlineComponent(component.BaseComponent):
    """
    Managerd Commandline Component intended for commandline use.
    """

    def __init__(self, args):
        component.BaseComponent.__init__(
            self,
            component_name="Manager_Daemon",
            component_description="Gather local performance metrics.",
            change_password_strategy=None,
            install_strategy=None,
            uninstall_strategy=None,
            process_start_strategy=None,
            process_stop_strategy=None,
            process_restart_strategy=None,
            process_status_strategy=None
        )
        if args.action_name == "install":
            self.register_install_strategy(
                execution_strategy.ManagerdInstallStrategy(
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                ))
            self.execute_install_strategy()
        elif args.action_name == "uninstall":
            self.register_uninstall_strategy(
                execution_strategy.ManagerdUninstallStrategy(
                    prompt_user=not args.skip_managerd_uninstall_prompt,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout
                )
            )
            self.execute_uninstall_strategy()
        elif args.action_name == "start":
            self.register_process_start_strategy(
                execution_strategy.ManagerdProcessStartStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_start_strategy()
        elif args.action_name == "stop":
            self.register_process_stop_strategy(
                execution_strategy.ManagerdProcessStopStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_stop_strategy()
        elif args.action_name == "restart":
            self.register_process_restart_strategy(
                execution_strategy.ManagerdProcessRestartStrategy(
                    status=True,
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout,
                )
            )
            self.execute_process_restart_strategy()

        elif args.action_name == "status":
            self.register_process_status_strategy(
                execution_strategy.ManagerdProcessStatusStrategy(
                    stdout=not args.no_stdout,
                    verbose=args.verbose and not args.no_stdout)
            )
            self.execute_process_status_strategy()


if __name__ == '__main__':
    managerd_component = ManagerdComponent()
    managerd_component.execute_install_strategy()
    managerd_component.execute_process_start_strategy()
    managerd_component.execute_process_stop_strategy()
    managerd_component.execute_process_status_strategy()
    managerd_component.execute_uninstall_strategy()
