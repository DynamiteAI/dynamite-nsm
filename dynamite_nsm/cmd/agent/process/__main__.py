from logging import DEBUG, INFO

from dynamite_nsm.logger import get_logger
from dynamite_nsm.cmd.agent.process import interface as agent_process_interface

if __name__ == '__main__':
    parser = agent_process_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('agent.process', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info(f'Calling agent.process.{args.entry_method_name}.')
    logger.debug(args.__dict__)
    result = agent_process_interface.execute(args)
    print(result)
