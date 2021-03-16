from logging import DEBUG, INFO

from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.kibana import process
from dynamite_nsm.commandline.utilities.kibana.process import interface as kibana_process_interface

if __name__ == '__main__':
    parser = kibana_process_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('KIBANA', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info(f'Calling kibana.{args.action}.')
    logger.debug(args.__dict__)
    result = kibana_process_interface.execute(args)
    if args.action != 'status':
        print(process.status(stdout=args.stdout, pretty_print_status=args.pretty_print_status,
                             verbose=args.verbose))
    else:
        print(result)

