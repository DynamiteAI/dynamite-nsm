from logging import DEBUG, INFO

from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.logstash import process
from dynamite_nsm.cmd.logstash.process import interface as logstash_process_interface


if __name__ == '__main__':
    parser = logstash_process_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('LOGSTASH', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info(f'Calling logstash.{args.action}.')
    logger.debug(args.__dict__)
    result = logstash_process_interface.execute(args)
    if args.action != 'status':
        print(process.status(stdout=args.stdout, pretty_print_status=args.pretty_print_status,
                             verbose=args.verbose))
    else:
        print(result)
