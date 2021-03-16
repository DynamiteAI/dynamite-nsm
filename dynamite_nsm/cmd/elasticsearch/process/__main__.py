from logging import DEBUG, INFO

from dynamite_nsm.cmd.elasticsearch.process import interface as elasticsearch_process_interface
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.elasticsearch import process

if __name__ == '__main__':
    parser = elasticsearch_process_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('ELASTICSEARCH', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info(f'Calling elasticsearch.{args.action}.')
    logger.debug(args.__dict__)
    result = elasticsearch_process_interface.execute(args)
    if args.action != 'status':
        print(process.status(stdout=args.stdout, pretty_print_status=args.pretty_print_status,
                             verbose=args.verbose))
    else:
        print(result)
