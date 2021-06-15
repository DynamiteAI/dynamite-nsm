from logging import DEBUG, INFO

from dynamite_nsm.cmd.elasticsearch.process import interface as elasticsearch_process_interface
from dynamite_nsm.logger import get_logger

if __name__ == '__main__':
    parser = elasticsearch_process_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('elasticsearch.process', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info(f'Calling elasticsearch.process.{args.entry_method_name}.')
    logger.debug(args.__dict__)
    result = elasticsearch_process_interface.execute(args)
    print(result)
