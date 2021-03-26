from dynamite_nsm.cmd.package.saved_objects import interface as saved_objects_interface
from logging import DEBUG, INFO
from dynamite_nsm.logger import get_logger

if __name__ == '__main__':
    parser = saved_objects_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('Saved Objects', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info('Calling package.saved_objects')
    logger.debug(args.__dict__)
    result = saved_objects_interface.execute(args)

