import io
import os
import gzip
import tarfile
import hashlib
import argparse
from configparser import ConfigParser

import boto3
import tabulate

config = ConfigParser()

c = config.read('config.cfg')
if not c:
    config.read('../config.cfg')

S3_STAGING_BUCKET = config['S3']['staging_bucket']
S3_STAGING_PREFIX = config['S3']['staging_prefix']

AWS_SECRET_KEY_ID = config['AWS']['aws_access_key_id']
AWS_SECRET_ACCESS_KEY = config['AWS']['aws_secret_access_key']

S3_BASE_URL = f'https://{S3_STAGING_BUCKET}.s3.amazonaws.com/{S3_STAGING_PREFIX}'


# ============================================== FILE-IO FUNCTIONS ====================================================


def get_file_hash(path):
    """
    Get the MD5 hash given a file path
    :param path: The path to the file to hash
    :return: MD5 hash 32byte string
    """
    md5_hash = hashlib.md5()
    with open(path, "rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
        return md5_hash.hexdigest()


def get_deltas(base_root_dir, overwrite_root_dir):
    """
    Given two directories recursively merge overwrite_root into base_root, return deltas as list of changes.

    :param base_root_dir: The top level directory containing all required files
    :param overwrite_root_dir: The top level directory containing additions/modifications relative to base_root
    :return: A list  of deltas in the format: (type, action, relative_path)
    """
    deltas = []
    base_root_dir = os.path.join(base_root_dir, '')
    overwrite_root_dir = os.path.join(overwrite_root_dir, '')

    # Iterate through our overwrite_directory; this directory will be merged into base_directory
    for overwrite_root, overwrite_dirs, overwrite_files in os.walk(overwrite_root_dir, topdown=True):
        relative_directory = overwrite_root.replace(overwrite_root_dir, '')
        base_directory = os.path.join(base_root_dir, relative_directory)
        if relative_directory.startswith('.git'):
            continue
        # Check if the equivalent overwrite path exists in the base directory
        if not os.path.exists(base_directory):
            # If it doesn't mark the directory for creation
            deltas.append(('directory', 'create', relative_directory))
        for overwrite_file in overwrite_files:
            relative_file = os.path.join(relative_directory, overwrite_file)
            base_file_path = os.path.join(base_root_dir, relative_file)
            overwrite_file_path = os.path.join(overwrite_root_dir, relative_file)
            if not os.path.exists(base_file_path):
                deltas.append(('file', 'write', relative_file))
            else:
                if get_file_hash(overwrite_file_path) != get_file_hash(base_file_path):
                    deltas.append(('file', 'overwrite', relative_file))
    return deltas


def create_tar(version, base_root_dir, overwrite_root_dir=None, separate_mirrors_and_configs=True):
    """
    Merge overwrite_root_dir into base_root_dir bundle the results into a tarball; 
    if overwrite_root_dir is not specified base_root_dir will be wrapped into a tarball without performing a merge.

    :param version: The current config version number (must be valid float)
    :param base_root_dir: The top level directory containing all required files
    :param overwrite_root_dir: The top level directory containing additions/modifications relative to base_root
    :param separate_mirrors_and_configs: If True, two archives will be created, default_configs and mirrors; otherwise
                                         a single combined archive will be created.
    """

    base_root_dir = os.path.join(base_root_dir, '')

    io_combined_bytes = io.BytesIO()
    io_config_bytes = io.BytesIO()
    io_mirror_bytes = io.BytesIO()
    combined_archive = tarfile.open(fileobj=io_combined_bytes, mode='w')
    default_configs_archive = tarfile.open(fileobj=io_config_bytes, mode='w')
    mirrors_archive = tarfile.open(fileobj=io_mirror_bytes, mode='w')
    if overwrite_root_dir:
        overwrite_root_dir = os.path.join(overwrite_root_dir, '')
        for _type, action, overwrite_relative_path in get_deltas(base_root_dir, overwrite_root_dir):
            if _type == 'file':
                overwrite_base_file_path = os.path.join(overwrite_root_dir, overwrite_relative_path)
                if separate_mirrors_and_configs:
                    if overwrite_relative_path.startswith('default_configs/'):
                        default_configs_archive.add(overwrite_base_file_path, overwrite_relative_path)
                    elif overwrite_relative_path.startswith('mirrors/'):
                        mirrors_archive.add(overwrite_base_file_path, overwrite_relative_path)
                else:
                    combined_archive.add(overwrite_base_file_path, overwrite_relative_path)
    for base_root, base_dirs, base_files in os.walk(base_root_dir):
        relative_directory = base_root.replace(base_root_dir, '')
        for base_file in base_files:
            relative_file = os.path.join(relative_directory, base_file)
            base_file_path = os.path.join(base_root_dir, relative_file)
            try:
                if not separate_mirrors_and_configs:
                    combined_archive.getmember(relative_file)
                else:
                    if relative_file.startswith('default_configs/'):
                        default_configs_archive.getmember(relative_file)
                    elif relative_file.startswith('mirrors/'):
                        mirrors_archive.getmember(relative_file)
            except KeyError:
                if separate_mirrors_and_configs:
                    if relative_file.startswith('default_configs/'):
                        default_configs_archive.add(base_file_path, relative_file)
                    elif relative_file.startswith('mirrors/'):
                        mirrors_archive.add(base_file_path, relative_file)
                else:
                    combined_archive.add(base_file_path, relative_file)
    if separate_mirrors_and_configs:
        with gzip.open('default_configs.{}.tar.gz'.format(version), 'wb') as config_archive_out:
            io_config_bytes.seek(0)
            config_archive_out.write(io_config_bytes.read())
        with gzip.open('mirrors.{}.tar.gz'.format(version), 'wb') as mirrors_archive_out:
            io_mirror_bytes.seek(0)
            mirrors_archive_out.write(io_mirror_bytes.read())
    else:
        with gzip.open('combined.{}.tar.gz'.format(version), 'wb') as combined_archive_out:
            io_combined_bytes.seek(0)
            combined_archive_out.write(io_combined_bytes.read())


# ================================================ S3 Functions ======================================================

def list_dynamite_config_versions_s3():
    """
    Dynamite Configurations must each be versioned (E.G 0.72, 1.0, 1.01); lists the versions currently in this staging
    bucket

    :return: A list of versions
    """
    versions = set()
    s3 = boto3.client('s3',
                      aws_access_key_id=AWS_SECRET_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    for key in s3.list_objects(
            Bucket=S3_STAGING_BUCKET,
            Prefix=S3_STAGING_PREFIX)['Contents']:
        key = key['Key'].split('/')
        if len(key) != 3:
            continue
        try:
            versions.add(float(key[1]))
        except ValueError:
            continue

    return list(versions)


def copy_to_latest_prefix_s3(filename, version):
    """
    Copy the contents of an uploaded version to the "latest" prefix

    :param filename: Name of the file (E.G default_configs.tar.gz OR mirrors.tar.gz)
    :param version: The version number for the configuration set you wish to copy.
    """
    s3 = boto3.resource('s3',
                        aws_access_key_id=AWS_SECRET_KEY_ID,
                        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    prefix = os.path.join(S3_STAGING_PREFIX, version)
    basepath = prefix.split('/')[-2]
    s3.meta.client.copy(
        {
            'Bucket': S3_STAGING_BUCKET,
            'Key': os.path.join(prefix, filename)
        },
        S3_STAGING_BUCKET,
        os.path.join(basepath, 'latest', filename),
        ExtraArgs={'ACL': 'public-read'}
    )


def upload_file_to_s3(f_obj, filename, version):
    """
    Uploads a file like object to S3

    :param f_obj:  A file like object (rb mode)
    :param filename: The name of the file in S3
    :param version: The version number prefix that the file will be written into.
    """
    s3 = boto3.client('s3', aws_access_key_id=AWS_SECRET_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    if filename is None:
        filename = f_obj.name.split("/")[-1]
    else:
        filename = filename
    file_key = os.path.join(S3_STAGING_PREFIX, str(version), filename)
    s3.upload_fileobj(f_obj, S3_STAGING_BUCKET, file_key, ExtraArgs={'ACL': 'public-read'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Stage Dynamite Configurations to public S3 bucket.'
    )

    parser.add_argument('base_directory', metavar='base_directory', type=str,
                        help='The path to the directory containing the base configurations.')
    parser.add_argument('version', metavar='version', type=float,
                        help='The version number for the current configuration set.')
    parser.add_argument("--merge-directory", dest="merge_directory", type=str, default=None,
                        help="A directory containing additional/modified configurations "
                             "you want to merge with the base directory and incorporate into the deployment"
                        )
    parser.add_argument('--overwrite', default=False, dest='overwrite', action='store_true',
                        help='If true overwrites an old version if one is specified.')

    args = parser.parse_args()

    if args.merge_directory:
        headers = ["File Type", "Merge Action", "Path"]
        rows = [delta for delta in get_deltas(args.base_directory, args.merge_directory)]
        print(tabulate.tabulate(rows, headers=headers, tablefmt='fancy_grid'))
        print('\nDetected {} changes when building merge strategy for {} <- {}'.format(len(rows), args.base_directory,
                                                                                        args.merge_directory))
        res = input("OK with the above merge? [Y|n]: ")
        while True:
            if str(res).strip() == "n":
                exit(0)
            elif str(res).strip() == "":
                break
            elif str(res).strip() == "y":
                break
    existing_versions_in_s3 = list_dynamite_config_versions_s3()
    if args.version in existing_versions_in_s3 and not args.overwrite:
        print('Version {} already exists in {}. Use the --overwrite flag to overwrite {}'.format(args.version,
                                                                                                 S3_BASE_URL,
                                                                                                 args.version))
        exit(1)
    print("Creating tarballs for default_configs and mirrors...")
    create_tar(version=args.version, base_root_dir=args.base_directory, overwrite_root_dir=args.merge_directory,
               separate_mirrors_and_configs=True)
    default_config_f_name = "default_configs.{}.tar.gz".format(args.version)
    mirrors_f_name = "mirrors.{}.tar.gz".format(args.version)

    print("Uploading {} to {}".format(mirrors_f_name, os.path.join(S3_BASE_URL, str(args.version), 'mirrors.tar.gz')))
    with open(mirrors_f_name, 'rb') as mirrors_fobj:
        upload_file_to_s3(mirrors_fobj, 'mirrors.tar.gz', args.version)

    print(
        "Uploading {} to {}".format(default_config_f_name,
                                    os.path.join(S3_BASE_URL, str(args.version), 'default_configs.tar.gz')))
    with open(default_config_f_name, 'rb') as default_configs_fobj:
        upload_file_to_s3(default_configs_fobj, 'default_configs.tar.gz', args.version)
