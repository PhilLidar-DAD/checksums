#!/usr/bin/env python

from pprint import pprint
import argparse
import logging
import os
import shutil
import sys
import subprocess

_version = '0.1'
print(os.path.basename(__file__) + ': v' + _version)
_logger = logging.getLogger()
_LOG_LEVEL = logging.DEBUG
_CONS_LOG_LEVEL = logging.INFO
_FILE_LOG_LEVEL = logging.DEBUG

# Check if binaries exist
BINS = ['shasum']
for bin in BINS:
    try:
        which = subprocess.check_output(['which', bin])
    except subprocess.CalledProcessError:
        print bin, 'is not in path! Exiting.'
        exit(1)


def _get_dir_checksums(dir_path):
    # Check if dir path exists
    if not os.path.isdir(dir_path):
        _logger.error('%s does not exist! Exiting.')
        return

    _logger.info('Processing dir: %s', dir_path)
    checksums = {}
    # Check if SHA1SUMS file already exists
    sha1sum_filepath = os.path.join(dir_path, 'SHA1SUMS')
    if os.path.isfile(sha1sum_filepath):
        # Read files from SHA1SUM file that already have checksums
        with open(sha1sum_filepath, 'r') as open_file:
            for line in open_file:
                tokens = line.strip().split()
                # Strip wildcard from filename if it exists
                fn = tokens[1]
                if fn.startswith('?'):
                    fn = fn[1:]
                checksums[fn] = tokens[0]

    # List dir contents
    for f in sorted(os.listdir(dir_path)):
        file_path = os.path.join(dir_path, f)
        if f != 'SHA1SUMS' and os.path.isfile(file_path):
            # Check if file already has checksum
            if not f in checksums:
                # Compute checksum
                _logger.info('Computing checksum: %s', file_path)
                shasum = subprocess.check_output(['shasum', '-p', file_path])
                tokens = shasum.strip().split()
                checksums[f] = tokens[0]

    # Write checksums to file
    with open(sha1sum_filepath, 'w') as open_file:
        for k, v in sorted(checksums.viewitems()):
            open_file.write(v + ' ' + k + '\n')


def parse_arguments():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version=_version)
    parser.add_argument('-v', '--verbose', action="store_true")
    parser.add_argument('dir')
    args = parser.parse_args()
    return args


def _setup_logging(args):
    # Setup logging
    _logger.setLevel(_LOG_LEVEL)
    formatter = logging.Formatter(
        '[%(asctime)s] (%(levelname)s) : %(message)s')

    # Check verbosity for console
    if args.verbose:
        global _CONS_LOG_LEVEL
        _CONS_LOG_LEVEL = logging.DEBUG

    # Setup console logging
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(_CONS_LOG_LEVEL)
    ch.setFormatter(formatter)
    _logger.addHandler(ch)

    # Setup file logging
    fh = logging.FileHandler(os.path.basename(__file__) + '.log', mode='w')
    fh.setLevel(_FILE_LOG_LEVEL)
    fh.setFormatter(formatter)
    _logger.addHandler(fh)

if __name__ == "__main__":

    # Parge arguments
    args = parse_arguments()
    pprint(args)

    # Setup logging
    _setup_logging(args)

    # Get checksum for dir
    _get_dir_checksums(os.path.abspath(args.dir))
