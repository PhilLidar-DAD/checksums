#!/usr/bin/env python

import argparse
import json
import logging
import os
import subprocess
import sys

_version = '0.3'
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
    old_checksums = {}
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
                old_checksums[fn] = tokens[0]

    last_modified = {}
    old_last_modified = {}
    # Check if LAST_MODIFIED file already exists
    last_modified_filepath = os.path.join(dir_path, 'LAST_MODIFIED')
    if os.path.isfile(last_modified_filepath):
        old_last_modified = json.load(open(last_modified_filepath, 'r'))

    # List dir contents
    for f in sorted(os.listdir(dir_path)):
        file_path = os.path.join(dir_path, f)
        if (f != 'SHA1SUMS' and f != 'LAST_MODIFIED' and not f.startswith('.')
                and os.path.isfile(file_path)):
            compute_checksum = False

            # Compute checksum if file hasn't been computed yet
            if not f in old_checksums:
                _logger.info("File does not have checksum. Computing checksum: %s",
                             file_path)
                compute_checksum = True

            # Get last modified time of file
            lmt = os.stat(file_path).st_mtime
            # Recompute checksum if file has been modified
            if f in old_last_modified and lmt > old_last_modified[f]:
                _logger.info("File has been modified. Computing checksum: %s",
                             file_path)
                compute_checksum = True

            if compute_checksum:
                # Compute checksum
                shasum = subprocess.check_output(['shasum', file_path])
                tokens = shasum.strip().split()
                checksums[f] = tokens[0]
            else:
                checksums[f] = old_checksums[f]

            last_modified[f] = lmt

    # Write checksums to file
    if checksums:
        with open(sha1sum_filepath, 'w') as open_file:
            for k, v in sorted(checksums.viewitems()):
                open_file.write(v + '  ' + k + '\n')
    # Write json to file
    if last_modified:
        json.dump(last_modified, open(last_modified_filepath, 'w'),
                  indent=4, sort_keys=True)


def parse_arguments():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version=_version)
    parser.add_argument('-v', '--verbose', action="store_true")
    parser.add_argument('start_dir')
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

    # Setup logging
    _setup_logging(args)

    # Get checksum for dir
    # _get_dir_checksums(os.path.abspath(args.dir))

    # Get checksums for all dirs in path
    start_path = os.path.abspath(args.start_dir)
    _logger.info('Start path: %s', start_path)
    for root, dirs, files in os.walk(start_path):
        # Ignore hidden dirs
        dirs[:] = [d for d in dirs if not d[0] == '.']

        _get_dir_checksums(root)
