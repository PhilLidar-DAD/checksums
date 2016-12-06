#!/usr/bin/env python

from datetime import datetime, timedelta
import argparse
import fcntl
import json
import logging
import multiprocessing
import os
import platform
import random
import shutil
import subprocess
import sys
import time

_version = '2.2'
print(os.path.basename(__file__) + ': v' + _version)
_logger = logging.getLogger()
_LOG_FILE = os.path.splitext(os.path.basename(__file__))[0] + '.log'
_LOG_LEVEL = logging.DEBUG
_CONS_LOG_LEVEL = logging.INFO
_FILE_LOG_LEVEL = logging.DEBUG
_VP_FILE = '.verify_pending'
_LOCKFILE = '.lockfile'
_CPU_USAGE = .5
_VERIFY_LOG = os.path.splitext(os.path.basename(__file__))[0] + '_verify.log'
_VERIFY_DONE = set()

# Check platform
if platform.system() == 'Linux':
    SHA1SUM = 'sha1sum'
elif platform.system() == 'FreeBSD':
    SHA1SUM = 'shasum'

# Check if binaries exist
BINS = [SHA1SUM]
for bin in BINS:
    try:
        which = subprocess.check_output(['which', bin])
    except subprocess.CalledProcessError:
        print bin, 'is not in path! Exiting.'
        exit(1)


def _touch(fname, times=None):
    with open(fname, 'a'):
        os.utime(fname, times)


def _load_files(dir_path):
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

    last_modified = {}
    # Check if LAST_MODIFIED file already exists
    last_modified_filepath = os.path.join(dir_path, 'LAST_MODIFIED')
    if os.path.isfile(last_modified_filepath):
        last_modified = json.load(open(last_modified_filepath, 'r'))

    return (checksums, sha1sum_filepath,
            last_modified, last_modified_filepath)


def _list_files(dir_path):
    # List dir contents
    for f in sorted(os.listdir(dir_path)):
        file_path = os.path.join(dir_path, f)
        if (f != 'SHA1SUMS' and f != 'LAST_MODIFIED' and not f.startswith('.')
                and os.path.isfile(file_path)):
            yield f, file_path


def _generate_checksum(args):

    old_checksums, old_last_modified, file_path = args
    f = os.path.basename(file_path)
    compute_checksum = False

    # Compute checksum if file hasn't been computed yet
    if not f in old_checksums:
        _logger.info("File does not have checksum. Computing checksum: %s",
                     file_path)
        compute_checksum = True

    # Get last modified time
    lmt = os.stat(file_path).st_mtime
    # Recompute checksum if file has been modified
    if f in old_last_modified and lmt > old_last_modified[f]:
        _logger.info("File has been modified. Computing checksum: %s",
                     file_path)
        compute_checksum = True

    if compute_checksum:
        # Compute checksum
        shasum = subprocess.check_output([SHA1SUM, file_path])
        tokens = shasum.strip().split()
        checksum = tokens[0]
    else:
        checksum = old_checksums[f]

    return f, checksum, lmt


def _generate(dir_path):

    # Load files
    (old_checksums, sha1sum_filepath,
        old_last_modified, last_modified_filepath) = _load_files(dir_path)

    args = [(old_checksums, old_last_modified, file_path)
            for _, file_path in _list_files(dir_path)]
    r = pool.map_async(_generate_checksum, args)
    results = r.get()

    # Get results
    checksums = {}
    last_modified = {}
    for f, checksum, lmt in sorted(results):
        checksums[f] = checksum
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


def _verify_checksum(args):

    checksums, last_modified, file_path = args
    f = os.path.basename(file_path)

    # Check if file has been verified already
    if _VERIFY_DONE and file_path in _VERIFY_DONE:
        _logger.info('OK: %s', file_path)
        return

    # Compute checksum
    shasum = subprocess.check_output([SHA1SUM, file_path])
    checksum = shasum.strip().split()[0]

    # Get last modified time
    lmt = os.stat(file_path).st_mtime

    # Only compare checksums if file hasn't been modified
    if lmt == last_modified[f]:
        if checksum == checksums[f]:
            _logger.info('OK: %s', file_path)
        else:
            _logger.warn('FAILED: %s', file_path)


def _verify(dir_path):
    # Load files
    checksums, _, last_modified, _ = _load_files(dir_path)

    args = []
    for f, file_path in _list_files(dir_path):
        if f in checksums and f in last_modified:
            args.append((checksums, last_modified, file_path))

    r = pool.map_async(_verify_checksum, args)
    r.wait()


def parse_arguments():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version=_version)
    parser.add_argument('-v', '--verbose', action="store_true")
    parser.add_argument('action', choices=['generate', 'verify'])
    parser.add_argument('start_dir')
    args = parser.parse_args()
    return args


def _setup_logging(args):
    # Setup logging
    _logger.setLevel(_LOG_LEVEL)
    formatter = logging.Formatter(
        '[%(asctime)s] %(message)s')

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
    fh = logging.FileHandler(_LOG_FILE, mode='w')
    fh.setLevel(_FILE_LOG_LEVEL)
    fh.setFormatter(formatter)
    _logger.addHandler(fh)

if __name__ == "__main__":

    # Parge arguments
    args = parse_arguments()

    # Try to acquire lock
    lockfile = open(_LOCKFILE, 'w')
    while True:
        try:
            fcntl.lockf(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print 'Lock acquired!'
            if os.path.isfile(_VP_FILE):
                os.remove(_VP_FILE)
            break
        except IOError:
            print 'Cannot acquire lock! Script might already be running.'
            if args.action == 'generate':
                print 'Exiting...'
                exit(1)
            elif args.action == 'verify':
                # Notify previously running script that we have priority
                _touch(_VP_FILE)
                duration = random.randint(0, 60)
                print 'Sleeping for', duration, 'secs'
                time.sleep(duration)
                print 'Retrying acquiring lock...'

    if args.action == 'verify':
        # Set logging to warn only when verifying
        _CONS_LOG_LEVEL = logging.WARN

    # Setup logging
    _setup_logging(args)

    if args.action == 'verify':
        # Check if verify log exists
        if os.path.isfile(_VERIFY_LOG):
            _logger.info('Reading existing verify log...')
            # Read verified files from log file
            with open(_VERIFY_LOG, 'r') as open_file:
                for line in open_file:
                    if 'OK' in line:
                        tokens = line.strip().split('OK:')
                        _VERIFY_DONE.add(tokens[-1].strip())

    # Start pool
    pool = multiprocessing.Pool(processes=int(multiprocessing.cpu_count() *
                                              _CPU_USAGE))

    # Get checksums for all dirs in path
    start_path = os.path.abspath(args.start_dir)
    _logger.warn('Start path: %s', start_path)
    start_time = datetime.now()
    for root, dirs, files in os.walk(start_path):
        # Ignore hidden dirs
        dirs[:] = sorted([d for d in dirs if not d[0] == '.'])

        if args.action == 'generate':
            _generate(root)

            # Check if there's a pending verify
            if os.path.isfile(_VP_FILE):
                _logger.info('Verify pending file found! Exiting.')
                # Exit immediately
                exit(1)

        elif args.action == 'verify':
            _verify(root)

            # Save verification progress every 30mins
            if datetime.now() - start_time >= timedelta(minutes=30):
                shutil.copy(_LOG_FILE, _VERIFY_LOG)
                start_time = datetime.now()

    # Stop pool
    pool.close()

    # Delete verify log if it exists
    if args.action == 'verify':
        if os.path.isfile(_VERIFY_LOG):
            os.remove(_VERIFY_LOG)

    # Delete lock file
    lockfile.close()
    if os.path.isfile(_LOCKFILE):
        os.remove(_LOCKFILE)

    _logger.warn('Done!')
