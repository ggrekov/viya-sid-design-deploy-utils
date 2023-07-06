import argparse
import re
import json
import logging
import os
import time
from datetime import datetime
from typing import Optional


class CompareGlobalVars():
    left_side: dict
    right_side: dict

    only_on_left: dict
    only_on_right: dict
    values_differ: dict

    def __init__(self, left_side: dict, right_side: dict):
        self.left_side = left_side
        self.right_side = right_side

        self.only_on_left = {}
        self.only_on_right = {}
        self.values_differ = {}

        self.__compare()

    def __compare(self):
        set_left = set(self.left_side.keys())
        set_right = set(self.right_side.keys())

        only_left = set_left.difference(set_right)
        for var_name in only_left:
            self.only_on_left[var_name] = self.left_side[var_name]

        only_right = set_right.difference(set_left)
        for var_name in only_right:
            self.only_on_right[var_name] = self.right_side[var_name]

        for var_name in set_left.intersection(set_right):
            if self.left_side[var_name] != self.right_side[var_name]:
                self.values_differ[var_name] = {
                    'left': self.left_side[var_name],
                    'right': self.right_side[var_name]
                }
    
    @property
    def as_json(self):
        result = {
            'only_on_left': self.only_on_left,
            'only_on_right': self.only_on_right,
            'values_differ': self.values_differ
        }
        return result


def get_from_cli_args() -> argparse.Namespace:
    '''Extract values from CLI arguments.'''
    parser = argparse.ArgumentParser(description='Utility for comparing source codes of sid_global_variable_container')
    parser.add_argument(
        '--input-1',
        type=str, required=True,
        help='First source code'
    )
    parser.add_argument(
        '--input-2',
        type=str, required=True,
        help='Second source code'
    )
    args = parser.parse_args()

    return args


def configure_logs() -> str:
    curdir = os.path.dirname(os.path.abspath(__file__))
    logdir = os.path.join(curdir, 'logs')
    if not os.path.exists(logdir):
        os.mkdir(logdir)
    logfile = os.path.join(logdir, f'app_{datetime.now():%Y-%m-%d_%H-%M-%S}.log')
    logging.basicConfig(
        filename=logfile,
        level=logging.DEBUG,
        format='[%(asctime)s] [%(levelname)-8s] %(message)s')

    return logfile


def extract(src_code: str) -> dict:
    # Regex
    result = {}

    pattern1 = re.compile(
        r'.+?gv_key = \'(?P<var_name>.+?)\'.+?'
    )
    pattern2 = re.compile(
        r'.+?gv_value = \'(?P<var_value>.+?)\'.+?'
    )
    pattern3 = re.compile(
        r'.+?gv_0.ref().+?'
    )

    lines = src_code.split('\n')
    for i in range(len(lines)):
        line = lines[i]
        match = pattern1.search(line)
        if not match:
            continue

        parsed = match.groupdict()
        var_name = parsed['var_name']

        i = i + 1
        line = lines[i]
        match = pattern2.search(line)
        if not match:
            continue
        parsed = match.groupdict()
        var_value = parsed['var_value']

        i = i + 1
        line = lines[i]
        match = pattern3.search(line)
        if not match:
            continue

        result[var_name] = var_value

    return result

def main():
    '''Main function.'''
    timings0 = time.time()
    # ============================================================================
    # Get arguments
    args = get_from_cli_args()
    
    # ============================================================================
    # Configure logs
    logfile = configure_logs()

    # ============================================================================
    logging.info('Input 1 file: %s', args.input_1)
    logging.info('Input 2 file: %s', args.input_2)

    # ============================================================================
    # Extract and compare

    # Read files
    with open(args.input_1, 'r', encoding='utf-8') as f:
        code_1 = f.read()
    with open(args.input_2, 'r', encoding='utf-8') as f:
        code_2 = f.read()

    # Extract data
    global_vars_1 = extract(code_1)
    global_vars_2 = extract(code_2)

    print(f'Variables in module 1: {len(global_vars_1)}')
    print(f'Variables in module 2: {len(global_vars_2)}')

    comparison = CompareGlobalVars(global_vars_1, global_vars_2)
    logging.info(comparison.as_json)
    
    # only in left
    if len(comparison.only_on_left) > 0:
        print('\n-------------------\n')
        print('Variables that are present ONLY in module 1:')
        print(json.dumps(comparison.only_on_left, indent=4))
    # only in right
    if len(comparison.only_on_right) > 0:
        print('\n-------------------\n')
        print('Variables that are present ONLY in module 2:')
        print(json.dumps(comparison.only_on_right, indent=4))
    # values differ
    if len(comparison.values_differ) > 0:
        print('\n-------------------\n')
        print('Variables with different values:')
        print(json.dumps(comparison.values_differ, indent=4))

    print('\nDone!')
    timings1 = time.time()
    print(f'\nElapsed time: {round((timings1 - timings0)*1000, 3)} ms')
    print(f'\nLogs are saved to {logfile}')


if __name__ == '__main__':
    main()
