import argparse
import base64
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.urllib3.disable_warnings(InsecureRequestWarning)

class ViyaConnectError(Exception):
    '''Viya connect error'''

class ViyaClient():
    '''Viya REST API client.'''
    hostname: str
    user_id: str
    password: str
    client_id_secret: str
    access_token: str

    def __get_access_token(self):
        '''Get access token.'''

        request_url = f'{self.hostname}/SASLogon/oauth/token'

        params = {}
        token_cred = base64.b64encode(
            self.client_id_secret.encode('ascii')
        ).decode('ascii')
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Basic {token_cred}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        request_body = f'grant_type=password&username={self.user_id}&password={self.password}'

        response = requests.post(
            request_url,
            data=request_body,
            params=params,
            headers=headers,
            timeout=60,
            verify=False
        )
        response.raise_for_status()
        response_body = json.loads(response.text)

        self.access_token = response_body.get('access_token')
        if self.access_token is None:
            raise ViyaConnectError('Failed to retrieve access_token')

    def __init__(self, hostname: str,
        user_id: Optional[str]=None, password: Optional[str]=None,
        client_id_secret: Optional[str]=None,
        access_token: Optional[str]=None
    ):
        self.hostname = hostname
        self.user_id = user_id
        self.password = password
        self.client_id_secret = client_id_secret
        self.access_token = access_token

        if self.access_token is None:
            self.__get_access_token()
        logging.info('Viya REST API client was initialized successfully')

    def delete_object_by_uri(self, uri: str) -> str:
        '''Delete object by URI.'''
        logging.info('Deleting uri %s ...', uri)
        
        headers = {
            'Authorization': f'bearer {self.access_token}'
        }
        
        request_url = f'{self.hostname}{uri}'
        response = requests.delete(
            request_url,
            data=None,
            params={},
            headers=headers,
            timeout=60,
            verify=False
        )
        if response.status_code == 204:
            return 'OK'
        elif response.status_code == 404:
            return 'NOT_FOUND'
        return 'FAILED'

    def get_module_src_code(self, module_id: str) -> str:
        """Get source code of module."""
        logging.info('Getting source code for %s ...', module_id)

        headers = {
            'Authorization': f'bearer {self.access_token}'
        }

        uri = f'/microanalyticScore/modules/{module_id}/source'
        request_url = f'{self.hostname}{uri}'
        response = requests.get(
            request_url,
            data=None,
            params={},
            headers=headers,
            timeout=60,
            verify=False
        )
        response.raise_for_status()
        module_source = json.loads(response.text)
        return module_source['source']


def get_from_cli_args() -> argparse.Namespace:
    '''Extract values from CLI arguments.'''
    parser = argparse.ArgumentParser(description='Utility for getting source code of sid_global_variable_container using REST API')
    parser.add_argument(
        '--hostname',
        type=str, required=True,
        help='Viya hostname in format http(s)://server-name.com'
    )
    parser.add_argument(
        '-u', '--user',
        type=str, required=False,
        help='Viya user name'
    )
    parser.add_argument(
        '-p', '--password',
        type=str, required=False,
        help='Viya user password'
    )
    parser.add_argument(
        '-c', '--client-id-secret',
        type=str, required=False,
        help='Client ID and Client Secret in format <client_id>:<client_secret>'
    )
    parser.add_argument(
        '--access-token-auth', '-a',
        action='store_true',
        help='Provide this option if you have authentication token. It must be located in token.txt in the working directory.')

    args = parser.parse_args()

    if not args.access_token_auth:
        if args.user is None or args.password is None or args.client_id_secret is None:
            print('ERROR: Wrong authentication information is provided.')
            print('User, password, client are required if no access token is provided')
            sys.exit(4)

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

def init_viya_client(hostname: str, access_token_auth: str, user: str, password: str, client_id_secret: str) -> ViyaClient:
    if access_token_auth:
        with open('token.txt', 'r', encoding='utf-8') as f:
            access_token = f.read()

        viya_client = ViyaClient(
            hostname=hostname,
            access_token=access_token
        )
    else:
        viya_client = ViyaClient(
            hostname=hostname,
            user_id=user,
            password=password,
            client_id_secret=client_id_secret
        )

    return viya_client


def make_it_pretty(src_code: str) -> str:
    return src_code.replace('\\n', '\n').replace('\\"', '"')

def extract(src_code: str) -> dict:
    # Regex
    return {}

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
    logging.info('Hostname: %s', args.hostname)
    module_id = 'sid_global_variable_container'
    logging.info('MAS module: %s', module_id)

    # ============================================================================
    # Initialize Viya client
    try:
        viya_client = init_viya_client(
                hostname=args.hostname, access_token_auth=args.access_token_auth,
                user=args.user, password=args.password, client_id_secret=args.client_id_secret)
    except Exception as e:
        logging.error('Viya client cannot be initialized', exc_info=True)
        print(f'\n{"="*50}\nError occured. Please check logs\n{"="*50}')
        return

    # ============================================================================
    # Get code and save
    # Create dir
    out_dir = os.path.join(os.curdir,
                           'data',
                           f'{module_id}__{datetime.now():%Y%m%d_%H%M%S}')
    if not os.path.exists(out_dir):
        logging.info('Creating directory %s', out_dir)
        os.makedirs(out_dir, exist_ok=True)

    # Get source code and save it
    try:
        src_code = make_it_pretty(viya_client.get_module_src_code(module_id))
        src_code_fn = os.path.join(out_dir, f'{module_id}_code.sas')
        with open(src_code_fn, 'w', encoding='utf-8') as f:
            f.write(src_code)
    except Exception as e:
        logging.error('Source code cannot be retrieved', exc_info=True)
        print(f'\n{"="*50}\nError occured. Please check logs\n{"="*50}')
        return

    print('\nGlobal variables were retrieved!')
    print(f'Source code is saved to {src_code_fn}')
    timings1 = time.time()
    print(f'\nElapsed time: {round((timings1 - timings0)*1000, 3)} ms')
    print(f'\nLogs are saved to {logfile}')


if __name__ == '__main__':
    main()
