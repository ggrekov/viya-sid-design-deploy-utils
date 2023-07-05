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


def get_from_cli_args() -> argparse.Namespace:
    '''Extract values from CLI arguments.'''
    parser = argparse.ArgumentParser(description='Utility for bulk deletion of Viya objects by URI from package JSON file using REST API')
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
    parser.add_argument(
        '--really-delete',
        action='store_true',
        help='a.k.a. Production mode (objects are going to be deleted)')
    parser.add_argument(
        '--decisions-only',
        action='store_true',
        help='Delete decisions only')
    parser.add_argument(
        '--input-file',
        type=str, required=True,
        help='Path to package JSON file'
    )

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
    logging.info('Input file: %s', args.input_file)

    if args.really_delete:
        print(f'{"="*50}\nPROD MODE. Objects will be deleted \n{"="*50}')
    else:
        print(f'{"="*50}\nTEST MODE. Nothing will be deleted\n{"="*50}')

    # ============================================================================
    # Reading file
    if not os.path.isfile(args.input_file):
        logging.error('File does not exist')
        print(f'\n{"="*50}\nFile does not exist\n{"="*50}')
        return

    with open(args.input_file, 'r', encoding='utf-8') as f:
        content = json.load(f)

    uri_list = content['requestedItems']
    print(f'Objects found from package: {len(uri_list)}')
    logging.info('Objects found from package: %s', len(uri_list))

    if len(uri_list) == 0:
        return

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
    # Delete objects
    print('\nStarting deletion ...\n')
    for uri in uri_list:
        if not args.really_delete:
            print(f'{uri:<70}\tSKIPPED')
        elif args.decisions_only and not uri.startswith('/decisions/flows'):
            print(f'{uri:<70}\tSKIPPED')
        else:
            status = viya_client.delete_object_by_uri(uri)
            print(f'{uri:<70}\t{status}')

    print('\nDeletion is completed!')
    timings1 = time.time()
    print(f'Elapsed time: {round((timings1 - timings0)*1000, 3)} ms')
    print(f'\nLogs are saved to {logfile}')


if __name__ == '__main__':
    main()
