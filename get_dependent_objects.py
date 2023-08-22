import argparse
import base64
import dataclasses as dc
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import List, Optional

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

    def get_any_json(self, uri: str) -> str:
        '''Send any GET request.'''
        logging.info('Sending GET %s ...', uri)

        headers = {
            'Authorization': f'bearer {self.access_token}'
        }

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
        json_result = json.loads(response.text)
        return json_result

def get_from_cli_args() -> argparse.Namespace:
    '''Extract values from CLI arguments.'''
    parser = argparse.ArgumentParser(description='Utility for getting dependent objects for decision using REST API')
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
        '--decision-uri',
        type=str, required=True,
        help='URI to decision'
    )
    parser.add_argument(
        '--major-version',
        type=int, required=True,
        help='Major version'
    )
    parser.add_argument(
        '--minor-version',
        type=int, required=True,
        help='Minor version'
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
    logfile = os.path.join(logdir, f'get_dep_obj_{datetime.now():%Y-%m-%d_%H-%M-%S}.log')
    logging.basicConfig(
        filename=logfile,
        level=logging.DEBUG,
        format='[%(asctime)s] [%(levelname)-8s] %(message)s')

    # Create a StreamHandler to log to stdout (console)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # Set the desired log level for console output
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)

    # Add the handlers to the root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(console_handler)

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


@dc.dataclass
class Model():
    uri: str
    model_id: str
    project_uri: str
    project_folder_uri: str

@dc.dataclass
class RuleSet():
    uri: str
    revision_uri: str
    lookups: List[str]

@dc.dataclass
class Treatment():
    uri: str
    revision_uri: str
    elig_rs_revision_uri: Optional[str]

@dc.dataclass
class TreatmentGroup():
    uri: str
    revision_uri: str
    treatments: List[str]

@dc.dataclass
class Decision():
    uri: str
    revision_uri: str
    subdecisions: List['Decision'] = dc.field(init=False, default=None)
    nodes: List[str] = dc.field(init=False, default=None)
    models: List[str] = dc.field(init=False, default=None)

    def __post_init__(self):
        self.subdecisions = []
        self.nodes = []
        self.models = []

@dc.dataclass
class DecisionLineage():
    viya_client: ViyaClient
    decision_uri: str
    major_version: int
    minor_version: int

    main_decision: Decision = dc.field(init=False)
    decisions: dict = dc.field(init=False)
    rulesets: dict = dc.field(init=False)
    treatment_groups: dict = dc.field(init=False)
    treatments: dict = dc.field(init=False)
    models: dict = dc.field(init=False)

    class RevisionNotFound(Exception):
        '''Revision was not found.'''

    def __post_init__(self):
        self.decisions = {}
        self.rulesets = {}
        self.treatment_groups = {}
        self.treatments = {}
        self.models = {}

    def remove_revision(self, uri: str) -> str:
        '''Remove revision part from URI.'''
        return '/'.join(uri.split('/')[:-2])

    def get_revision_by_version(self, uri: str, major_version: int, minor_version: int) -> str:
        '''Get revision ID of decision by uri and version numbers.'''
        revisions = self.viya_client.get_any_json(f'{uri}/revisions')
        for item in revisions['items']:
            if item['majorRevision'] == major_version and item['minorRevision'] == minor_version:
                return item['id']

        raise self.RevisionNotFound

    def get_decision(self, revision_uri) -> Decision:
        '''Extract decision from Viya.'''

        def get_steps(steps_src: List[dict]) -> List[dict]:
            steps = []

            for step in steps_src:
                # If step is branch Yes/No or Like
                if step['type'] == 'application/vnd.sas.decision.step.condition':
                    steps.extend(get_steps(step['onTrue']['steps']))
                    steps.extend(get_steps(step['onFalse']['steps']))
                # If step is branch Equals or Range
                elif step['type'] == 'application/vnd.sas.decision.step.branch':
                    for branch in step['branchCases']:
                        steps.extend(get_steps(branch['onTrue']['steps']))

                    steps.extend(get_steps(step['defaultCase']['steps']))
                else:
                    steps.append(step)

            return steps

        d = Decision(self.remove_revision(revision_uri), revision_uri)

        rev_src = self.viya_client.get_any_json(revision_uri)
        steps = get_steps(rev_src['flow']['steps'])
        for step in steps:
            item = None
            if step['type'] == 'application/vnd.sas.decision.step.custom.object':
                item = step['customObject']
                step_custom_type = item['type']

                if step_custom_type in (
                        'decisionPythonFile', 'decisionSQLCodeFile',
                        'decisionDS2CodeFile', 'decisionQryCodeFile'):

                    logging.debug('found code file %s', item['uri'])
                    d.nodes.append(item['uri'])
                elif step_custom_type == 'treatmentGroup':
                    logging.debug('found treatmentGroup %s', item['uri'])
                    d.nodes.append(item['uri'])
                elif step_custom_type == 'decision':
                    logging.debug('found decision %s', item['uri'])

                    subd = self.get_decision(item['uri'])
                    d.subdecisions.append(subd)

                elif step_custom_type == 'dynamicMASDecisionModule':
                    logging.warning('found MAS module')
                else:
                    logging.warning('found unknown custom object %s', json.dumps(item))
            elif step['type'] == 'application/vnd.sas.decision.step.ruleset':
                logging.debug('found ruleset %s', step["ruleset"]["id"])
                d.nodes.append(
                    f'/businessRules/ruleSets/{step["ruleset"]["id"]}'
                    f'/revisions/{step["ruleset"]["versionId"]}'
                )
            elif step['type'] == 'application/vnd.sas.decision.step.node.link':
                logging.warning('found link')
            elif step['type'] == 'application/vnd.sas.decision.step.model':
                logging.debug('found model %s', step["model"]["id"])
                d.models.append(step["model"]["id"])
            else:
                logging.warning('found unknown object %s', json.dumps(step))

        if d.revision_uri not in self.decisions:
            self.decisions[d.revision_uri] = d

        return d

    def process_treatment_groups(self) -> bool:
        '''Collect all treatment groups and extract dependent objects.'''
        trt_grps = []
        for d in self.decisions.values():
            for node_revision_uri in d.nodes:
                if node_revision_uri.startswith('/treatmentDefinitions/definitionGroups'):
                    trt_grps.append(node_revision_uri)
        trg_revision_uris = list(set(trt_grps))  # remove duplicates

        for trg_revision_uri in trg_revision_uris:
            trt_grp_info_src = self.viya_client.get_any_json(
                self.remove_revision(trg_revision_uri))

            treatments = []
            for member in trt_grp_info_src['members']:
                treatments.append(
                    f'/treatmentDefinitions/definitions/{member["definitionId"]}'
                    f'/revisions/{member["definitionRevisionId"]}'
                )

            trg = TreatmentGroup(
                self.remove_revision(trg_revision_uri), trg_revision_uri, treatments)
            self.treatment_groups[trg_revision_uri] = trg

    def process_treatments(self) -> bool:
        '''Collect all treatments and extract dependent objects.'''
        trts = []
        for trg in self.treatment_groups.values():
            trts.extend(trg.treatments)
        trt_revision_uris = list(set(trts))  # remove duplicates

        for trt_revision_uri in trt_revision_uris:
            trt_info_src = self.viya_client.get_any_json(trt_revision_uri)

            # Extract eligibility ruleset
            elig_rs_revision_uri = None
            if 'eligibility' in trt_info_src:
                elig_rs_revision_uri = trt_info_src['eligibility']['ruleSetUri']

            trt = Treatment(
                self.remove_revision(trt_revision_uri), trt_revision_uri, elig_rs_revision_uri)
            self.treatments[trt_revision_uri] = trt

    def process_rulesets(self) -> bool:
        '''Collect all rulesets and extract dependent objects.'''
        def retrieve_lookups(rs_revision_uri: str) -> List[str]:
            rules_count = 1000
            request_uri = rs_revision_uri + f'/rules?limit={rules_count}'
            rules = self.viya_client.get_any_json(request_uri)

            lookups_content = []
            for item in rules['items']:
                for c in item['conditions']:
                    if 'id' in c['lookup']:
                        lookups_content.append(c['lookup'])
                for a in item['actions']:
                    if 'id' in a['lookup']:
                        lookups_content.append(a['lookup'])

            lookups = []
            for content in lookups_content:
                lt_uri = '/referenceData/domains/' + content['id']
                lookups.append(lt_uri)

            return lookups

        rss = []
        trt: Treatment
        for trt in self.treatments.values():
            if trt.elig_rs_revision_uri is not None:
                rss.append(trt.elig_rs_revision_uri)
        for d in self.decisions.values():
            for node_revision_uri in d.nodes:
                if node_revision_uri.startswith('/businessRules'):
                    rss.append(node_revision_uri)
        rs_revision_uris = list(set(rss))  # remove duplicates

        for rs_revision_uri in rs_revision_uris:
            lookups = retrieve_lookups(rs_revision_uri)
            rs = RuleSet(self.remove_revision(rs_revision_uri), rs_revision_uri, lookups)
            self.rulesets[rs_revision_uri] = rs

    def process_models(self) -> bool:
        '''Process all models.'''

        def get_decision_models(d: Decision) -> List[str]:
            models = []
            models.extend(d.models)
            for subd in d.subdecisions:
                models.extend(get_decision_models(subd))
            return models

        model_ids = set(get_decision_models(self.main_decision))

        for model_id in model_ids:

            model_uri = f'/modelRepository/models/{model_id}'
            model_src_info = self.viya_client.get_any_json(model_uri)
            project_uri = f'/modelRepository/projects/{model_src_info["projectId"]}'
            project_folder_src = self.viya_client.get_any_json(
                f'/folders/folders/@item?childUri={project_uri}'
            )
            project_folder_uri = next(
                (link['uri'] for link in project_folder_src['links'] if link['rel'] == 'self'),
                None
            )

            model = Model(
                model_uri,
                model_id,
                project_uri,
                project_folder_uri
            )
            self.models[model_id] = model

        return True

    def fill_decision_lineage(self) -> bool:
        '''Extract all objects for decision from Viya.'''
        revision_id = self.get_revision_by_version(
            self.decision_uri, self.major_version, self.minor_version)

        self.main_decision = self.get_decision(
            f'{self.decision_uri}/revisions/{revision_id}')

        self.process_treatment_groups()

        self.process_treatments()

        self.process_rulesets()

        self.process_models()

        return True

    def __get_dependent_objects(self, d: Decision) -> List[str]:
        dep_uris = [d.uri]
        for node_revision_uri in d.nodes:
            dep_uris.append(self.remove_revision(node_revision_uri))
            if node_revision_uri.startswith('/treatmentDefinitions/definitionGroups'):
                trg = self.treatment_groups[node_revision_uri]
                for trt_revision_uri in trg.treatments:
                    trt: Treatment
                    trt = self.treatments[trt_revision_uri]
                    dep_uris.append(trt.uri)
                    if trt.elig_rs_revision_uri is not None:
                        rs = self.rulesets[trt.elig_rs_revision_uri]
                        dep_uris.append(rs.uri)
                        dep_uris.extend(rs.lookups)
            elif node_revision_uri.startswith('/businessRules'):
                rs = self.rulesets[node_revision_uri]
                dep_uris.extend(rs.lookups)
        for model_id in d.models:
            model: Model
            model = self.models[model_id]
            dep_uris.append(model.uri)
            dep_uris.append(model.project_uri)
            dep_uris.append(model.project_folder_uri)
        for subd in d.subdecisions:
            subd_dep_uris = self.__get_dependent_objects(subd)
            dep_uris.extend(subd_dep_uris)

        dependent_object_uris = list(set(dep_uris))

        return dependent_object_uris

    def get_dependent_objects(self, revision_uri: Optional[str]=None) -> List[str]:

        if revision_uri is None:
            revision_uri = self.main_decision.revision_uri

        dependent_object_uris = self.__get_dependent_objects(self.decisions[revision_uri])

        return dependent_object_uris


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
    logging.info('Decision URI: %s', args.decision_uri)
    logging.info('Decision Version: %s.%s', args.major_version, args.minor_version)

    # ============================================================================
    # Initialize Viya client
    try:
        viya_client = init_viya_client(
                hostname=args.hostname, access_token_auth=args.access_token_auth,
                user=args.user, password=args.password, client_id_secret=args.client_id_secret)
    except Exception:
        logging.error('Viya client cannot be initialized', exc_info=True)
        print(f'\n{"="*50}\nError occured. Please check logs\n{"="*50}')
        return

    # ============================================================================
    # Retrieve lineage
    print('\nStarting collecting lineage ...\n')

    dl = DecisionLineage(
        viya_client=viya_client,
        decision_uri=args.decision_uri,
        major_version=args.major_version,
        minor_version=args.minor_version
    )
    dl.fill_decision_lineage()

    print('\nLineage is collected!')

    # ============================================================================
    # Get code and save
    # Create dir
    out_dir = os.path.join(os.curdir,
                           'data')
    if not os.path.exists(out_dir):
        logging.info('Creating directory %s', out_dir)
        os.makedirs(out_dir, exist_ok=True)

    dependent_object_uris = dl.get_dependent_objects()
    output_fn = os.path.join(out_dir, f'depobj__{datetime.now():%Y%m%d_%H%M%S}.json')
    with open(output_fn, 'w', encoding='utf-8') as f:
        json.dump(
            {
                'decision_uri': dl.main_decision.uri,
                'decision_revision_uri': dl.main_decision.revision_uri,
                'version_name': f'{dl.major_version}.{dl.minor_version}',
                'items': dependent_object_uris
            }, f, indent=4)

    print(f'Dependent object URIs were saved to {output_fn}')

    timings1 = time.time()
    print(f'\nElapsed time: {round((timings1 - timings0)*1000, 3)} ms')
    print(f'\nLogs are saved to {logfile}')


if __name__ == '__main__':
    main()
