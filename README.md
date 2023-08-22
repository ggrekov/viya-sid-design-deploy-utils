# Utilities for SAS Intelligent Decisioning objects deployment

This is the set of various useful utilities for making SID objects deployment easier.

## Prerequisites

1. Python 3.6+
1. External package `requests`
1. Network connection to destination Viya environment

## How to install

1. Put `*.py` files at some place on server

## Utility for deletion objects from package

This utility is suggested to be used as preparatory step for importing the package with design objects of SAS Intelligent Decisioning.  
It grabs the list of URIs from package .json file and delete them one-by-one via SAS Viya REST API.  

> **Problem description:**  
> SAS ID decisions consist of bunch of objects such as subdecisions, rule sets, code files and others. In order to move the whole implementation from one environment to another properly, all objects must be included into the package. The unique identifier of the object **across all environments** is URI.  
> When user imports the package (via SAS Environment Manager or `sas-admin` CLI), the system attempts to overwrite these objects by URI. And sometimes this process is failed. For example, if the object's location was changed. Also there are other reasons, which are not clearly identified.  
> The workaround is - delete all objects going to be imported from target environments, and then try to import again. There could be dozens/hundreds/thousands of objects, and there is no OOTB utility for bulk delete. This utility automates this process.

How to use:

1. Put package JSON file exported from target Viya environment at some place on server
1. Navigate to directory where `uri_deletion_util.py` resides
1. Run utility with necessary options provided

    Here is the help:

    ```bash
    usage: uri_deletion_util.py [-h] --hostname HOSTNAME -u USER -p PASSWORD -c CLIENT_ID_SECRET [--really-delete] [--decisions-only] --input-file INPUT_FILE

    Utility for bulk deletion of Viya objects by URI from package JSON file using REST API

    options:
    -h, --help            show this help message and exit
    --hostname HOSTNAME   Viya hostname in format http(s)://server-name.com
    -u USER, --user USER  Viya user name
    -p PASSWORD, --password PASSWORD
                            Viya user password
    -c CLIENT_ID_SECRET, --client_id_secret CLIENT_ID_SECRET
                            Client ID and Client Secret in format <client_id>:<client_secret>
    --access-token-auth, -a
                            Provide this option if you have authentication token.
                            It must be located in token.txt in the working
                            directory.
    --really-delete       a.k.a. Production mode (objects are going to be deleted)
    --decisions-only      Delete decisions only
    --input-file INPUT_FILE
                            Path to package JSON file
    ```

    Example:

    ```bash
    python3.6 uri_deletion_util.py --hostname https://sasserver.demo.sas.com -u sasboot -p Orion123 -c sas.ec: --input-file ./data/Decision_1.json --really-delete
    ```

## Utility for retrieval list of global variables and their values

This utility grabs the list of global variables and their values (which are activated at the moment) via SAS Viya REST API. It is taken from `sid_global_variable_container` MAS module source code.

How to use:

1. Navigate to directory where `get_global_vars.py` resides
1. Run utility with necessary options provided

    Here is the help:

    ```bash
    usage: get_global_vars.py [-h] --hostname HOSTNAME [-u USER] [-p PASSWORD]
                          [-c CLIENT_ID_SECRET] [--access-token-auth]

    Utility for getting source code of sid_global_variable_container using REST
    API

    optional arguments:
    -h, --help            show this help message and exit
    --hostname HOSTNAME   Viya hostname in format http(s)://server-name.com
    -u USER, --user USER  Viya user name
    -p PASSWORD, --password PASSWORD
                            Viya user password
    -c CLIENT_ID_SECRET, --client-id-secret CLIENT_ID_SECRET
                            Client ID and Client Secret in format
                            <client_id>:<client_secret>
    --access-token-auth, -a
                            Provide this option if you have authentication token.
                            It must be located in token.txt in the working
                            directory.
    ```

    Example (with already retrieved token saved to `token.txt`):

    ```bash
    python3.6 get_global_vars.py --hostname https://sasserver.demo.sas.com -a
    ```

    Name of output file is printed in command output.

## Utility for retrieval of dependent object URIs of decision

This utility grabs the list of dependent objects of decision, which can be used further for creating export package.

> Required Python 3.9+

How to use:

1. Navigate to directory where `get_dependent_objects.py` resides
1. Run utility with necessary options provided

    Here is the help:

    ```text
    usage: get_dependent_objects.py [-h] --hostname HOSTNAME [-u USER] [-p PASSWORD] [-c CLIENT_ID_SECRET] [--access-token-auth] --decision-uri DECISION_URI --major-version MAJOR_VERSION --minor-version MINOR_VERSION

    Utility for getting dependent objects for decision using REST API

    options:
    -h, --help            show this help message and exit
    --hostname HOSTNAME   Viya hostname in format http(s)://server-name.com
    -u USER, --user USER  Viya user name
    -p PASSWORD, --password PASSWORD
                            Viya user password
    -c CLIENT_ID_SECRET, --client-id-secret CLIENT_ID_SECRET
                            Client ID and Client Secret in format <client_id>:<client_secret>
    --access-token-auth, -a
                            Provide this option if you have authentication token. It must be located in token.txt in the working directory.
    --decision-uri DECISION_URI
                            URI to decision
    --major-version MAJOR_VERSION
                            Major version
    --minor-version MINOR_VERSION
                            Minor version
    ```

    Example (with already retrieved token saved to `token.txt`):

    ```bash
    python3 get_dependent_objects.py --hostname https://sasserver.demo.sas.com -a --decision-uri /decisions/flows/26d9b2a8-a7be-4c9a-9af5-cd9e77cefcaf --major-version 1 --minor-version 0
    ```

    Name of output file is printed in command output.

## Logging

Logs are written to work directory in `logs` subfolder.
