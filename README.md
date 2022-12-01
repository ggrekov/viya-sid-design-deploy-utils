# Utility for deletion objects from package

This utility is suggested to be used as preparatory step for importing the package with design objects of SAS Intelligent Decisioning.  
It grabs the list of URIs from package .json file and delete them one-by-one via SAS Viya REST API.  

> **Problem description:**  
> SAS ID decisions consist of bunch of objects such as subdecisions, rule sets, code files and others. In order to move the whole implementation from one environment to another properly, all objects must be included into the package. The unique identifier of the object **across all environments** is URI.  
> When user imports the package (via SAS Environment Manager or `sas-admin` CLI), the system attempts to overwrite these objects by URI. And sometimes this process is failed. For example, if the object's location was changed. Also there are other reasons, which are not clearly identified.  
> The workaround is - delete all objects going to be imported from target environments, and then try to import again. There could be dozens/hundreds/thousands of objects, and there is no OOTB utility for bulk delete. This utility automates this process.

## Prerequisites

1. Python 3.6+
1. External package `requests`
1. Network connection to destination Viya environment

## How to install

1. Put `uri_deletion_util.py` at some place on server

## How to use

1. Put package JSON file exported from target Viya environment at some place on server
2. Navigate to directory where `uri_deletion_util.py` resides
3. Run utility with necessary options provided

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
    --really-delete       a.k.a. Production mode (objects are going to be deleted)
    --decisions-only      Delete decisions only
    --input-file INPUT_FILE
                            Path to package JSON file
    ```

    Example:

    ```bash
    python3.6 uri_deletion_util.py --hostname https://sasserver.demo.sas.com -u sasboot -p Orion123 -c sas.ec: --input-file ./data/Decision_1.json --really-delete
    ```

    Logs are written to work directory in `logs` subfolder.
