#! /usr/bin/env python3
#  Heavily inspired from https://github.com/renatoalmeidaoliveira/netero/tree/master/plugins/modules/peeringdb_getasn.py
#  Stole the fix from https://gitlab.xs4me.net/jorg/netero/-/commit/129209c5302b81fe16c1887508f8e56b7a88bc73
#  Modified for API key support
#  Huge thanks to Renato Almeida de Oliveira for the base
#  Huge thanks to Dano Hodovic for the retry code snippets : https://findwork.dev/blog/advanced-usage-python-requests-timeouts-retries-hooks/#retry-on-failure

import requests
import urllib3
import json

from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {
    'metadata_version': '1.0.1',
    'status': ['preview'],
    'supported_by': 'community'
}
DOCUMENTATION = '''
module: peeringdb_getasn

short_description: Searches for an ASN policy and interfaces

version_added: "0.0.1"

description:
    - "This modules encapsules peeringDB API to search for an specific ASN his interfaces and policy information"

options:
    asn:
        description:
          - "The searched ASN"
        required: true
    api_key:
        description:
          - "Your peeringDB API key"
        required: false
    ix_id:
        description:
          - "The peeringDB IXP ID"
        required: false
    ix_name:
        description:
          - "The peerigDB IXP Name"
        required: false
'''

EXAMPLES = '''
- name: Search ASN 64497
  peeringdb_getasn:
    asn: 64497
    ix_id: 70
'''

RETURN = '''
object:
    description: object representing ASN data
    returned: success
    type: dict
'''

# Implement retries and backoff because of the peeringdb ratelimiting
# Documentation here : https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html
class CustomRetry(urllib3.util.Retry) :
    DEFAULT_MAX_BACKOFF=30 # Default 120

retry_strategy = CustomRetry(
    total=100, # Default 10
    backoff_factor=0.05, # Default 0
    allowed_methods=["HEAD", "GET", "OPTIONS"],
    status_forcelist=[413, 429, 500, 502, 503, 504]
)
http = requests.Session()
http.mount("https://", requests.adapters.HTTPAdapter(max_retries=retry_strategy))

def getASNID(asn, api_key=None):
    if (api_key is not None):
        headers = {"AUTHORIZATION": "Api-Key " + api_key}
        request = http.get("https://www.peeringdb.com/api/net?asn=" + str(asn),
                               headers=headers)
    else:
        request = http.get(
            "https://www.peeringdb.com/api/net?asn=" + str(asn))

    request.raise_for_status()
    response = json.loads(request.text)
    result = None
    for data in response["data"]:
        if data["asn"] == int(asn):
            result = data["id"]
            break
    if result is not None:
        return result
    else:
        raise NameError('Unknown ASN')


def getASNData(asn, api_key=None):

    asnId = getASNID(asn)

    if (api_key is not None):
        asnId = getASNID(asn, api_key)
        headers = {"AUTHORIZATION": "Api-Key " + api_key}
        request = http.get("https://www.peeringdb.com/api/net/" + str(asnId),
                               headers=headers)
    else:
        asnId = getASNID(asn)
        request = http.get(
            "https://www.peeringdb.com/api/net/" + str(asnId))

    request.raise_for_status()
    response = json.loads(request.text)
    return response["data"][0]


def parseASNData(asn, api_key=None, ixId=None, ixName=None):
    keys = ["info_prefixes4", "info_prefixes6",
            "poc_set", "info_unicast", "info_ipv6"]
    data = getASNData(asn, api_key)
    output = {}
    ixOutput = []
    irrData = []
    output["asn"] = asn
    for key in keys:
        if key in data:
            output[key] = data[key]
    if "irr_as_set" in data:
        if data["irr_as_set"] == "":
            irrData = []
        else:
            irrDataSet = data["irr_as_set"].split(" ")
            for irrAsSet in irrDataSet:
                irrRepoSet = irrAsSet.rsplit('(AS[-:A-Z0-9]+)')
                if len(irrRepoSet) == 1:
                    irrData.append(irrRepoSet[0])
                else:
                    irrData.append(irrRepoSet[1])
    if "netixlan_set" in data:
        ixFilter = None
        if ixName is not None:
            ixFilter = "name"
        if ixId is not None:
            ixFilter = "ix_id"
        inputIxData = ixId or ixName
        if ixFilter is not None:
            ixSet = data["netixlan_set"]
            ixOutput = []
            for ix in ixSet:
                interfaceData = {}
                if ix[ixFilter] == inputIxData:
                    if "operational" in ix and ix["operational"]:
                        if "ipaddr4" in ix:
                            interfaceData["ipaddr4"] = ix["ipaddr4"]
                        if "ipaddr6" in ix:
                            interfaceData["ipaddr6"] = ix["ipaddr6"]
                        if "speed" in ix:
                            interfaceData["speed"] = ix["speed"]
                    ixOutput.append(interfaceData)
    if ixOutput != []:
        output["interfaces"] = ixOutput
    output["irr_as_set"] = irrData
    return output


def main():

    fields = {
        "asn":       {"required": True,  "type": "int"},
        "api_key":  {"required": False, "type": "str", "no_log": True},
        "ix_id":     {"required": False, "type": "int"},
        "ix_name":   {"required": False, "type": "str"}
    }
    module = AnsibleModule(argument_spec=fields)
    response = parseASNData(module.params['asn'], module.params['api_key'],
                             module.params['ix_id'], module.params['ix_name'])
    module.exit_json(changed=False, message=response)


if __name__ == '__main__':
    main()
