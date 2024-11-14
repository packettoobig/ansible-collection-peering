#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#  Heavily inspired from https://github.com/renatoalmeidaoliveira/netero/tree/master/plugins/modules/peeringdb_getasn.py
#  Stole the fix from https://gitlab.xs4me.net/jorg/netero/-/commit/129209c5302b81fe16c1887508f8e56b7a88bc73
#  Modified for API key support
#  Huge thanks to Renato Almeida de Oliveira for the base
#  Huge thanks to Dano Hodovic for the retry code snippets : https://findwork.dev/blog/advanced-usage-python-requests-timeouts-retries-hooks/#retry-on-failure

import requests
import urllib3
import json

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
module: peeringdb_getasn

short_description: Searches for ASN policies and interfaces

version_added: "2.0.0"

description:
    - "This modules encapsules peeringDB API to search for an specific ASN interfaces and policy information"

options:
    asn_list:
        description:
          - "The searched list of ASNs"
        required: true
    api_key:
        description:
          - "Your peeringDB API key"
        required: true
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
- name: Search ASN 64497,65500
  peeringdb_getasn:
    asn_list:
      - 64497
      - 65500
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
retry_strategy = urllib3.util.Retry(
    total=10, # Default 10
    backoff_factor=0.2, # Default 0
    allowed_methods=["HEAD", "GET", "OPTIONS"],
    status_forcelist=[413, 429, 500, 502, 503, 504]
)
http = requests.Session()
http.mount("https://", requests.adapters.HTTPAdapter(max_retries=retry_strategy))

def getASNData(asn_list, api_key=None):
    if len(asn_list) > 150:
        raise NameError("Maximum 150 objects in a single request,\
            see https://docs.peeringdb.com/howto/work_within_peeringdbs_query_limits/")

    if (api_key is not None):
        headers = {
            "Authorization": "Api-Key " + api_key,
            "User-Agent": "Ansible module: packettoobig.peering.peeringdb_getasn"
        }
    else:
        raise NameError("Please provide an API key or you will hit the rate limits,\
            see https://docs.peeringdb.com/howto/work_within_peeringdbs_query_limits/")
    request = http.get("https://www.peeringdb.com/api/net?depth=2&asn__in=" + ','.join(map(str, asn_list)), headers=headers)
    request.raise_for_status()
    response = json.loads(request.text)
    data_objects = response.get("data", [])
    if len(data_objects) != len(asn_list):
        raise NameError("No data for one or more ASN IDs in the request.")
    return data_objects

def parseSingularASNData(asn, data, ixId=None, ixName=None):
    netfields = ["name",
              "info_prefixes4",
              "info_prefixes6",
              "poc_set",
              "info_unicast",
              "info_ipv6"]

    ixfields = ["name",
                "ix_id",
                "ipaddr4",
                "ipaddr6",
                "speed",
                "bfd_support",
                "is_rs_peer"
                ]

    output = {}
    ixOutput = []
    irrData = []
    output["asn"] = asn
    for key in netfields:
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
                if str(ix[ixFilter]) == str(inputIxData):
                    if "operational" in ix and ix["operational"]:
                        for key in ixfields:
                            if key in ix:
                                interfaceData[key] = ix[key]
                    ixOutput.append(interfaceData)
    if ixOutput != []:
        output["interfaces"] = ixOutput
    output["irr_as_set"] = irrData
    return output

def parseAllASNDataAtOnce(asn_list, api_key=None, ixId=None, ixName=None):
    data_objects = getASNData(asn_list, api_key)
    # Need to sort data_objects similarly to asn_list
    sorted_data_objects = sorted(data_objects, key=lambda data: asn_list.index(data["asn"]))
    # Pair up the asn_list and the sorted data objects
    paired_data = zip(asn_list, sorted_data_objects)
    # Process the paired data
    res = [parseSingularASNData(pair[0], pair[1], ixId, ixName) for pair in paired_data]
    return res

def main():
    fields = {
        "asn_list": {"required": True,  "type": "list", "elements": "int"},
        "api_key":  {"required": True, "type": "str", "no_log": True},
        "ix_id":     {"required": False, "type": "int"},
        "ix_name":   {"required": False, "type": "str"}
    }
    module = AnsibleModule(argument_spec=fields)
    response = parseAllASNDataAtOnce(module.params['asn_list'], module.params['api_key'],
                             str(module.params['ix_id']), str(module.params['ix_name']))
    module.exit_json(changed=False, message=response)

if __name__ == '__main__':
    main()