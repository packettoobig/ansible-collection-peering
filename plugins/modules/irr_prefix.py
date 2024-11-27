#! /usr/bin/env python3
#  Heavily inspired from https://github.com/renatoalmeidaoliveira/netero/tree/master/plugins/modules/irr_prefix.py
#  Modified quite a lot
#  Huge thanks to Renato Almeida de Oliveira for the base

from ansible.errors import AnsibleError
from ansible.module_utils.basic import to_native, AnsibleModule
import json
ANSIBLE_METADATA = {
    'metadata_version': '1.0.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
module: irr_prefix

short_description: Generates IRR prefix-list

version_added: "0.0.1"

description:
    - "This modules runs bgpq3/4 to generate model based prefix-list"

options:
    IPv:
        description:
            - "IP protocol version"
        required: true
        choices: [ 4 , 6]
    aggregate:
        description:
            - "If true aggregate the prefix"
        required: false
        default: True
    max_depth:
        description:
            - Max bgpq3/4 recursion depth (bgpq3/4 "-L" option)
            - Unlimited by default
    limit_length:
        description:
            - "If true, limit IPv4 length to 24 and IPv6 length to 48"
        required: false
        default: True
    ASN:
        description:
            - "The ASN with format AS64496"
        required: true
    AS_SET:
        description:
            - "The AS-SET with format AS-NAME"
        required: false
    irrd_host:
        description:
            - "host running IRRD software, bgpq3 default is whois.radb.net, bgpq4 default is rr.ntt.net"
        required: false
        default: rr.ntt.net
    sources:
        description:
            - "Data sources"
        required: false
        default: "RPKI,RIPE,APNIC,ARIN,RADB"
requirements:
    - bgpq4 (or bgpq3)
'''

EXAMPLES = '''
- name: Get prefix-list
  irr_prefix:
    IPv: 4
    ASN: AS64496
'''

RETURN = '''
message:
  description: object containing the IRR prefixes
  returned: success
  type: dict
'''

def bgpq4Query(module, path):
    args = module.params["IPv"]
    if module.params["aggregate"]:
        args = args + "A"
    if module.params["max_depth"]:
        args = "%s -L %s" % (args, str(module.params["max_depth"]))
    if module.params["irrd_host"]:
        args = "%s -h %s" % (args, module.params["irrd_host"])
    if module.params["sources"]:
        args = "%s -S %s" % (args, module.params["sources"])
    if module.params["AS_SET"]:
        IRR_OBJECT = module.params["AS_SET"]
    else:
        IRR_OBJECT = module.params["ASN"]
    if module.params["limit_length"]:
        if module.params["IPv"] == '4':
            args = args + " -m 24"
        if module.params["IPv"] == '6':
            args = args + " -m 48"
    cmd = "%s -j%s -l irr_prefix %s" % (path, args, IRR_OBJECT)
    rc, stdout, stderr = module.run_command(cmd)
    if stderr != "":
        raise AnsibleError(" bgpq4 error: %s " % to_native(stderr))
    data = json.loads(stdout)
    fields = ['prefix', 'exact', 'less-equal', 'greater-equal']
    output = {"irrPrefix": []}
    for prefixData in data["irr_prefix"]:
        prefixObject = {}
        for field in fields:
            if field in prefixData:
                fieldName = field
                if field == "less-equal":
                    fieldName = "lessEqual"
                if field == "greater-equal":
                    fieldName = "greaterEqual"
                prefixObject[fieldName] = str(prefixData[field])
        output["irrPrefix"].append(prefixObject)
    return output


def main():

    fields = {

        "IPv":                  {"required": True, "type": "str", "choices": ['4', '6']},
        "aggregate":            {"default": True, "type": "bool"},
        "max_depth":            {"required": False, "type": "str"},
        "limit_length":         {"default": True, "type": "int"},
        "ASN":                  {"required": True, "type": "str"},
        "AS_SET":               {"required": False, "type": "str"},
        "irrd_host":            {"default": 'rr.ntt.net', "required": False, "type": "str"},
        "sources":              {"default": "RPKI,RIPE,APNIC,ARIN,RADB", "required": False, "type": "str"}

    }
    module = AnsibleModule(argument_spec=fields)
    result = dict(changed=False, warnings=list())
    try:
        path = module.get_bin_path('bgpq4', False) or module.get_bin_path('bgpq3', False)
        if path is None:
            raise AnsibleError("bgpq4 and bgpq3 not found")
        response = bgpq4Query(module, path)
        result.update(changed=True, message=response)
    except Exception as e:
        module.fail_json(msg=to_native(e))
    module.exit_json(**result)


if __name__ == '__main__':
    main()
