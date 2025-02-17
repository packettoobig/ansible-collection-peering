#!/usr/bin/python3
# -*- coding: utf-8 -*-

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
    - "This modules runs bgpq4 to generate model based prefix-list"

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
            - Max bgpq4 recursion depth (bgpq4 "-L" option)
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
            - "host running IRRD software, bgpq4 default is rr.ntt.net"
        required: false
        default: rr.ntt.net
    sources:
        description:
            - "Data sources"
        required: false
        default: "RPKI,RIPE,APNIC,ARIN,RADB"
    allow_priv_asn:
        description:
            - "Do not error-out if there is a private or martian ASN in the AS-SET"
            - "This is the equivalent of bgpq4 -p option (introduced in 1.15)"
        required: false
        default: False
requirements:
    - bgpq4 >= 1.8
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
    if module.params["allow_priv_asn"]:
        args = args + "p"
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

    # Error handling for bgpq4 command
    if rc != 0:
            raise AnsibleError("bgpq4 command failed with exit code %s. Command used: %s. The error is: %s" % (rc, cmd, to_native(stderr)))
    if not stdout:
        raise AnsibleError("bgpq4 returned an empty output. Command used: %s" % cmd)
    # Trigger only a warning if bgpq4 return code is zero but stderr exists
    if stderr != "":
        # Special warning for invalid AS number in AS-SET (see related allow_priv_asn option)
        stderr_lines=(to_native(stderr).splitlines())
        if stderr_lines and all("Invalid AS number" in line for line in stderr_lines):
            module.warn("bgpq4 encountered one or more invalid AS in %s AS-SET." % module.params["ASN"])
        # Generic warning
        else:
            module.warn("bgpq4 warning: %s" % to_native(stderr))

    try:
        data = json.loads(stdout)
    # Error handling for JSON data decode with multiple verbosities
    except json.JSONDecodeError as e:
        if module._verbosity >= 1:
            raise AnsibleError("Failed to parse JSON output from bgpq4: %s. Output: %s" % (to_native(e), stdout))
        else:
            raise AnsibleError("Failed to parse JSON output from bgpq4")
    if "irr_prefix" not in data:
        if module._verbosity >= 1:
            raise AnsibleError("JSON output did not contain expected 'irr_prefix' key. Output: %s" % stdout)
        else:
            raise AnsibleError("JSON output did not contain expected 'irr_prefix' key.")

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
        "limit_length":         {"default": True, "type": "bool"},
        "ASN":                  {"required": True, "type": "str"},
        "AS_SET":               {"required": False, "type": "str"},
        "irrd_host":            {"default": 'rr.ntt.net', "required": False, "type": "str"},
        "sources":              {"default": "RPKI,RIPE,APNIC,ARIN,RADB", "required": False, "type": "str"},
        "allow_priv_asn":       {"default": False, "type": "bool"}

    }
    module = AnsibleModule(argument_spec=fields)
    result = dict(changed=False, warnings=list())
    try:
        path = module.get_bin_path('bgpq4', required=True)
        response = bgpq4Query(module, path)
        result.update(changed=True, message=response)
    except Exception as e:
        module.fail_json(msg="Error: %s" % to_native(e))
    module.exit_json(**result)


if __name__ == '__main__':
    main()
