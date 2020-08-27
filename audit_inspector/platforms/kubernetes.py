from collections import defaultdict
import json
import itertools
import re
from plucky import pluck, plucks, pluckable, merge # TODO remove the specific imports not needed
from audit_inspector.common import functions
from dateutil import parser
import simplejson as json
import ipaddress
from collections import abc


class kubernetes():

    def __init__(self, text):

        # TEXT PROCESSING VARIABLES
        ###############################################################################################################
        section_regxp = re.compile(r'(?<=\+\s)?(?P<command>.*)\n(?P<output>[\s\S]*?)\+\s')
        command_regx = re.search(section_regxp, text).group('command')
        output_regx = re.search(section_regxp, text).group('output').replace('\n\n', '\n')
        ###############################################################################################################

        # EVIDENCE VARIABLES
        ###############################################################################################################
        date = '' # This needs to be included with any information returned by the class
        hostname = '' # Not all Kube output will include 'config view' so there are multiple methods to find hostname
        platform = 'Kubernetes'
        connectionDetails = {}
        connectionDetails['Available Ciphers'] = []
        ###############################################################################################################
        for section in re.finditer(section_regxp, text):
            if 'date' in section.group('command'):
                date = functions.get_evidence_date(section.group('output'))

            if 'config view' in section.group('command'):
                for line in section.group('output').split('\n'):
                    if 'server:' in line:
                        hostname = line.split()[1]

            if 'get pods' in section.group('command'):
                def get_pod_info():
                    """
                    Collect and return Kubernetes pod information as a list of dictionaries with the following information:
                    {<POD_NAME>:, <NAMESPACE>:, <LABELS>:} Likely to add <IMAGE>:, <RESOURCE_LIMITS>:
                    Kubernetes returns a very complicated json object with nested dictionaries, lists, etc. So Plucky
                    is used to simplify data retrieval.
                    """
                    pod_info = []
                    for entry in functions.section_text_to_json(section):
                        d = {}
                        # <POD_NAME>
                        d['name'] = plucks(entry, 'metadata.name')
                        # <NAMESPACE>
                        d['namespace'] = plucks(entry, 'metadata.namespace')
                        # <LABELS>
                        labels = []
                        if plucks(entry, 'metadata.labels'):
                            for label in functions.traverse(plucks(entry, 'metadata.labels')):
                                labels.append(f"{label[0]}={label[1]}")
                        else:
                            labels.append('!')
                        d['labels'] = labels
                        # <IMAGE>
                        d['image'] = plucks(entry, 'spec.containers.image')
                        # <RESOURCE_LIMITS>
                        limits = []
                        if plucks(entry, 'spec.containers.resources.limits'):
                            for limit in plucks(entry, 'spec.containers.resources.limits'):
                                for k,v in limit.items():
                                    limits.append(f'{k}={v}')
                        else:
                            limits = '*:*'
                        d['limits'] = limits
                        pod_info.append(d)
                    return pod_info

                self.pods = get_pod_info()

            if 'get networkpolicy' in section.group('command'):
                def getFirewallInfo():
                    """
                    Collect and return Kubernetes Network Policy object information as a list of dictionaries.

                    Inputs: kubectl get networkpolicy -A -o json

                    Returns: {<NAME>:, <NAMESPACE>:, <ACTION>:, <SOURCE>:, <DEST>:, <PROTOCOL>:, <PORT>}
                    """
                    firewall_rules = [] # list to hold dictionaries of test results
                    for entry in functions.section_text_to_json(section):
                        # TODO figure out how to level this so I can use a common function in each if/else block
                        # If spec.ingress exists then the pod selector is the destination and the spec.ingress is the source
                        def build_acl_dict(entry, action, direction):
                            results = {}

                            # <ACL_NAME>
                            results.update({'name': plucks(entry, 'metadata.name')})
                            # <NAMESPACE>
                            results.update({'namespace': plucks(entry, 'metadata.namespace')})
                            # <ACTION>
                            results.update({'action': action})
                            # <PORTS>
                            ports = []
                            protocols = []
                            if plucks(entry, f"spec.{direction}.ports"):
                                for i in functions.traverse(plucks(entry, f"spec.{direction}.ports")):
                                    if 'protocol' in i:
                                        protocols.append(f"{i[1]}")
                                    if 'port' in i:
                                        ports.append(f"{i[1]}")
                            if ports:
                                results.update({'ports': ports})
                                results.update({'protocols': protocols})
                            if not ports:
                                results.update({'ports': '*'})
                                results.update({'protocols': '*'})
                            # <SOURCE>
                            if direction == 'ingress':
                                results.update({'source': k8s_selectors(plucks(entry, 'spec.ingress.from'))})
                                # <DESTINATION>
                                if plucks(entry, 'spec.podSelector'): # an empty pod selector allows all in the NS
                                    results.update({'destination': k8s_selectors(plucks(entry, 'spec.podSelector'))})
                                else:
                                    results.update({'destination': '*'})
                            if direction == 'egress':
                                # <SOURCE>
                                if plucks(entry, 'spec.podSelector'): # an empty pod selector allows all in the NS
                                    results.update({'source': k8s_selectors(plucks(entry, 'spec.podSelector'))})
                                else:
                                    results.update({'source': '*'})
                                # <DESTINATION>
                                results.update({'destination': k8s_selectors(plucks(entry, 'spec.egress.to'))})
                            return results

                        if 'Ingress' in plucks(entry, 'spec.policyTypes'):
                            if plucks(entry, 'spec.ingress'): # allow
                                firewall_rules.append(build_acl_dict(entry, 'allow', 'ingress'))
                            else: # If spec.ingress is missing then no traffic is allowed to the podSelector target
                                firewall_rules.append(build_acl_dict(entry, 'deny', 'ingress'))

                        # If spec.egress exists then the pod selector is the source and the spec.egress is the destination
                        if 'Egress' in plucks(entry, 'spec.policyTypes'):
                            if plucks(entry, 'spec.egress'): # allow
                                firewall_rules.append(build_acl_dict(entry, 'allow', 'egress'))
                            else: # empty or missing egress target blocks all egress traffic
                                firewall_rules.append(build_acl_dict(entry, 'deny', 'egress'))
                    return firewall_rules

                self.firewall = getFirewallInfo()

            if 'get service' in section.group('command'):
                def get_services():
                    """
                    Collect and return Kubernetes Service object information as a nested dictionary with the
                    following information:
                    {<SERVICE NAME>: {<NAMESPACE>, <TYPE>, <LABELS>, <IP>, <PORTS>}}
                    Kubernetes returns a very complicated json object with nested dictionaries, lists, etc. So Plucky
                    is used to simplify data retrieval.
                    """
                    # TODO the service info hasnt been vetted very well. go through and make sure its grabbing everything

                    service_info = defaultdict(dict)
                    for entry in functions.section_text_to_json(section):
                        service_name = plucks(entry, 'metadata.name')
                        # <NAMESPACE>
                        service_info[service_name]['namespace'] = plucks(entry, 'metadata.namespace')
                        # <TYPE>
                        service_info[service_name]['type'] = plucks(entry, 'spec.type')
                        # <LABELS>
                        labels = []
                        if plucks(entry, 'spec.selector'):
                            for label in functions.traverse(plucks(entry, 'spec.selector')):
                                labels.append(f"{label[0]}={label[1]}")
                        else:
                            labels.append('!*=!*')
                        service_info[service_name]['labels'] = labels
                        # <IP>
                        if plucks(entry, 'status.loadBalancer.ingress.ip'):
                            service_info[service_name]['ip'] = ''.join(plucks(entry, 'status.loadBalancer.ingress.ip'))
                        # <PORTS>
                        if str(plucks(entry, 'spec.ports.port')):
                            service_info[service_name]['ports'] = ''.join(str(plucks(entry, 'spec.ports.port')))
                    return service_info
                self.services = get_services()

            if 'get namespace' in section.group('command'):
                def get_namespaces():
                    """
                    Collect and return Kubernetes Namespace object information as a nested dictionary with the
                    following information:
                    {<NAMESPACE_NAME>: {<LABELS>;,}}
                    Kubernetes returns a very complicated json object with nested dictionaries, lists, etc. So Plucky
                    is used to simplify data retrieval.
                    """
                    namespace_info = defaultdict(dict)
                    for entry in functions.section_text_to_json(section):
                        namespace_name = plucks(entry, 'metadata.name')
                        # <LABELS>
                        labels = []
                        if plucks(entry, 'metadata.labels'):
                            for label in functions.traverse(plucks(entry, 'metadata.labels')):
                                labels.append(f"{label[0]}={label[1]}")
                        else:
                            labels.append('!*=!*')
                        namespace_info[namespace_name]['labels'] = labels
                    return namespace_info
                self.namespaces = get_namespaces()

            # Process OpenSSL s_client output
            ###############################################################################################################
            if 'openssl s_client' in section.group('command'):
                connectionDetails.update(functions.process_openssl_output(connectionDetails, platform, date, section.group('output'), section.group('command')))
        self.connectionDetails = connectionDetails

def k8s_selectors(json):
    """
    Options for ingresses include CIDR/except, labels, and namespace. This function checks for all
    of those and returns the results.

    Returns: List of the results with possible formats CIDR:<value>, LABEL:<value>, NAMESPACE:<value>
    """
    # TODO figure out how to fold this into functions.traverse. Need a way to notate whether its a namespace Selector, podselector, cidr, etc.
    selectors = [] # there may be multiple ingress options so hold them here
    if json:
        # The JSON is usually a nested dict in a list so this section iterates through that to get to the data.
        ###############################################################################################################
        if isinstance(json, list):
            for item in itertools.chain.from_iterable(json):
                if isinstance(item, dict):
                    for key in item:
        ###############################################################################################################
                        # TODO there is no port search in here. figure out how to return open ports
                        if 'ipBlock' == key: # CIDR selector
                            cidr = ''
                            less = ''
                            for value in functions.traverse(item[key]):
                                if 'cidr' in value:
                                    cidr = ipaddress.IPv4Network(value[1])
                                if 'except' in value: # CIDR minus exception
                                    less = [ipaddress.IPv4Network(item) for item in value[1]]


                            if less:
                                # Remove the exception subnets from the supernet and return a set of the results.
                                ###################################################################################
                                resultant_cidrs = []
                                for item in less:
                                    resultant_cidrs.extend(list(cidr.address_exclude(item)))

                                for i in set(resultant_cidrs):
                                    selectors.append('CIDR:' + str(i))
                                ###################################################################################
                            else:
                                selectors.append('CIDR:' + str(cidr))
                        if 'namespaceSelector' == key: # namespace label selector
                            for value in functions.traverse(item[key]):
                                selectors.append(f"NSLABEL:{value[0]}={value[1]}")
                        if 'podSelector' == key:
                            for value in functions.traverse(item[key]):
                                selectors.append(f"PODLABEL:{value[0]}={value[1]}")
        elif isinstance(json, abc.Mapping): # Only podSelectors will be in this format and always use matchLabel
            for key in json:
                for value in functions.traverse(json[key]):
                    selectors.append(f"PODLABEL:{value[0]}={value[1]}")
    else:
        selectors.append('*') # An empty selector selects everything.
    return selectors
