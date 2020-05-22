from collections import defaultdict
import json
import itertools
import re
from plucky import pluck, plucks, pluckable, merge # TODO remove the specific imports not needed
from audit_inspector.common import functions
from dateutil import parser


class kubernetes():
    
    def __init__(self, text):
        
        # TEXT PROCESSING VARIABLES
        ###############################################################################################################
        section_regxp = re.compile(r'(?<=\+\s)?(?P<command>.*)\n(?P<output>[\s\S]*?)\+\s')
        command_regx = re.search(section_regxp, text).group('command')
        output_regx = re.search(section_regxp, text).group('output')
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
                    {<POD_NAME>:, <NAMESPACE>:, <LABELS>:, <IMAGE>:, <RESOURCE_LIMITS>:}
                    Kubernetes returns a very complicated json object with nested dictionaries, lists, etc. So Plucky
                    is used to simplify data retrieval.
                    """
                    pods = []
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
                                labels.append(label)
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
                        pods.append(d)
                    return pods

                self.pods = get_pod_info()

            if 'get networkpolicy' in section.group('command'):
                def getFirewallInfo():
                    """
                    Collect and return Kubernetes Network Policy object information as a list of dictionaries with the
                    following information:
                    {<ACL_NAME>:, <INTERFACE>:, <INGRESS_FROM/EGRESS_TO>:, <PORTS>:}
                    Kubernetes returns a very complicated json object with nested dictionaries, lists, etc. So Plucky
                    is used to simplify data retrieval.
                    """
                    firewall = []
                    for entry in functions.section_text_to_json(section):
                        d = {}
                        # <ACL_NAME>
                        d['aclName'] = plucks(entry, 'metadata.name')
                        # <INTERFACE>
                        pod_selector = []
                        if plucks(entry, 'spec.podSelector.matchLabels'): # There is always some kind of pod selector
                            for k,v in plucks(entry, 'spec.podSelector.matchLabels').items():
                                pod_selector.append(f"LABEL:{k}={v}")
                        else: # Empty podSelector selects all pods in namespace
                            pod_selector.append(f"NAMESPACE:{plucks(entry, 'metadata.namespace')}")
                        d['interface'] = pod_selector
                        # <INGRESS_FROM>
                        if 'Ingress' in plucks(entry, 'spec.policyTypes'):
                            ingress_from = []
                            if plucks(entry, 'spec.ingress.from'):
                                for ingress in functions.traverse(plucks(entry, 'spec.ingress.from')):
                                    # TODO figure out a cleaner way to add an IP and except in the same list item
                                    # TODO create a separate dict entry for ports rather than attached to the ingress/egress
                                    cidr = ''
                                    less = ''
                                    if 'cidr' in ingress:
                                        cidr = ingress
                                    if 'except' in ingress:
                                        less = ingress.split('=')[1]
                                        ingress_from.append(f'{cidr}:less{less}')
                                    if plucks(entry, 'spec.ingress.ports'):
                                        port, protocol = '', ''
                                        for ports in functions.traverse(plucks(entry, 'spec.ingress.ports')):
                                            if 'port' in ports:
                                                port = ports.split('=')[1]
                                            elif 'protocol' in ports:
                                                protocol = ports.split('=')[1]
                                        ingress_from.append(f'{ingress}:{protocol}{port}')
                                    else: # if no ports are specified, all ports are allowed
                                        ingress_from.append(f'{ingress}:*')
                            else: # If spec.ingress is empty no traffic is allowed
                                ingress_from.append('!')
                            d['ingress_from'] = ingress_from
                        # <EGRESS_TO>
                        if 'Egress' in (plucks(entry, 'spec.policyTypes')):
                            egress_to = []
                            if (plucks(entry, 'spec.egress.to')):
                                for egress in functions.traverse(plucks(entry, 'spec.egress.to')):
                                    if plucks(entry, 'spec.egress.ports'):
                                        port, protocol = '', ''
                                        for ports in functions.traverse(plucks(entry, 'spec.egress.ports')):
                                            for ports in functions.traverse(plucks(entry, 'spec.egress.ports')):
                                                if 'port' in ports:
                                                    port = ports.split('=')[1]
                                                elif 'protocol' in ports:
                                                    protocol = ports.split('=')[1]
                                        egress_to.append(f'{egress}:{protocol}{port}')
                                    else: # if no ports are specified, all ports are allowed
                                        egress_to.append(f'{egress}:*')
                            else: # If spec.egress is empty no traffic is allowed
                                egress_to.append(f'!')
                            d['egress_to'] = egress_to
                        firewall.append(d)
                    return firewall
                                               
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
                                labels.append(label)
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
                                labels.append(label)
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