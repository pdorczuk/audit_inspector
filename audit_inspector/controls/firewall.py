from audit_inspector.platforms import kubernetes as kube
from audit_inspector.common.functions import traverse
#from audit_inspector.common.checks import pci_1_1_4

def kubernetes(text):
    k = kube.kubernetes(text) # Instantiate the kubernetes class that processes the evidence
    """
    TODO figure out how I can create a central testing file. This will likely include making standard variable names
    that are consistent across platforms so I can pass them into the central function. So determine the variable in
    each platform file and pass those consistent variables into the check.
    Here is the common outputs I'm working towards:
    {<Interface>: {<Direction>:, <Source/Destination>:, <Ports>:}
    """
    pass
    '''
    interface= []
    for podInfo in k.pods:
        d = {'interface':podInfo['name']} # Pod is the interface in K8s so always to list out all pods
        for netpolInfo in k.firewall: # Check network policies 
            for podLabel in podInfo['labels']:
                for netpolLabel in netpolInfo['interface']:
                    if 'L:' in netpolLabel:
                        if podLabel in netpolLabel:
                            d['direction'] = 'inbound'
                    elif 'N:' in netpolLabel:
                        if podInfo['namespace'] in netpolLabel:
                            d['direction'] = 'inbound'
                if 'ingress_from' in netpolInfo:
                    for ingress in netpolInfo['ingress_from']:
                        if ingress.split(':')[0] in podLabel:
                            d['source'] = podInfo['name']
                        elif '!' == ingress:
                            d['source'] = '!'
                        else:
                            d['source'] = ingress
                if 'egress_to' in netpolInfo:
                    for egress in netpolInfo['egress_to']:
                        if egress.split(':')[0] in podLabel:
                            d['destination'] = podInfo['name']
                        elif '!' == egress:
                            d['destination'] = '!'
                        else:
                            d['destination'] = egress
        interface.append(d)

    for i in interface:
        print(i)
    '''