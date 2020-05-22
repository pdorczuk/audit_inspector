from audit_inspector.platforms import kubernetes as kube
from audit_inspector.platforms import linux as lnx
from audit_inspector.common import functions
from audit_inspector.common import settings
import re

control = 'connection'

def linux(text):
    """
    Check Linux (Debian, RHEL) SSH configuration.

    Parameters:
    text: 
    
    Output: <Platform>:<string>, <Hostname>:<string>, <Date>:<datetime>, <Protocol>:<string>, <Version>:<float>,
    <Cipher>:<string>, <Available Ciphers>:<list>, <Credential Methods>:<list>, <Idle Timeout>:<int>, <Issues/Notes>:<list>}
    """
    l = lnx.linux(text) # Instantiate the linux class that processes the evidence
    data = run_tests(l.connectionDetails)
    data['Control'] = control
    if checks(data) : data['Notes'] = checks(data) # This function calls all the specific check functions
    return data


def kubernetes(text):
    """
    Output: <Platform>:<string>, <Hostname>:<string>, <Date>:<datetime>, <Protocol>:<string>, <Version>:<float>,
    <Cipher>:<string>, <Available Ciphers>:<list>, <Credential Methods>:<list>, <Idle Timeout>:<int>, <Issues/Notes>:<list>}
    """
    k = kube.kubernetes(text) # Instantiate the kubernetes class that processes the evidence
    data = run_tests(k.connectionDetails)
    data['Control'] = control
    if checks(data) : data['Notes'] = checks(data) # This function calls all the specific check functions
    return data

def run_tests(class_method):
    data = class_method
    data['Control'] = control
    if checks(data) : data['Notes'] = checks(data) # This function calls all the specific check functions
    return data


def checks(class_method):
    data = class_method
    data['Control'] = control
    findings = []
    if check_ssh_idle_timeout(data) : findings.append(check_ssh_idle_timeout(data))
    if check_insecure_ciphers(data) : findings.append(check_insecure_ciphers(data))
    if check_ssh_root_login(data) : findings.append(check_ssh_root_login(data))
    return findings


def check_ssh_idle_timeout(data): # Called by checks() function
    pci_controls = ['8.1.8']
    duration = ''
    remediation = ''
    text = f"FINDING$$Idle timeout is {duration}.$$PCI Requirement(s) {', '.join(pci_controls)} states that sessions idle for more than 15 minutes must require the user to re-authenticate to re-activate the terminal or session. This can be remediated by adjusting the clientaliveinterval (in seconds) and the clientalivecountmax (multiplier) to a combination equal to or less than 900."
    
    if 'ssh'.lower() == data['Protocol'].lower():
        if data['Idle Timeout'] == 0:
            duration = 'not configured'
            return text
        elif data['Idle Timeout'] > 900:
            duration = 'greater than 15 minutes'
            return text
        

def check_insecure_ciphers(data): # Called by checks() function
    pci_controls = ['2.3.b', '8.2', '8.5']

    for k,v in settings.insecure_ciphers.items():
        if k.lower() in data['Protocol'].lower():
            for cipher in v:
                if (re.search(rf"{cipher}:", str(data['Available Ciphers']))) or (cipher in data['Available Ciphers']): 
                    if 'ssh'.lower() == data['Protocol'].lower():
                        return f"FINDING$$Weak SSH ciphers are enabled.$$PCI Requirement(s) {', '.join(pci_controls)} states that insecure remote-login commands not be available for remote access. RC4 encryption is steadily weakening in cryptographic strength and IETF document RFC4253 notes the deprecation of the RC4 ciphers. This can be remediated by explicitly denying weak ciphers 'Ciphers -arcfour*' in the SSHD configuration file."
                    if 'tls'.lower() == data['Protocol'].lower():
                        return f"FINDING$$TLS version 1.0 is enabled.$$PCI DSS states that after June 30, 2018, all entities must have stopped use of SSL/early TLS as a security control, and use only secure versions of the protocol."


def check_ssh_root_login(data):
    pci_controls = ['8.2', '8.5']
    method = ''
    credentialStore = ''
    finding = f"FINDING$$Login as root is enabled using {method}.$$PCI Requirement(s) {', '.join(pci_controls)} prohibit generic or shared login accounts. Please provide evidence of how usage of the {credentialStore} for the root user can be traced back to an individual user."

    if 'ssh'.lower() == data['Protocol'].lower():
        if ('without-password' in data['Root Login']) or ('forced-commands-only' in data['Root Login']):
            method = 'SSH keys'
            credentialStore = 'SSH key'
            return finding
        if 'yes' in data['Root Login']:
            method = 'a password'
            credentialStore = 'password'
            return finding

