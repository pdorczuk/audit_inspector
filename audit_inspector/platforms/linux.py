import re
from audit_inspector.common import functions


class linux():
    
    def __init__(self, text):
        
        # TEXT PROCESSING VARIABLES
        ###############################################################################################################
        section_regxp = re.compile(r'(?<=\+\s)?(?P<command>.*)\n(?P<output>[\s\S]*?)\+\s')
        command_regx = re.search(section_regxp, text).group('command')
        output_regx = re.search(section_regxp, text).group('output')
        ###############################################################################################################

        # EVIDENCE VARIABLES
        ###############################################################################################################
        connectionDetails = {}
        date = '' # This needs to be included with any information returned by the class
        hostname = '' # This needs to be included with any information returned by the class
        platform = 'Linux'
        ###############################################################################################################
        
        for section in re.finditer(section_regxp, text):
            if 'hostname' in section.group('command'):
                hostname = functions.get_hostname(section.group('output'))
            
            if 'date' in section.group('command'):
                date = functions.get_evidence_date(section.group('output'))
            
            if ('OpenSSH_' in section.group('command')) or ('sshd -T' in section.group('command')):
                def getConnectionDetails():
                    """
                    Returns list of dictionaries with authentication connection details.
                    {<Platform>:<string>, <Hostname>:<string>, <Date>:<datetime>, <Protocol>:<string>, 
                    <Version>:<float>, <Cipher>:<string>, <Available Ciphers>:<list>, <Credential Methods>:<list>,
                    <Idle Timeout>:<int>, <Root Login>:<str>}
                    """
                    # <Platform>
                    connectionDetails['Platform'] = platform
                    # <Hostname>
                    connectionDetails['Hostname'] = hostname
                    # <Date>
                    connectionDetails['Date'] = date
                    # <Protocol>
                    if 'OpenSSH_' in section.group('command'):
                        connectionDetails['Protocol'] = 'SSH'
                        # <Version>
                        if 'SSH2' in section.group('output'):
                            connectionDetails['Version'] = 2
                        else:
                            connectionDetails['Version'] = 1
                        # <Cipher>
                        if 'kex: server->client' in section.group('output'):
                            connectionDetails['Cipher'] = re.search(r'kex: server->client cipher:\s([a-z].*)\sMAC', section.group('output')).group(1)
                    # <Available Ciphers>
                    if 'sshd -T' in section.group('command'):
                        connectionDetails['Available Ciphers'] = re.search(r'ciphers\s(.*)', section.group('output')).group(1).split(',')
                        # <Credential Methods>
                        def get_credential_method():
                            method = []
                            if 'pubkeyauthentication yes' in section.group('output'):
                                method.append('key')
                            elif 'passwordauthentication yes' in section.group('output'):
                                method.append('password')
                            return method
                        connectionDetails['Credential Methods'] = get_credential_method()
                        # <Idle Timeout>
                        def get_idle_timeout():
                            interval = int(re.search(r'clientaliveinterval\s(\d+)', section.group('output')).group(1))
                            multiplier = int(re.search(r'clientalivecountmax\s(\d+)', section.group('output')).group(1))
                            return interval * multiplier # timeout is calculated by interval (in seconds) * count
                        connectionDetails['Idle Timeout'] = int(get_idle_timeout())
                        if 'permitrootlogin' in section.group('output'):
                            connectionDetails['Root Login'] = re.search(r'permitrootlogin\s(.*)', section.group('output')).group(1)
                getConnectionDetails()
        self.connectionDetails = connectionDetails