import json
from pathlib import Path
import re
import itertools
from collections import abc
from dateutil import parser
from audit_inspector.common.settings import control_categories, header_font, dark_blue_fill
from openpyxl.utils import get_column_letter


def get_evidence_date(datestring):
    """
    Parse the output of the 'date' command and return as a datetime object.
    """
    raw_date = parser.parse(datestring, ignoretz=True)
    evidence_date = raw_date.strftime('%m/%d/%Y')
    return evidence_date


def get_hostname(output):
    hostname = str(output.strip().lower())
    return hostname

    
def section_text_to_json(section):
    """
    Converts command output from text to YAML which can be parsed as a dictionary.
    """
    data = json.loads(section.group('output'))
    if data: # if there is some error in conversion, skip
        for k,v in data.items():
            for entry in v:
                if (isinstance(entry, dict)) and 'List' not in entry: # Kubernetes adds 
                    yield entry


def traverse(o):
    if isinstance(o, list):
        for item in itertools.chain.from_iterable(o):
            if isinstance(item, dict):
                yield from dict_keys(item)
    elif isinstance(o, dict):
        yield from dict_keys(o)
    else:
        yield item


def dict_keys(nested):
    for key, value in nested.items():
        if isinstance(value, abc.Mapping):
            yield from dict_keys(value)
        else:
            try:
                yield f"{key}={''.join(value)}"
            except TypeError:
                yield f"{key}={value}"


def process_openssl_output(connectionDetails, platform, date, section_text, section_command):
    """
    Parse OpenSSL s_client output and return relevant information.

    The command in requests.xlsx ends up returning multiple sections separated by a plus sign. This function returns them in the
                   
    Returns:
    {<Platform>:<string>, <Hostname>:<string>, <Date>:<datetime>, <Protocol>:<string>, <Version>:<float>, <Cipher>:<string>, <Available Ciphers>:<list>}
    """
    connectionDetails['Platform'] = platform
    connectionDetails['Hostname'] = re.search(r'-connect\s+(.*)\s+', section_command).group(1)
    connectionDetails['Date'] = date
    connectionDetails['Protocol'] = 'TLS'
                    
    for line in section_text.split('\n'): # Convert output string to a list of strings
        protocol = ''
        if re.search(r'Protocol\s+:', line): # This line contains the TLS version
            protocol = line.split(':')[1].strip()
            i = section_text.split('\n').index(line) # The next list item holds Cipher info so get index of the item
            if '0000' not in section_text.split('\n')[i+1]: # 0000 means no connection was made
                connectionDetails['Available Ciphers'].append("" + protocol + ':' + section_text.split('\n')[i+1].split(':')[1].strip() + "")

    version = float()
    for protocol in connectionDetails['Available Ciphers']:
        if float(protocol.split(':')[0].split('v')[1]) > version:
            connectionDetails['Version'] = protocol.split(':')[0].split('v')[1] # default is highest available
            connectionDetails['Cipher'] = protocol.split(':')[1]
    return connectionDetails