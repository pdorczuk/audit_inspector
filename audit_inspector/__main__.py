import sys
from tkinter import Tk, messagebox
from tkinter.filedialog import askdirectory
import os
from pathlib import Path
from audit_inspector.common import functions, settings
from audit_inspector.controls import connection, authorization, firewall, logging, patching
from jinja2 import Environment, PackageLoader, FileSystemLoader
from audit_inspector import controls


def main():
    results = [] # Holds control function returns from mulitple files.
    #template_name = ''
    evidence_dir = set_evidence_dir()
    for text in read_files(evidence_dir):
        results.extend(call_control_function(text))


def set_evidence_dir():
    """ 
    Set the evidence directory.

    This program is designed to be packaged as an exe with PyInstaller. When run as an exe, a Tkinter window lets the user
    select the evidence directory but for testing/development use a static test directory.

    Returns:
    evidence_dir: Path object to the directory where evidence files will be read.
    """
    evidence_dir = ''
    if getattr(sys, 'frozen', False): # Program is running from an exe
        Tk().withdraw() # We don't need a full GUI, so keep the root window from appearing    
        evidence_dir = Path(askdirectory()) # Open a file-browser to let user select the evidence folder
    else: # Program is being called directly, outside of an exe
        # TODO the path doesn't work in Linux. It won't read any files in the directory. Need to play around with the path. Tried Path.cwd() / 'test_dir' which seems like it shoudl work but doesn't.
        evidence_dir = Path('./test_data/')
    return evidence_dir


def read_files(evidence_dir):
    """
    Read each file in a given directory.

    Parameters:
    evidence_dir (str): Directory to read files from

    Returns:
    text: Text inside the file with decorators for easily separating by sections.
    """
    for input_file in evidence_dir.glob('*.txt'): # Read each file in the evidence directory
        with open(input_file, 'r', encoding='utf8') as f:
            text = '+ ' + f.read() + '\n+ ' # plus sign is used as a section separator so put one at the end
            # TODO write a function to clean up the text file and make sure it is parsable
            yield text
        
        
def call_control_function(text):
    """
    Call appropriate controls function.

    Use expected keywords in system commands to determine what category of evidence this is (firewall rules,
    authentication, etc.) and what platform generated it (AWS, Linux, etc.). This is used to call the appropriate
    function and class methods.

    Parameters:
    text: Text from files read by the read_files function.

    Returns:
    None
    """
    test_results = []
    for platform, control in settings.control_categories.items():
        for key in control:
            """
            TODO find a clean way to check if every item from a list is in the text. This will let me build better settings search words.
            something like:
            if (isinstance(control[key], list)):
                for item in control[key]:
                    if str(item) in text:
            """
            if str(control[key]) in text:
                template_name = key
                if eval(f'controls.{key}.{platform}(text)'):
                    eval(f'test_results.append(controls.{key}.{platform}(text))') # Call controls function and aggregate the results from all files.
    return test_results


if __name__ == '__main__':
    main()