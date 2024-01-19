import concurrent.futures
import os
import requests
import tempfile
import json
import re
from code_formatting_checks import perform_code_formatting_check
from security_checks import (
    detect_sql_injection, detect_xss, detect_sensitive_data_exposure,
    detect_insecure_deserialization, detect_insecure_session_management,
    detect_file_inclusion, detect_command_injection, detect_sensitive_data_encryption,
    detect_csrf_prevention, detect_secure_password_storage, detect_debug_info_exposure,
    detect_hardcoded_credentials, detect_insecure_http_methods ,detect_lack_of_input_validation,
    detect_open_redirects,
)
from solutions import get_solution_for_issue





# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

# Environment variable for GitHub token 
github_token = os.getenv('GITHUB_TOKEN')

def fetch_repo_contents(repo_name):
    """Fetches contents of a specified GitHub repository."""
    api_url = f'https://api.github.com/repos/{repo_name}/contents'
    headers = {'Authorization': f'token {github_token}'}
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        contents = response.json()
        # Filter out only files based on configuration and ignore directories or submodules
        return [content for content in contents if content['type'] == 'file' and content['name'].endswith(tuple(config['file_types_to_scan'])) and not any(dir in content['path'] for dir in config['directories_to_ignore'])]
    else:
        raise Exception(f"Unable to fetch repo contents. Status code: {response.status_code}")

security_check_functions = {
    'SQLInjection': detect_sql_injection,
    'XSS': detect_xss,
    'SensitiveDataExposure': detect_sensitive_data_exposure,
    'InsecureDeserialization': detect_insecure_deserialization,
    'InsecureSessionManagement': detect_insecure_session_management,
    'FileInclusion': detect_file_inclusion,
    'CommandInjection': detect_command_injection,
    'SensitiveDataEncryption': detect_sensitive_data_encryption,
    'CSRFPrevention': detect_csrf_prevention,
    'SecurePasswordStorage': detect_secure_password_storage,
    'HardcodedCredentials': detect_hardcoded_credentials,
    'OpenRedirects': detect_open_redirects,
    'DebugInfoExposure': detect_debug_info_exposure,
    'InsecureHTTPMethods': detect_insecure_http_methods,
    'LackOfInputValidation': detect_lack_of_input_validation,
}

def download_file(url):
    """Downloads the file from the provided URL and returns the file path."""
    local_filename = url.split('/')[-1]

    with requests.get(url, stream=True) as r:
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    return local_filename

def read_file(file_path):
    """Reads the content of a file and returns it as a string."""
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()
    

def analyze_file(file_content, check_type, config):
    if file_content['name'].endswith('.py'):
        file_path = download_file(file_content['download_url'])
        code = read_file(file_path)
        findings = []

        if check_type == 'security':
            for check_name, check_function in security_check_functions.items():
                if config['security_checks'][check_name]['enabled']:
                    function_findings = check_function(code, config)
                    for finding in function_findings:
                        # Attach the correct solution based on the issue type
                        finding['solution'] = get_solution_for_issue(finding['type'])
                        # Debug print statement
                        print(f"Debug: Finding: {finding}")
                        findings.append(finding)

        elif check_type == 'formatting':
            formatting_issues = perform_code_formatting_check(code)
            for issue in formatting_issues:
                # Create a finding dictionary for formatting issues
                finding = {
                    'type': issue['type'],
                    'line_number': issue['line_number'],
                    'message': issue['message'],
                    'severity': 'N/A',  # Formatting issues typically don't have a severity
                    'solution': get_solution_for_issue(issue['type'])
                }
                # Debug print statement
                print(f"Debug: Finding: {finding}")
                findings.append(finding)

        os.remove(file_path)
        return findings



def summarize_findings(findings):
    """Summarizes the findings from custom security rule checks."""
    summary = {}
    for issue in findings:
        issue_type = issue['type']
        if issue_type in summary:
            summary[issue_type] += 1
        else:
            summary[issue_type] = 1
    return summary
 

def analyze_repo(repo_name, check_type='security'):
    # Load configuration for each scan
    with open('config.json') as config_file:
        config = json.load(config_file)

    contents = fetch_repo_contents(repo_name)
    if not isinstance(contents, list):
        raise TypeError("Expected a list of repository contents")

    all_findings = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_content = {
            executor.submit(analyze_file, content, check_type, config): content
            for content in contents
            if content['type'] == 'file' and content['name'].endswith('.py')
        }

        for future in concurrent.futures.as_completed(future_to_content):
            try:
                findings = future.result()
                if check_type == 'security':
                    # Apply security checks filtering
                    all_findings.extend(findings)
                elif check_type == 'formatting':
                    # Directly add formatting findings without filtering
                    all_findings.extend(findings)
            except Exception as exc:
                print(f"An error occurred: {exc}")

    findings_summary = summarize_findings(all_findings)
    return {'findings': all_findings, 'summary': findings_summary}


def filter_findings(findings, config):
    if not config:
        return findings

    filtered_findings = []
    for finding in findings:
        check_name = finding['type']  # Assuming 'type' is the check name
        check_config = config.get('security_checks', {}).get(check_name, {})

        if check_config.get('enabled', True):
            severity = check_config.get('severity', 'Low')
            if severity_matches(finding['severity'], severity):
                filtered_findings.append(finding)
    
    return filtered_findings

def severity_matches(finding_severity, config_severity):
    severity_order = {'Low': 1, 'Medium': 2, 'High': 3}
    return severity_order.get(finding_severity, 0) >= severity_order.get(config_severity, 0)


if __name__ == "__main__":
    repo_to_analyze = input("Enter the GitHub repository to analyze: ").strip()
    print(f"Analyzing repository: '{repo_to_analyze}'")
    results = analyze_repo(repo_to_analyze, check_type='security')
    # Output results
    print(json.dumps(results, indent=4))

    

