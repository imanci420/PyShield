import concurrent.futures
import os
import requests
import tempfile
import json
import re
from security_checks import (
    detect_sql_injection, detect_xss, detect_sensitive_data_exposure,
    detect_insecure_deserialization, detect_insecure_session_management,
    detect_file_inclusion, detect_command_injection, detect_sensitive_data_encryption,
    detect_csrf_prevention, detect_secure_password_storage,
)


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
    
    
def analyze_file(file_url):
    file_path = download_file(file_url)
    code = read_file(file_path)
    
    # Perform security checks on the code using your defined functions
    sql_injection_findings = detect_sql_injection(code)
    xss_findings = detect_xss(code)
    # ... (Perform other security checks)

    os.remove(file_path)  # Clean up downloaded file
    
    return sql_injection_findings + xss_findings  # Combine findings from multiple checks



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
 

def analyze_repo(repo_name):
    """Main function to analyze a GitHub repository."""
    contents = fetch_repo_contents(repo_name)
    all_findings = []  # Initialize all_findings before the loop

    def analyze_file(content):
        if content['name'].endswith('.py'):
            print(f"Analyzing file: {content['name']}")
            file_path = download_file(content['download_url'])

            # Security checks
            code = read_file(file_path)
            findings = (
                detect_sql_injection(code) + 
                detect_xss(code) +
                detect_sensitive_data_exposure(code) +
                detect_insecure_deserialization(code) +
                detect_insecure_session_management(code) +
                detect_file_inclusion(code) +
                detect_command_injection(code) +
                detect_sensitive_data_encryption(code) +
                detect_csrf_prevention(code) +
                detect_secure_password_storage(code)
            )

            os.remove(file_path)
            return findings

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_content = {executor.submit(analyze_file, content): content for content in contents}
        
        for future in concurrent.futures.as_completed(future_to_content):
            content = future_to_content[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
            except Exception as exc:
                print(f"An error occurred while analyzing {content['name']}: {exc}")

    findings_summary = summarize_findings(all_findings)

    if not all_findings:
        print("No issues found.")
        return {'findings': [], 'summary': {}}

    # Output findings based on the configured format
    output = {'findings': all_findings, 'summary': findings_summary}
    if config['output_format'] == 'json':
        with open('scan_report.json', 'w') as report_file:
            json.dump(output, report_file, indent=4)

    print("Analysis complete. Report generated.")
    return output



    # Optional: Write findings to a file
    with open('scan_report.txt', 'w') as report_file:
        for finding in all_findings:
            report_file.write(json.dumps(finding) + '\n')
        report_file.write("Summary of Findings:\n")
        report_file.write(json.dumps(findings_summary))


if __name__ == "__main__":
    # Prompt the user for the repository to analyze
    repo_to_analyze = input("Enter the GitHub repository to analyze (e.g., 'octocat/Hello-World'): ").strip()
    # Debugging: Print the repo name to verify input
    print(f"Analyzing repository: '{repo_to_analyze}'")
    analyze_repo(repo_to_analyze)


    

