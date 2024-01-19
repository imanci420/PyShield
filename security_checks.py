import re

def detect_sql_injection(code, config):
    findings = []
    sql_injection_pattern = re.compile(r'("|\').*?(=|<|>|\'|"|;).*?("|\')')
    
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(sql_injection_pattern, line):
            findings.append({
                'type': 'SQL Injection',
                'line_number': line_number,
                'severity': config['security_checks']['SQLInjection']['severity'],
                'message': 'Potential SQL injection pattern detected',
            })
    return findings

def detect_xss(code, config):
    findings = []
    xss_pattern = re.compile(r'(<|&lt;).*?(>|&gt;)')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(xss_pattern, line):
            findings.append({
                'type': 'XSS',
                'line_number': line_number,
                'severity': config['security_checks']['XSS']['severity'],
                'message': 'Potential XSS pattern detected',
            })
    return findings

def detect_sensitive_data_exposure(code, config):
    findings = []
    sensitive_data_patterns = ['password', 'api_key', 'secret_key']

    for line_number, line in enumerate(code.split('\n'), start=1):
        for pattern in sensitive_data_patterns:
            if pattern in line:
                findings.append({
                    'type': 'Sensitive Data Exposure',
                    'line_number': line_number,
                    'severity': config['security_checks']['SensitiveDataExposure']['severity'],
                    'message': f'Sensitive data ({pattern}) exposure detected',
                })
    return findings

def detect_insecure_deserialization(code, config):
    findings = []
    insecure_deserialization_patterns = ['pickle.loads', 'json.loads']

    for line_number, line in enumerate(code.split('\n'), start=1):
        for pattern in insecure_deserialization_patterns:
            if pattern in line:
                findings.append({
                    'type': 'Insecure Deserialization',
                    'line_number': line_number,
                    'severity': config['security_checks']['InsecureDeserialization']['severity'],
                    'message': f'Insecure deserialization ({pattern}) detected',
                })
    return findings

def detect_insecure_session_management(code, config):
    findings = []
    session_management_pattern = re.compile(r'session\.secret\s*=\s*("|\').*?("|\')')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(session_management_pattern, line):
            findings.append({
                'type': 'Insecure Session Management',
                'line_number': line_number,
                'severity': config['security_checks']['InsecureSessionManagement']['severity'],
                'message': 'Potential insecure session management detected',
            })
    return findings

def detect_file_inclusion(code, config):
    findings = []
    file_inclusion_pattern = re.compile(r'include\((.*?)\)')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(file_inclusion_pattern, line):
            findings.append({
                'type': 'File Inclusion',
                'line_number': line_number,
                'severity': config['security_checks']['FileInclusion']['severity'],
                'message': 'Potential file inclusion vulnerability detected',
            })
    return findings

def detect_command_injection(code, config):
    findings = []
    command_injection_pattern = re.compile(r'exec\((.*?)\)')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(command_injection_pattern, line):
            findings.append({
                'type': 'Command Injection',
                'line_number': line_number,
                'severity': config['security_checks']['CommandInjection']['severity'],
                'message': 'Potential command injection vulnerability detected',
            })
    return findings

def detect_sensitive_data_encryption(code, config):
    findings = []
    encryption_patterns = ['AES', 'DES', 'RSA']

    for line_number, line in enumerate(code.split('\n'), start=1):
        for pattern in encryption_patterns:
            if pattern in line:
                findings.append({
                    'type': 'Sensitive Data Encryption',
                    'line_number': line_number,
                    'severity': config['security_checks']['SensitiveDataEncryption']['severity'],
                    'message': f'Sensitive data encryption issue detected ({pattern})',
                })
    return findings

def detect_csrf_prevention(code, config):
    findings = []
    csrf_prevention_pattern = re.compile(r'csrf_\w*')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(csrf_prevention_pattern, line):
            findings.append({
                'type': 'CSRF Prevention',
                'line_number': line_number,
                'severity': config['security_checks']['CSRFPrevention']['severity'],
                'message': 'Potential CSRF prevention issue detected',
            })
    return findings

def detect_secure_password_storage(code, config):
    findings = []
    password_storage_pattern = re.compile(r'password\s*=\s*hashlib\.sha256')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(password_storage_pattern, line):
            findings.append({
                'type': 'Secure Password Storage',
                'line_number': line_number,
                'severity': config['security_checks']['SecurePasswordStorage']['severity'],
                'message': 'Potential insecure password storage detected',
            })
    return findings

def detect_hardcoded_credentials(code, config):
    findings = []
    credentials_pattern = re.compile(r'(username|password|secret)\s*=\s*["\'].*?["\']')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(credentials_pattern, line):
            findings.append({
                'type': 'Hardcoded Credentials',
                'line_number': line_number,
                'severity': config['security_checks']['HardcodedCredentials']['severity'],
                'message': 'Potential hardcoded credentials detected',
            })
    return findings

def detect_open_redirects(code, config):
    findings = []
    redirect_pattern = re.compile(r'redirect\((.*?request\.GET\[.*?\].*?)\)')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(redirect_pattern, line):
            findings.append({
                'type': 'Open Redirect',
                'line_number': line_number,
                'severity': config['security_checks']['OpenRedirects']['severity'],
                'message': 'Potential open redirect vulnerability detected',
            })
    return findings

def detect_debug_info_exposure(code, config):
    findings = []
    debug_info_patterns = ['console.log', 'print', 'debugger']

    for line_number, line in enumerate(code.split('\n'), start=1):
        for pattern in debug_info_patterns:
            if pattern in line:
                findings.append({
                    'type': 'Debug Information Exposure',
                    'line_number': line_number,
                    'severity': config['security_checks']['DebugInfoExposure']['severity'],
                    'message': f'Potential debug information ({pattern}) exposure detected',
                })
    return findings

def detect_insecure_http_methods(code, config):
    findings = []
    http_method_pattern = re.compile(r'http://')

    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(http_method_pattern, line):
            findings.append({
                'type': 'Insecure HTTP Method',
                'line_number': line_number,
                'severity': config['security_checks']['InsecureHTTPMethods']['severity'],
                'message': 'Insecure HTTP method detected (no SSL/TLS)',
            })
    return findings

def detect_lack_of_input_validation(code, config):
    findings = []
    input_validation_pattern = re.compile(r'input\(\)')
    
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(input_validation_pattern, line):
            findings.append({
                'type': 'Lack of Input Validation',
                'line_number': line_number,
                'severity': config['security_checks']['LackOfInputValidation']['severity'],
                'message': 'Potential lack of input validation detected',
            })
    return findings
