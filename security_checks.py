import re

def detect_sql_injection(code):
    findings = []
    # Regular expression to search for potential SQL injection patterns
    sql_injection_pattern = re.compile(r'("|\').*?(=|<|>|\'|"|;).*?("|\')')
    
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(sql_injection_pattern, line):
            findings.append({
                'type': 'SQL Injection',
                'line_number': line_number,
                'message': 'Potential SQL injection pattern detected',
            })
    
    return findings

def detect_xss(code):
    findings = []
    # Regular expression to search for potential XSS patterns
    xss_pattern = re.compile(r'(<|&lt;).*?(>|&gt;)')
    
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(xss_pattern, line):
            findings.append({
                'type': 'XSS',
                'line_number': line_number,
                'message': 'Potential XSS pattern detected',
            })
    
    return findings

def detect_sensitive_data_exposure(code):
    findings = []
    # Search for sensitive data exposure patterns
    sensitive_data_patterns = ['password', 'api_key', 'secret_key']
    
    for line_number, line in enumerate(code.split('\n'), start=1):
        for pattern in sensitive_data_patterns:
            if pattern in line:
                findings.append({
                    'type': 'Sensitive Data Exposure',
                    'line_number': line_number,
                    'message': f'Sensitive data ({pattern}) exposure detected',
                })
    
    return findings

def detect_insecure_deserialization(code):
    findings = []
    # Search for insecure deserialization patterns
    insecure_deserialization_patterns = ['pickle.loads', 'json.loads']
    
    for line_number, line in enumerate(code.split('\n'), start=1):
        for pattern in insecure_deserialization_patterns:
            if pattern in line:
                findings.append({
                    'type': 'Insecure Deserialization',
                    'line_number': line_number,
                    'message': f'Insecure deserialization ({pattern}) detected',
                })
    
    return findings


def detect_insecure_session_management(code):
    findings = []
    # Regular expression to search for potential session management issues
    session_management_pattern = re.compile(r'session\.secret\s*=\s*("|\').*?("|\')')
    
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(session_management_pattern, line):
            findings.append({
                'type': 'Insecure Session Management',
                'line_number': line_number,
                'message': 'Potential insecure session management detected',
            })
    
    return findings

def detect_file_inclusion(code):
    findings = []
    # Regular expression to search for potential file inclusion patterns
    file_inclusion_pattern = re.compile(r'include\((.*?)\)')
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(file_inclusion_pattern, line):
            findings.append({
                'type': 'File Inclusion',
                'line_number': line_number,
                'message': 'Potential file inclusion vulnerability detected',
            })
    return findings


def detect_command_injection(code):
    findings = []
    # Regular expression to search for potential command injection patterns
    command_injection_pattern = re.compile(r'exec\((.*?)\)')
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(command_injection_pattern, line):
            findings.append({
                'type': 'Command Injection',
                'line_number': line_number,
                'message': 'Potential command injection vulnerability detected',
            })
    return findings


def detect_sensitive_data_encryption(code):
    findings = []
    # Search for patterns indicating sensitive data encryption
    encryption_patterns = ['AES', 'DES', 'RSA']
    for line_number, line in enumerate(code.split('\n'), start=1):
        for pattern in encryption_patterns:
            if pattern in line:
                findings.append({
                    'type': 'Sensitive Data Encryption',
                    'line_number': line_number,
                    'message': f'Sensitive data encryption issue detected ({pattern})',
                })
    return findings


def detect_csrf_prevention(code):
    findings = []
    # Regular expression to search for potential CSRF prevention patterns
    csrf_prevention_pattern = re.compile(r'csrf_\w*')
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(csrf_prevention_pattern, line):
            findings.append({
                'type': 'CSRF Prevention',
                'line_number': line_number,
                'message': 'Potential CSRF prevention issue detected',
            })
    return findings

def detect_secure_password_storage(code):
    findings = []
    # Regular expression to search for potential password storage patterns
    password_storage_pattern = re.compile(r'password\s*=\s*hashlib\.sha256')
    for line_number, line in enumerate(code.split('\n'), start=1):
        if re.search(password_storage_pattern, line):
            findings.append({
                'type': 'Secure Password Storage',
                'line_number': line_number,
                'message': 'Potential insecure password storage detected',
            })
    return findings
