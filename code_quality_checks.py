import re
def check_code_complexity(code):
    """
    Checks for code complexity.
    This is a very basic check that counts the depth of nested structures.
    """
    findings = []
    depth = 0
    max_depth = 4  # Example threshold for complexity
    for i, line in enumerate(code.splitlines(), start=1):
        stripped_line = line.strip()
        if stripped_line.startswith(('if ', 'for ', 'while ', 'with ', 'try:', 'except ')):
            depth += 1
        if depth > max_depth:
            findings.append({
                "type": "High Complexity",
                "line_number": i,
                "message": "Complex nested structures."
            })
        if stripped_line in ('endif', 'endfor', 'endwhile', 'endwith', 'endtry'):
            depth = max(0, depth - 1)

    return findings

def check_global_variables_usage(code):
    """
    Checks for the use of global variables.
    """
    findings = []
    for i, line in enumerate(code.splitlines(), start=1):
        if ' global ' in line:
            findings.append({
                "type": "Global Variable Usage",
                "line_number": i,
                "message": "Use of global variables."
            })

    return findings

def check_duplicate_code(code):
    """
    Checks for duplicate lines of code.
    Note: This is a very naive implementation.
    """
    findings = []
    lines = code.splitlines()
    seen = set()
    for i, line in enumerate(lines, start=1):
        if line in seen:
            findings.append({
                "type": "Duplicate Code",
                "line_number": i,
                "message": "Duplicate line of code."
            })
        else:
            seen.add(line)

    return findings

def perform_code_quality_check(code):
    """
    Performs code quality checks.
    """
    findings = []
    findings.extend(check_code_complexity(code))
    findings.extend(check_global_variables_usage(code))
    findings.extend(check_duplicate_code(code))

    return findings
