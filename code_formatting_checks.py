def perform_code_formatting_check(code):
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, start=1):
        # Check for line length
        if len(line) > 79:
            findings.append({
                "type": "Exceeds 79 characters", 
                "line_number": i, 
                "message": "Exceeds 79 characters."
            })

        # Check for indentation using tabs
        if line.startswith('\t'):
            findings.append({
                "type": "Uses tabs for indentation (use spaces)", 
                "line_number": i, 
                "message": "Uses tabs for indentation (use spaces)."
            })

        # Check for trailing whitespaces
        if line.rstrip() != line:
            findings.append({
                "type": "Has trailing whitespaces", 
                "line_number": i, 
                "message": "Has trailing whitespaces."
            })

        # Check for spaces around operators and after commas
        if '==' in line or '+=' in line or '-=' in line or '*=' in line or '/=' in line:
            if ' ==' not in line or '!=' not in line or '+=' not in line or '-=' not in line or '*=' not in line or '/=' not in line:
                findings.append({
                    "type": "Missing spaces around operator", 
                    "line_number": i, 
                    "message": "Missing spaces around operator."
                })
        
        # Check for multiple statements on a single line
        if ';' in line and not line.strip().startswith('#'):  # Ignore semicolons in comments
            findings.append({
                "type": "Multiple statements on a single line", 
                "line_number": i, 
                "message": "Multiple statements on a single line."
            })

        # Check for correct use of spaces before and after comments
        if '#' in line:
            comment_index = line.index('#')
            if comment_index != 0 and line[comment_index - 1] != ' ':
                findings.append({
                    "type": "Missing space before inline comment", 
                    "line_number": i, 
                    "message": "Missing space before inline comment."
                })
            if comment_index + 1 < len(line) and line[comment_index + 1] != ' ':
                findings.append({
                    "type": "Missing space after '#' in comment", 
                    "line_number": i, 
                    "message": "Missing space after '#' in comment."
                })

        # Additional checks can be added here as needed

    return findings
