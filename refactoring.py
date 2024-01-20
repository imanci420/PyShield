def get_refactoring_suggestion(issue_type):
    refactoring_suggestions = {
        'SQL Injection': "Refactor your code to use parameterized queries or prepared statements to prevent SQL injection.",
        'XSS': "Sanitize user input to prevent XSS. Ensure proper output encoding when displaying user-generated content.",
        'Sensitive Data Exposure': "Use encryption and secure storage techniques to protect sensitive data.",
        'Insecure Deserialization': "Implement thorough validation of deserialized objects. Avoid deserializing data from untrusted sources.",
        'Insecure Session Management': "Use secure and standard practices for session management. Avoid custom implementations.",
        'File Inclusion': "Validate and sanitize file paths. Avoid direct use of user input in file paths.",
        'Command Injection': "Avoid direct use of user input in system commands. Use safer APIs or parameterized interfaces.",
        'Sensitive Data Encryption': "Use strong and modern encryption algorithms. Securely manage encryption keys.",
        'CSRF Prevention': "Implement anti-CSRF tokens in forms and ensure state-changing requests are protected.",
        'Secure Password Storage': "Use strong hashing algorithms like bcrypt for password storage. Implement salting and hashing appropriately.",
        'Hardcoded Credentials': "Remove hardcoded credentials. Use secure storage like environment variables or configuration files.",
        'Open Redirects': "Validate and whitelist redirect URLs to prevent open redirect vulnerabilities.",
        'Debug Information Exposure': "Configure logging and error handling to avoid exposing sensitive debug information.",
        'Insecure HTTP Method': "Enforce the use of HTTPS to secure data in transit. Redirect all HTTP requests to HTTPS.",
        'Lack of Input Validation': "Implement strict input validation. Sanitize and validate all user inputs.",
         # Formatting Issues
        'FormattingIssue': "Automatically format code according to the style guide (e.g., PEP 8 for Python). Use tools like 'black' or 'autopep8'.",
        'Exceeds 79 characters': "Break lines longer than 79 characters into multiple lines for better readability.",
        'Uses tabs for indentation (use spaces)': "Replace tabs with spaces as recommended in PEP 8.",
        'Has trailing whitespaces': "Remove trailing whitespaces at the end of lines.",
        'Missing spaces around operator': "Ensure spaces are placed around operators for better readability.",
        'Multiple statements on a single line': "Place each statement on its own line for clarity.",
        'Missing space before inline comment': "Add a space before inline comments for readability.",
        'Missing space after \'#\' in comment': "Insert a space after '#' for clarity in comments.",
         # Code Quality Issues
        'High Complexity': "Refactor to reduce complexity. Consider simplifying logic and dividing into smaller functions.",
        'Global Variable Usage': "Replace global variables with function arguments or class members to improve encapsulation.",
        'Duplicate Code': "Identify common patterns and create shared methods or functions to avoid repetition.",
    }

    return refactoring_suggestions.get(issue_type, "No refactoring suggestion available for this issue.")
