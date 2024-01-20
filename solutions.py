def get_solution_for_issue(issue_type):
    solutions = {
        # Security issues solutions

        'SQL Injection': (
            "To prevent SQL injection, use parameterized queries or prepared statements. "
            "Avoid constructing SQL queries with user inputs directly. "
            "For example, in Python with SQLAlchemy:"
            "\n\n"
            "```python\n"
            "from sqlalchemy import create_engine, text\n"
            "\n"
            "engine = create_engine('sqlite:///mydatabase.db')\n"
            "connection = engine.connect()\n"
            "query = text('SELECT * FROM users WHERE username = :username AND password = :password')\n"
            "result = connection.execute(query, username=user_input_username, password=user_input_password)\n"
            "```\n"
        ),

        'XSS': (
            "To prevent Cross-Site Scripting (XSS) attacks, sanitize user inputs and use proper output encoding. "
            "Always validate and filter data before rendering it in HTML or JavaScript. "
            "For example, in JavaScript with DOMPurify:"
            "\n\n"
            "```javascript\n"
            "const userInput = 'User-controlled input with <script>malicious code</script>';\n"
            "const sanitizedInput = DOMPurify.sanitize(userInput);\n"
            "document.getElementById('output').innerHTML = sanitizedInput;\n"
            "```\n"
        ),

        'Sensitive Data Exposure': (
            "To prevent sensitive data exposure, avoid exposing sensitive information in error messages or responses. "
            "Use encryption to protect sensitive data at rest and in transit. "
            "For example, in Python with cryptography:"
            "\n\n"
            "```python\n"
            "from cryptography.fernet import Fernet\n"
            "key = Fernet.generate_key()\n"
            "cipher_suite = Fernet(key)\n"
            "encrypted_data = cipher_suite.encrypt(b'Sensitive data')\n"
            "```\n"
        ),

        'Insecure Deserialization': (
            "To address insecure deserialization, validate and sanitize all deserialized data. "
            "Avoid deserializing untrusted data. "
            "For example, in Java with Jackson:"
            "\n\n"
            "```java\n"
            "ObjectMapper mapper = new ObjectMapper();\n"
            "String jsonString = 'User-controlled JSON data';\n"
            "MyObject obj = mapper.readValue(jsonString, MyObject.class);\n"
            "```\n"
        ),

        'Insecure Session Management': (
            "To ensure secure session management, use secure session practices such as generating strong session identifiers, "
            "setting secure session attributes, and handling session timeouts properly. "
            "For example, in Python with Flask:"
            "\n\n"
            "```python\n"
            "from flask import Flask, session, redirect, url_for\n"
            "import os\n"
            "\n"
            "app = Flask(__name__)\n"
            "app.secret_key = os.urandom(24)\n"
            "```\n"
        ),

    
        'File Inclusion': (
        "To prevent File Inclusion vulnerabilities, validate and sanitize file paths to prevent unauthorized access. "
        "Avoid directly using user-controlled input in file operations. "
        "For example, in Python:"
        "\n\n"
        "```python\n"
        "import os\n"
        "\n"
        "user_input_file = 'user-controlled-file.txt'\n"
        "if user_input_file.startswith('/'):\n"
        "    absolute_path = user_input_file\n"
        "else:\n"
        "    absolute_path = os.path.abspath(user_input_file)\n"
        "with open(absolute_path, 'r') as file:\n"
        "    content = file.read()\n"
        "```\n"
    ),

    'Command Injection': (
        "To prevent Command Injection, avoid using user input directly in system commands. "
        "Use safe subprocess libraries and validate and sanitize inputs. "
        "For example, in Python:"
        "\n\n"
        "```python\n"
        "import subprocess\n"
        "import shlex\n"
        "\n"
        "user_input_command = 'ls -l /path/to/user-controlled-directory'\n"
        "try:\n"
        "    args = shlex.split(user_input_command)\n"
        "    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
        "    output = result.stdout\n"
        "except Exception as e:\n"
        "    output = str(e)\n"
        "```\n"
    ),

    'Sensitive Data Encryption': (
        "To ensure sensitive data encryption, use strong encryption algorithms and manage encryption keys securely. "
        "Implement industry-standard encryption practices. "
        "For example, in Python with cryptography library:"
        "\n\n"
        "```python\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
        "from cryptography.hazmat.primitives import serialization\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "\n"
        "# Generate a strong encryption key\n"
        "private_key = rsa.generate_private_key(\n"
        "    public_exponent=65537,\n"
        "    key_size=2048,\n"
        ")\n"
        "private_pem = private_key.private_bytes(\n"
        "    encoding=serialization.Encoding.PEM,\n"
        "    format=serialization.PrivateFormat.PKCS8,\n"
        "    encryption_algorithm=serialization.NoEncryption()\n"
        ")\n"
        "```\n"
    ),

    'CSRF Prevention': (
        "To prevent Cross-Site Request Forgery (CSRF) attacks, implement and enforce CSRF tokens in forms. "
        "Generate a unique token for each user session and include it in the form. "
        "Verify the token on the server to ensure that the request is legitimate. "
        "For example, in HTML with Django:"
        "\n\n"
        "```html\n"
        "<form method='POST' action='/submit'>\n"
        "    {% csrf_token %}\n"
        "    <!-- Other form fields -->\n"
        "    <input type='submit' value='Submit'>\n"
        "</form>\n"
        "```\n"
    ),

    'Secure Password Storage': (
        "To securely store passwords, use strong, salted hashing algorithms. "
        "Never store plaintext passwords. Use libraries like bcrypt or argon2 to hash passwords. "
        "For example, in Python with bcrypt:"
        "\n\n"
        "```python\n"
        "import bcrypt\n"
        "\n"
        "password = 'user_password'\n"
        "salt = bcrypt.gensalt()\n"
        "hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)\n"
        "```\n"
    ),

    'Hardcoded Credentials': (
        "To remove hardcoded credentials, avoid storing sensitive information directly in the source code. "
        "Use environment variables or secure vaults to manage credentials. "
        "For example, in Python with environment variables:"
        "\n\n"
        "```python\n"
        "import os\n"
        "\n"
        "api_key = os.environ.get('API_KEY')\n"
        "api_secret = os.environ.get('API_SECRET')\n"
        "```\n"
    ),

    'Open Redirects': (
        "To validate and sanitize redirect URLs, ensure that redirect URLs are validated and whitelist them. "
        "Do not allow arbitrary or user-controlled URLs in redirects. "
        "For example, in Django with a whitelist of trusted domains:"
        "\n\n"
        "```python\n"
        "from django.shortcuts import redirect\n"
        "\n"
        "def safe_redirect(request, url):\n"
        "    trusted_domains = ['example.com', 'myapp.com']\n"
        "    if any(url.startswith(domain) for domain in trusted_domains):\n"
        "        return redirect(url)\n"
        "    else:\n"
        "        return redirect('/')  # Redirect to a safe default\n"
        "```\n"
    ),

    'Debug Information Exposure': (
        "To remove or secure debug information and logs, ensure that debug information is disabled "
        "in production environments. Avoid exposing sensitive information in logs. "
        "For example, in Django settings:"
        "\n\n"
        "```python\n"
        "DEBUG = False\n"
        "```\n"
    ),

    'Insecure HTTP Method': (
        "To use HTTPS to encrypt data in transit, configure your web server to use HTTPS. "
        "Install and configure an SSL/TLS certificate. "
        "For example, in Apache with Let's Encrypt:"
        "\n\n"
        "```bash\n"
        "sudo apt-get update\n"
        "sudo apt-get install certbot python3-certbot-apache\n"
        "sudo certbot --apache\n"
        "```\n"
    ),

    'Lack of Input Validation': (
        "To implement thorough input validation, validate all user inputs to ensure they conform to expected formats. "
        "Use input validation libraries or regular expressions. "
        "For example, in Python with a regular expression for email validation:"
        "\n\n"
        "```python\n"
        "import re\n"
        "\n"
        "def is_valid_email(email):\n"
        "    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'\n"
        "    return bool(re.match(pattern, email))\n"
        "```\n"
    ),

        # Formatting issues solutions

        'Exceeds 79 characters': "Ensure the line length does not exceed 79 characters.",
        'Uses tabs for indentation (use spaces)': "Replace tabs with spaces for indentation.",
        'Has trailing whitespaces': "Remove any trailing whitespaces at the end of lines.",
        'Missing spaces around operator': "Add spaces around operators for readability.",
        'Multiple statements on a single line': "Place each statement on a separate line.",
        'Missing space before inline comment': "Add a space before inline comments.",
        'Missing space after \'#\' in comment': "Add a space after '#' in comments.",

          # Code Quality Issues
        'High Complexity': 
        (
            "Reduce complexity by breaking down complex functions, "
            "using helper functions, and avoiding deep nesting."
        ),
        'Global Variable Usage':
        (
            "Avoid global variables. Consider passing variables as parameters, "
            "or encapsulating them within a class."
        ),
        'Duplicate Code': 
        (
            "Refactor duplicate code into a single function or method. "
            "Use this function/method wherever the duplicate code is found."
        )

        
    }
    solution = solutions.get(issue_type, "No specific solution available for this issue.")
    print(f"Debug: Issue type: {issue_type}, Solution: {solution}")  # Debug print
    return solution