# Password Strength Analyzer

A Python-based security tool that evaluates password strength, prevents password reuse, generates secure password suggestions, and stores password hashes securely using SHA-256 and SQLite.

---

## Features

- Checks password length (8+ and 12+ character standards)
- Verifies uppercase letters, lowercase letters, numbers, and special characters
- Calculates a password strength score (0–6)
- Converts score into a security percentage
- Classifies passwords as:
  - Weak
  - Medium
  - Strong
- Detects common and easily guessable passwords
- Prevents password reuse using SQLite database storage
- Uses SHA-256 hashing for secure password storage
- Generates strong password suggestions automatically
- Exports password analysis reports to a text file
- Provides detailed feedback and improvement suggestions

---

## Technologies Used

- Python
- SQLite
- SHA-256 Hashing
- Regular Expressions (re)
- Secrets Module
- String Module

---

## How to Run

1. Open Command Prompt, PowerShell, or VS Code Terminal.

2. Navigate to the project folder:

```bash
cd "path_to_your_project_folder"
```

3. Run the program:

```bash
python password_analyzer.py
```

---

## Example Features

### Password Analysis
- Length Validation
- Complexity Checks
- Security Scoring
- Common Password Detection

### Password Security
- SHA-256 Password Hashing
- Password Reuse Prevention
- Secure Password Suggestions

### Report Generation
- Export analysis results to:
  
```text
password_report.txt
```

---

## Database Support

The application automatically creates:

```text
passwords.db
```

This database stores only SHA-256 password hashes and is used to prevent password reuse.

---

## Security Assessment Levels

| Rating | Assessment |
|----------|-------------|
| Weak | Easily guessable |
| Medium | Moderate protection |
| Strong | Difficult to crack |

---

## Security Note

Passwords are never stored in plain text.

The application stores only SHA-256 hashes in the SQLite database, ensuring that original passwords cannot be recovered from the database.

All password analysis is performed locally on the user's machine.

---

## Author

Shwetha Chary

---

## Project Objective

To develop a Password Strength Analyzer that evaluates password security based on length, complexity, uniqueness, and common password detection while demonstrating basic cybersecurity and cryptography concepts.
