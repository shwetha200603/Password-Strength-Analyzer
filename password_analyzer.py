import re
import sys
import sqlite3
import hashlib
import secrets
import string

COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

COMMON_PASSWORDS = {
    "123456", "password", "qwerty", "123456789", "12345678", "12345", "1234567",
    "password123", "111111", "admin", "admin123", "letmein", "sunshine",
    "iloveyou", "princess", "welcome", "shadow", "abc123", "secret", "charlie"
}

def init_db(db_name="passwords.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS used_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:

    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def is_password_used(password: str, db_name="passwords.db") -> bool:
    
    p_hash = hash_password(password)
    
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM used_passwords WHERE password_hash = ?", (p_hash,))
    row = cursor.fetchone()
    
    conn.close()
    return row is not None

def save_password_hash(password: str, db_name="passwords.db"):
   
    p_hash = hash_password(password)
    
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO used_passwords (password_hash) VALUES (?)", (p_hash,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

def generate_strong_password(length=14) -> str:

    if length < 12:
        length = 12
        
    uppers = string.ascii_uppercase
    lowers = string.ascii_lowercase
    digits = string.digits
    specials = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    password_chars = [
        secrets.choice(uppers),
        secrets.choice(lowers),
        secrets.choice(digits),
        secrets.choice(specials)
    ]
    
    all_chars = uppers + lowers + digits + specials
    password_chars += [secrets.choice(all_chars) for _ in range(length - 4)]
    
    secrets.SystemRandom().shuffle(password_chars)
    
    return "".join(password_chars)

def export_report_to_file(password: str, results: dict, filename="password_report.txt"):

    score = results["score"]
    rating = results["rating"]
    percentage = results["percentage"]
    assessment = results["assessment"]
    criteria = results["criteria"]
    suggestions = results["suggestions"]
    is_common = results["is_common"]
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("             🛡️  PASSWORD ANALYSIS REPORT 🛡️\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Password Checked: {password}\n")
        f.write(f"Strength Rating:  {rating} ({assessment})\n")
        f.write(f"Security Score:   {score}/6 ({percentage}%)\n\n")
        
        f.write("--- Criteria Analysis ---\n")
        def check_symbol(met):
            return "[✔]" if met else "[✘]"
            
        f.write(f" {check_symbol(criteria['len_8'])} Length is 8 or more characters\n")
        f.write(f" {check_symbol(criteria['len_12'])} Length is 12 or more characters (Bonus)\n")
        f.write(f" {check_symbol(criteria['has_upper'])} Contains uppercase letter (A-Z)\n")
        f.write(f" {check_symbol(criteria['has_lower'])} Contains lowercase letter (a-z)\n")
        f.write(f" {check_symbol(criteria['has_digit'])} Contains digit (0-9)\n")
        f.write(f" {check_symbol(criteria['has_special'])} Contains special character (e.g. !, @, $, etc.)\n\n")
        
        if is_common:
            f.write("⚠️ WARNING: This is a highly common/dictionary password!\n\n")
            
        if suggestions:
            f.write("Suggestions for Improvement:\n")
            for i, suggestion in enumerate(suggestions, 1):
                f.write(f"  {i}. {suggestion}\n")
        else:
            f.write("🎉 Excellent! Your password meets all security guidelines.\n")
            
        f.write("\n" + "=" * 60 + "\n")


def check_common_password(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS

def analyze_password(password: str) -> dict:
    criteria = {
        "len_8": len(password) >= 8,
        "len_12": len(password) >= 12,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^A-Za-z0-9]", password))
    }
    
    suggestions = []
    is_common = check_common_password(password)

    score = 0
    
    if is_common:
        score = 0
        rating = "Weak"
        assessment = "Easily guessable"
        suggestions.append("Avoid using highly common or easily guessable dictionary words.")
    else:
        if criteria["len_12"]:
            score += 2
        elif criteria["len_8"]:
            score += 1
        else:
            suggestions.append("Increase password length to at least 8 characters (ideally 12+).")
            
        if criteria["has_upper"]:
            score += 1
        else:
            suggestions.append("Add at least one uppercase letter (A-Z).")
            
        if criteria["has_lower"]:
            score += 1
        else:
            suggestions.append("Add at least one lowercase letter (a-z).")
            
        if criteria["has_digit"]:
            score += 1
        else:
            suggestions.append("Add at least one number (0-9).")
            
        if criteria["has_special"]:
            score += 1
        else:
            suggestions.append("Add at least one special character (e.g. !, @, #, $, %, etc.).")
            
        if criteria["len_8"] and not criteria["len_12"]:
            suggestions.append("Make the password longer (12+ characters) for optimal security.")

        if len(password) < 8 or score <= 2:
            rating = "Weak"
            assessment = "Easily guessable"
        elif score <= 4:
            rating = "Medium"
            assessment = "Moderate protection"
        else:
            rating = "Strong"
            assessment = "Difficult to crack"
            
    percentage = int((score / 6) * 100)
            
    return {
        "criteria": criteria,
        "score": score,
        "percentage": percentage,
        "rating": rating,
        "assessment": assessment,
        "suggestions": suggestions,
        "is_common": is_common
    }

def print_ui_header():
    print(f"\n{COLOR_CYAN}{'='*60}{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}         🛡️  PASSWORD STRENGTH ANALYZER 🛡️{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'='*60}{COLOR_RESET}\n")

def display_results(password: str, results: dict):

    score = results["score"]
    rating = results["rating"]
    percentage = results["percentage"]
    assessment = results["assessment"]
    criteria = results["criteria"]
    suggestions = results["suggestions"]
    is_common = results["is_common"]   
    if rating == "Weak":
        color = COLOR_RED
        emoji = "❌ Weak"
    elif rating == "Medium":
        color = COLOR_YELLOW
        emoji = "⚠️  Medium"
    else:
        color = COLOR_GREEN
        emoji = "✅ Strong"
        
    print(f"{COLOR_BOLD}Password Checked:{COLOR_RESET} {password}")
    print(f"{COLOR_BOLD}Strength Rating: {COLOR_RESET}{color}{COLOR_BOLD}{emoji} ({assessment}){COLOR_RESET}")
    
    bar_length = 12
    filled_length = int(round(bar_length * score / 6))
    bar = "█" * filled_length + "-" * (bar_length - filled_length)
    print(f"{COLOR_BOLD}Security Score:  {COLOR_RESET}{color}[{bar}] {score}/6 ({percentage}%){COLOR_RESET}\n")
    
    print(f"{COLOR_BOLD}--- Criteria Analysis ---{COLOR_RESET}")
    
    def print_criterion(name: str, met: bool, label: str):
        symbol = f"{COLOR_GREEN}✔{COLOR_RESET}" if met else f"{COLOR_RED}✘{COLOR_RESET}"
        print(f" {symbol} {label}")

    print_criterion("len_8", criteria["len_8"], "Length is 8 or more characters")
    print_criterion("len_12", criteria["len_12"], "Length is 12 or more characters (Bonus)")
    print_criterion("has_upper", criteria["has_upper"], "Contains uppercase letter (A-Z)")
    print_criterion("has_lower", criteria["has_lower"], "Contains lowercase letter (a-z)")
    print_criterion("has_digit", criteria["has_digit"], "Contains digit (0-9)")
    print_criterion("has_special", criteria["has_special"], "Contains special character (e.g. !, @, $, etc.)")
    
    if is_common:
        print(f"\n{COLOR_RED}{COLOR_BOLD}⚠️  WARNING: This is a highly common/dictionary password and is extremely easy to hack!{COLOR_RESET}")
        
    if suggestions:
        print(f"\n{COLOR_BOLD}Suggestions for Improvement:{COLOR_RESET}")
        for i, suggestion in enumerate(suggestions, 1):
            print(f"  {COLOR_YELLOW}{i}. {suggestion}{COLOR_RESET}")
    else:
        print(f"\n{COLOR_GREEN}{COLOR_BOLD}🎉 Excellent! Your password meets all security guidelines.{COLOR_RESET}")
        
    print(f"\n{COLOR_CYAN}{'-'*60}{COLOR_RESET}")

def main():
    init_db()

    if sys.platform.startswith("win"):
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass 

    print_ui_header()
    
    while True:
        try:
           
            password_input = input(f"{COLOR_BOLD}Enter a password to analyze (or press Enter/Ctrl+C to exit): {COLOR_RESET}").strip()
            if not password_input:
                print(f"\n{COLOR_CYAN}Thank you for using the Password Strength Analyzer. Stay secure!{COLOR_RESET}\n")
                break
            
            if is_password_used(password_input):
                print(f"\n{COLOR_RED}{COLOR_BOLD}Password already used. Please choose a different password.{COLOR_RESET}\n")
                print(f"{COLOR_CYAN}{'-'*60}{COLOR_RESET}")
                continue
                
            analysis_results = analyze_password(password_input)
            
            save_password_hash(password_input)
            
            print()
            display_results(password_input, analysis_results)
            
            if analysis_results["rating"] in ["Weak", "Medium"]:
                suggested_pw = generate_strong_password(14)
                print(f"{COLOR_CYAN}{COLOR_BOLD}💡 Suggested Strong Password: {COLOR_GREEN}{suggested_pw}{COLOR_RESET}")
                print(f"{COLOR_CYAN}{'-'*60}{COLOR_RESET}\n")
                
            export_choice = input(f"{COLOR_BOLD}Would you like to export this report to 'password_report.txt'? (y/n): {COLOR_RESET}").strip().lower()
            if export_choice in ["y", "yes"]:
                export_report_to_file(password_input, analysis_results)
                print(f"\n{COLOR_GREEN}✔ Report successfully saved to 'password_report.txt'!{COLOR_RESET}\n")
                print(f"{COLOR_CYAN}{'-'*60}{COLOR_RESET}")
            else:
                print()
            
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n{COLOR_CYAN}Exiting. Stay secure!{COLOR_RESET}\n")
            break

if __name__ == "__main__":
    main()