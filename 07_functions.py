"""
====================================================================
MODULE 7: FUNCTIONS - Building Reusable Security Tools 🔧
====================================================================

Welcome to Module 7! You've learned to store data and control program flow.
Now you'll learn about functions - reusable blocks of code that make your
cybersecurity scripts more organized, efficient, and maintainable.

WHAT ARE FUNCTIONS?
Functions are named blocks of code that perform specific tasks. Think of them
as specialized tools in your cybersecurity toolkit - each one designed for
a particular job that you can use whenever needed without rewriting code.

FUNCTION CONCEPTS WE'LL COVER:
- Defining and calling functions
- Parameters and arguments
- Return values and scope
- Default parameters and keyword arguments
- Documenting functions with docstrings
"""

"""
====================================================================
MODULE 7: FUNCTIONS - Building Reusable Security Tools 🔧
====================================================================

Welcome to Module 7! You've learned to store data and control program flow.
Now you'll learn about functions - reusable blocks of code that make your
cybersecurity scripts more organized, efficient, and maintainable.

WHAT ARE FUNCTIONS?
Functions are named blocks of code that perform specific tasks. Think of them
as specialized tools in your cybersecurity toolkit - each one designed for
a particular job that you can use whenever needed without rewriting code.

FUNCTION CONCEPTS WE'LL COVER:
- Defining and calling functions
- Parameters and arguments
- Return values and scope
- Default parameters and keyword arguments
- Documenting functions with docstrings
"""
import random # For scan_network_range simulation
from datetime import datetime # For generate_security_alert

# ============================================================================
# CONCEPT EXPLANATION: Basic Function Definition and Calling
# ============================================================================

# Define a simple function
def check_port_status_conceptual(): # Renamed for clarity
    """Check if a specific port is in the common secure ports list."""
    secure_ports = [22, 80, 443, 993, 995]
    port_to_check = 443

    if port_to_check in secure_ports:
        print(f"✅ Port {port_to_check} is a standard secure port")
    else:
        print(f"⚠️  Port {port_to_check} is not in standard secure ports list")

# Call the function
print("Calling check_port_status_conceptual():")
check_port_status_conceptual()

# Function that performs a calculation
def calculate_password_strength_conceptual(): # Renamed
    """Calculate a basic password strength score."""
    password = "SecurePass123!"
    score = 0

    if len(password) >= 8: score += 25
    if any(c.isupper() for c in password): score += 25
    if any(c.islower() for c in password): score += 25
    if any(c.isdigit() for c in password): score += 15
    if any(c in "!@#$%^&*" for c in password): score += 10

    print(f"\nPassword: {password}") # Added newline
    print(f"Strength score: {score}/100")
    return score

print("\nCalling calculate_password_strength_conceptual():") # Added newline
strength_conceptual = calculate_password_strength_conceptual()
print(f"Returned score: {strength_conceptual}")

# ============================================================================
# CONCEPT EXPLANATION: Functions with Parameters
# ============================================================================

def scan_ip_address_conceptual(ip_address, port): # Renamed
    """Simulate scanning a specific IP address and port."""
    print(f"\nScanning {ip_address}:{port}...") # Added newline
    is_open = random.choice([True, False]) # import random is at top now
    if is_open:
        print(f"✅ Port {port} is OPEN on {ip_address}")
        return "open"
    else:
        print(f"❌ Port {port} is CLOSED on {ip_address}")
        return "closed"

print("\nScanning different targets (conceptual):") # Added newline
scan_ip_address_conceptual("192.168.1.1", 22)
scan_ip_address_conceptual("10.0.0.1", 80)

def analyze_login_attempt_conceptual(username, ip_address, success, timestamp): # Renamed
    """Analyze a login attempt for security patterns."""
    print(f"\nAnalyzing login attempt (conceptual):") # Added newline
    print(f"  User: {username}, IP: {ip_address}, Success: {success}, Time: {timestamp}")
    external_ip = not ip_address.startswith(("192.168.", "10.", "172.16."))
    admin_account = "admin" in username.lower()
    risk_level = "LOW"
    if not success and external_ip: risk_level = "HIGH"
    elif not success and admin_account: risk_level = "MEDIUM"
    elif external_ip and admin_account: risk_level = "MEDIUM"
    print(f"  Risk Assessment: {risk_level}")
    return risk_level

print("\nLogin Analysis Examples (conceptual):") # Added newline
analyze_login_attempt_conceptual("john_user", "192.168.1.100", True, "2023-10-01 09:15")
analyze_login_attempt_conceptual("admin", "203.0.113.42", False, "2023-10-01 09:20")

# ============================================================================
# CONCEPT EXPLANATION: Default Parameters and Return Values
# ============================================================================

def check_system_health_conceptual(cpu_threshold=80, memory_threshold=85, disk_threshold=90): # Renamed
    """Check system health against configurable thresholds."""
    current_cpu = random.randint(30, 95)
    current_memory = random.randint(40, 90)
    current_disk = random.randint(20, 95)
    print(f"\nSystem Health Check (Thresholds: CPU={cpu_threshold}%, Mem={memory_threshold}%, Disk={disk_threshold}%)") # Added newline
    print(f"Current: CPU={current_cpu}%, Mem={current_memory}%, Disk={current_disk}%")
    issues = []
    if current_cpu > cpu_threshold: issues.append(f"High CPU: {current_cpu}%")
    if current_memory > memory_threshold: issues.append(f"High Mem: {current_memory}%")
    if current_disk > disk_threshold: issues.append(f"High Disk: {current_disk}%")
    if issues:
        print("⚠️  Issues found:")
        for issue in issues: print(f"   - {issue}")
        return issues
    else:
        print("✅ All systems healthy")
        return []

print("\nUsing default thresholds (conceptual):") # Added newline
check_system_health_conceptual()
print("\nUsing strict thresholds (conceptual):") # Added newline
check_system_health_conceptual(70, 75, 80)

# ============================================================================
# CONCEPT EXPLANATION: Multiple Return Values and Docstrings
# ============================================================================

def analyze_security_log_conceptual(log_entries_list): # Renamed arg
    """
    Analyze security log entries and return comprehensive statistics.
    Args: log_entries_list (list): List of log entry strings
    Returns: tuple: (total_entries, error_count, warning_count, critical_count, summary_dict)
    """
    # ... (implementation is fine, just using conceptual name)
    total_entries = len(log_entries_list)
    error_count, warning_count, critical_count, info_count = 0, 0, 0, 0
    for entry in log_entries_list:
        if "ERROR" in entry: error_count += 1
        elif "WARNING" in entry: warning_count += 1
        elif "CRITICAL" in entry: critical_count += 1
        elif "INFO" in entry: info_count += 1
    summary = {"total": total_entries, "critical": critical_count, "errors": error_count, "warnings": warning_count, "info": info_count}
    return total_entries, error_count, warning_count, critical_count, summary

sample_logs_conceptual = ["INFO: Login", "WARNING: High CPU", "ERROR: DB fail", "CRITICAL: Breach"]
print("\nAnalyzing security logs (conceptual):") # Added newline
total, errors, warnings, critical, summary_dict = analyze_security_log_conceptual(sample_logs_conceptual)
print(f"Total: {total}, Critical: {critical}, Errors: {errors}, Warnings: {warnings}, Summary: {summary_dict}")

# ============================================================================
# CONCEPT EXPLANATION: Variable Scope
# ============================================================================

global_threat_level_conceptual = "MEDIUM" # Renamed
def update_threat_level_conceptual(new_level): # Renamed
    global global_threat_level_conceptual
    old_level = global_threat_level_conceptual
    global_threat_level_conceptual = new_level
    print(f"Threat level updated: {old_level} -> {new_level}")

def get_security_status_conceptual(): # Renamed
    print(f"\nCurrent threat (conceptual): {global_threat_level_conceptual}") # Added newline
    local_scan_time = "2023-10-01 16:30" # This is fine as local
    print(f"Last scan (conceptual): {local_scan_time}")

print("\nScope demonstration (conceptual):") # Added newline
get_security_status_conceptual()
update_threat_level_conceptual("HIGH")
get_security_status_conceptual()

# ============================================================================
# HOW THIS APPLIES TO CYBERSECURITY ADMINISTRATION:
# ============================================================================
"""
CYBERSECURITY APPLICATIONS OF FUNCTIONS:

1. SECURITY SCANNING AND ASSESSMENT:
   - port_scan(ip, port_list): Scan multiple ports on target systems
   - vulnerability_check(system_id): Check system for known vulnerabilities
   - compliance_audit(system, policy): Verify system meets security policies

2. LOG ANALYSIS AND MONITORING:
   - parse_log_entry(line): Extract structured data from log lines
   - detect_anomalies(user_activity): Identify unusual user behavior
   - correlate_events(event_list): Find related security events

3. INCIDENT RESPONSE:
   - isolate_system(system_id): Quarantine compromised systems
   - collect_evidence(incident_id): Gather forensic information
   - notify_stakeholders(incident_type, severity): Send alerts and updates

4. USER AND ACCESS MANAGEMENT:
   - validate_password(password, policy): Check password strength
   - check_permissions(user, resource): Verify access rights
   - audit_user_activity(username, timeframe): Review user actions

5. NETWORK SECURITY:
   - analyze_traffic(packet_data): Examine network communications
   - update_firewall_rules(rule_set): Modify security configurations
   - monitor_bandwidth(interface): Track network utilization

6. AUTOMATION AND ORCHESTRATION:
   - backup_system(system_list): Automate data protection
   - patch_management(system_group): Deploy security updates
   - generate_reports(data_source, format): Create security documentation
"""

def validate_ip_address_conceptual(ip): # Renamed
    # ... (implementation is fine, printing is fine for conceptual)
    parts = ip.split('.')
    if len(parts) != 4: return {"valid": False, "reason": "Invalid format", "category": "invalid"}
    try: octets = [int(part) for part in parts]
    except ValueError: return {"valid": False, "reason": "Non-numeric octets", "category": "invalid"}
    if not all(0 <= octet <= 255 for octet in octets): return {"valid": False, "reason": "Octet out of range", "category": "invalid"}
    first_octet = octets[0]
    if first_octet == 10 or (first_octet == 172 and 16 <= octets[1] <= 31) or (first_octet == 192 and octets[1] == 168): category = "private"
    elif first_octet == 127: category = "loopback"
    elif 224 <= first_octet <= 239: category = "multicast"
    else: category = "public"
    return {"valid": True, "reason": "Valid IP address", "category": category}


def security_score_calculator_conceptual(system_info): # Renamed
    # ... (implementation is fine, printing is fine for conceptual)
    score = 0
    if system_info.get("firewall_enabled", False): score += 20
    if system_info.get("antivirus_active", False): score += 15
    days_since_update = system_info.get("days_since_update", 999)
    if days_since_update <= 7: score += 20
    elif days_since_update <= 30: score += 10
    if system_info.get("password_policy_enforced", False): score += 15
    if system_info.get("disk_encrypted", False): score += 15
    if system_info.get("access_control_enabled", False): score += 15
    return min(score, 100)

print("\nIP Address Validation Examples (Conceptual):") # Added newline
test_ips_conceptual = ["192.168.1.1", "10.0.0.256", "invalid.ip", "203.0.113.42"]
for ip_c in test_ips_conceptual: # Renamed loop var
    result_c = validate_ip_address_conceptual(ip_c)
    status_c = "✅" if result_c["valid"] else "❌"
    print(f"{status_c} {ip_c}: {result_c['reason']} ({result_c['category']})")

print("\nSecurity Score Examples (Conceptual):") # Added newline
test_systems_conceptual = [{"name": "Secure Server", "firewall_enabled": True, "antivirus_active": True, "days_since_update": 3, "password_policy_enforced": True, "disk_encrypted": True, "access_control_enabled": True}, {"name": "Basic Workstation", "firewall_enabled": True, "antivirus_active": False, "days_since_update": 45, "password_policy_enforced": False, "disk_encrypted": False, "access_control_enabled": True}]
for system_c in test_systems_conceptual: # Renamed loop var
    score_c = security_score_calculator_conceptual(system_c)
    grade_c = "A" if score_c >= 90 else "B" if score_c >= 80 else "C" if score_c >= 70 else "D" if score_c >= 60 else "F"
    print(f"{system_c['name']}: {score_c}/100 (Grade: {grade_c})")

# ============================================================================
# WARM-UP EXERCISES: Practice Creating Functions
# ============================================================================

# Exercise 1: Simple function with no parameters
"""
PRACTICE: System Status Reporter

You need a quick way to report the basic status of a system.
Create a reusable piece of code (a function) that, when called,
always reports "System status: Online".

(Define this as a function named `check_system_status_warmup` that returns the status string.)
"""
# TODO: Define the function `check_system_status_warmup`.
# TODO: Inside the function, return the string "System status: Online".
def check_system_status_warmup():
    pass # Placeholder


# Exercise 2: Function with one parameter
"""
PRACTICE: Personalized Greeting

To make your security tools more user-friendly, you want to greet users by name.
Develop a component that can take any username as input and produce a
personalized greeting: "Hello, [username]".

(Define this as a function named `greet_user_warmup` that accepts one
argument (the username) and returns the greeting string.)
"""
# TODO: Define the function `greet_user_warmup` that takes one parameter (e.g., `username`).
# TODO: Inside the function, construct and return the greeting string "Hello, [username]".
def greet_user_warmup(username):
    pass # Placeholder


# Exercise 3: Function that returns a value
"""
PRACTICE: Security Score Calculator

A simple way to assess overall security is to subtract the number of identified
threats from the number of effective defenses. Create a tool that performs
this calculation. It should take the count of threats and defenses as input
and output the resulting security score.

(Define this as a function named `calculate_security_score_warmup` that
accepts two arguments: `threats` and `defenses`. It should return their difference.)
"""
# TODO: Define the function `calculate_security_score_warmup` with two parameters (e.g., `threats`, `defenses`).
# TODO: Calculate `defenses - threats` and return the result.
def calculate_security_score_warmup(threats, defenses):
    pass # Placeholder


# Exercise 4: Function with conditional logic
"""
PRACTICE: Port Assessor

Different network ports are used for different services. You need a utility
that can identify common services based on their port number.
- Port 22 is typically "SSH port".
- Port 80 is typically "HTTP port".
- Any other port should be labeled "Unknown port".
Your utility should take a port number and return its assessment.

(Define this as a function named `assess_port_warmup` that accepts a
`port_number` and returns the corresponding string assessment.)
"""
# TODO: Define the function `assess_port_warmup` that takes `port_number` as a parameter.
# TODO: Use conditional logic (if/elif/else) to check the port_number.
# TODO: Return "SSH port", "HTTP port", or "Unknown port" accordingly.
def assess_port_warmup(port_number):
    pass # Placeholder


# ============================================================================
# YOUR MAIN EXERCISE: Build Modular Security Tools
# ============================================================================
"""
CHALLENGE: MODULAR SECURITY TOOLKIT DEVELOPMENT

You're tasked with creating a versatile security toolkit. This toolkit will consist of
several specialized functions (modules) that can be used independently or together for
various security operations.

TOOL 1: PASSWORD SECURITY ANALYZER
   Develop a function to analyze the strength of a given password string.
   The analysis should be based on the following criteria, each contributing to a total score (max 100):
   - Is the password at least 8 characters long? (Adds 20 points)
   - Does it contain at least one uppercase letter? (Adds 20 points)
   - Does it contain at least one lowercase letter? (Adds 20 points)
   - Does it include at least one number? (Adds 20 points)
   - Does it use any special characters from the set "!@#$%^&*" (Adds 20 points)

   This function, named `analyze_password`, should take the `password_string` as input.
   It must return a dictionary containing:
   - "score": The calculated numerical score (0-100).
   - "strength": A text assessment ("Weak" for scores 0-40, "Fair" for 41-60,
                 "Good" for 61-80, "Strong" for 81-100).
   - "recommendations": A list of text strings suggesting improvements for any unmet criteria
     (e.g., "Add uppercase letters.", "Ensure password is at least 8 characters.").

TOOL 2: NETWORK RECONNAISSANCE SCANNER
   Create a function for basic network scanning. This function,
   `scan_network_range(network_base, start_host, end_host, target_port=80)`,
   will simulate checking a specific port on a range of IP addresses.
   - `network_base`: The first part of the IP, like "192.168.1".
   - `start_host`, `end_host`: Define the range for the last part of the IP (e.g., 1 to 3).
   - `target_port`: The port to check (defaults to 80 if not specified).
   For each IP in the range, your function should simulate a scan: randomly decide if the
   `target_port` is "open" or "closed".
   The function should return a dictionary: `{"open_hosts": [list_of_IPs_with_open_port],
   "closed_hosts": [list_of_IPs_with_closed_port]}`.

TOOL 3: SECURITY LOG PROCESSOR
   Develop a function, `parse_security_event(log_line_string)`, to process individual lines
   from a security log. Assume log lines follow the format:
   "YYYY-MM-DD HH:MM:SS SEVERITY Event description"
   (Example: "2023-10-01 14:30:15 WARNING Multiple failed login attempts")
   The SEVERITY is always a single word.
   This function must return a dictionary with keys "timestamp", "severity", and "description".
   If a log line is malformed (e.g., doesn't have enough parts to extract timestamp, severity, and description),
   it should return `{"timestamp": "Unknown", "severity": "ERROR",
   "description": "Malformed log entry: [original_log_line]"}`.

TOOL 4: INCIDENT ALERT GENERATOR
   Create a function `generate_security_alert(event_type, severity, affected_systems_list, details_string)`
   to format and prepare security alerts.
   - `severity` can be "LOW", "MEDIUM", "HIGH", or "CRITICAL".
   The function should first generate a unique `alert_id` (e.g., "ALERT-YYYYMMDD-HHMMSSMS",
   like ALERT-20231028-153000123).
   Then, it should prepare a detailed, multi-line alert message string. This message should include the alert ID,
   event type, timestamp (current time when the alert is generated), severity (with an icon: 🟢 LOW, 🟡 MEDIUM, 🟠 HIGH, 🔴 CRITICAL),
   a list of affected systems, and the details string. This formatted message should be printed to the console.
   The function must return a dictionary containing the `alert_id` and the `formatted_message` string.

INTEGRATION: SECURITY ASSESSMENT SCRIPT
   Finally, create a main function `run_security_assessment()` that demonstrates the use of your toolkit:
   1. Analyze these passwords: "password", "SecurePass123!", and "MyP@ssw0rd2023". Store all results.
   2. Perform a network scan for the base "192.168.1", covering hosts 1 through 3, on port 80. Store the result.
   3. Process these log lines:
      - "2023-10-01 14:30:15 INFO User login successful"
      - "2023-10-01 14:35:22 WARNING Multiple failed login attempts"
      - "Malformed log" (a deliberately malformed entry)
      Store all parsed log data.
   4. Based on the findings:
      - Generate an alert if any analyzed password has a "Weak" or "Fair" strength.
      - Generate an alert if any processed log event has a "CRITICAL", "HIGH", or "ERROR" severity.
      - Generate an alert if the network scan found any hosts with open ports.
      Store all generated alert dictionaries.
   5. The `run_security_assessment` function should also print summaries of its findings at each step
      (e.g., "Password analysis complete...", "Network scan found X open hosts..."). These prints are for
      illustrative purposes during execution.
   6. This main function must return a dictionary summarizing all collected data:
      `{"password_analysis_results": [...], "network_scan_results": {...},
      "parsed_log_results": [...], "generated_alerts_details": [...]}`.
"""

# YOUR CODE GOES HERE
# ============================================================================


# PART 1: Password Security Function
# TODO: Implement analyze_password function
def analyze_password(password_string): # Renamed arg for clarity
    # Placeholder: Actual logic to be implemented by the user
    score = 0
    recommendations = []
    strength = "Weak"
    if len(password_string) >= 8: score += 20
    else: recommendations.append("Ensure password is at least 8 characters.")
    if any(c.isupper() for c in password_string): score += 20
    else: recommendations.append("Add uppercase letters.")
    # ... (add other checks for lowercase, numbers, special characters) ...

    # Determine strength category based on score
    if score <= 40: strength = "Weak"
    elif score <= 60: strength = "Fair"
    elif score <= 80: strength = "Good"
    else: strength = "Strong"

    return {"score": score, "strength": strength, "recommendations": recommendations}

# PART 2: Network Scanner Function
# TODO: Implement scan_network_range function
def scan_network_range(network_base, start_host, end_host, target_port=80):
    # Placeholder: Actual logic to be implemented by the user
    # import random # Moved to top
    open_hosts = []
    closed_hosts = []
    for i in range(start_host, end_host + 1):
        ip = f"{network_base}.{i}"
        if random.choice([True, False]): open_hosts.append(ip)
        else: closed_hosts.append(ip)
    return {"open_hosts": open_hosts, "closed_hosts": closed_hosts}

# PART 3: Log Analysis Function
# TODO: Implement parse_security_event function
def parse_security_event(log_line_string): # Renamed arg
    # Placeholder
    try:
        parts = log_line_string.split(" ", 2)
        if len(parts) < 3:
            # Attempt to find severity if it's a single word log_line_string
            possible_severities = ["INFO", "WARNING", "ERROR", "CRITICAL"]
            severity_found = "UNKNOWN"
            for sev in possible_severities:
                if log_line_string.upper().startswith(sev):
                    severity_found = sev
                    break
            return {"timestamp": "Unknown", "severity": severity_found if severity_found != "UNKNOWN" else "ERROR", "description": f"Malformed log entry: {log_line_string}"}

        timestamp = f"{parts[0]} {parts[1]}"

        # More robust severity parsing
        remaining_part = parts[2]
        severity = "UNKNOWN" # Default
        description = remaining_part

        # Check common severity keywords at the start of the remaining part
        # Case-insensitive check for severity
        possible_severities = ["INFO", "WARNING", "ERROR", "CRITICAL"]
        for sev_keyword in possible_severities:
            if remaining_part.upper().startswith(sev_keyword):
                # Check if the keyword is followed by a space or is the whole remaining string
                if len(remaining_part) == len(sev_keyword) or (len(remaining_part) > len(sev_keyword) and remaining_part[len(sev_keyword)].isspace()):
                    severity = sev_keyword
                    description = remaining_part[len(sev_keyword):].lstrip()
                    break

        return {"timestamp": timestamp, "severity": severity, "description": description}
    except Exception: # Catch any other parsing error
        return {"timestamp": "Unknown", "severity": "ERROR", "description": f"Malformed log entry: {log_line_string}"}


# PART 4: Security Alert Function
# TODO: Implement generate_security_alert function
def generate_security_alert(event_type, severity, affected_systems_list, details_string): # Renamed args
    # from datetime import datetime # Moved to top
    now = datetime.now()
    alert_id = f"ALERT-{now.strftime('%Y%m%d-%H%M%S%f')[:-3]}" # Added microseconds for uniqueness
    severity_icons = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
    icon = severity_icons.get(severity.upper(), "⚪️")

    formatted_message_lines = [
        f"\n{'='*60}",
        f"{icon} SECURITY ALERT - {severity.upper()} SEVERITY",
        f"{'='*60}",
        f"Alert ID: {alert_id}",
        f"Event Type: {event_type}",
        f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Affected Systems: {', '.join(affected_systems_list)}",
        f"Details: {details_string}",
        f"{'='*60}"
    ]
    formatted_message = "\n".join(formatted_message_lines)
    # The problem asks this function to print, but for better testability,
    # the printing will be handled by run_security_assessment.
    # This function will return the data needed for printing.
    return {"alert_id": alert_id, "formatted_message": formatted_message}


# PART 5: Integration Test Function
# TODO: Implement run_security_assessment function
def run_security_assessment():
    # This function will call the other functions you've defined.
    # Store their results and then return the final summary dictionary.
    password_analysis_results = []
    network_scan_results = {}
    parsed_log_results = []
    generated_alerts_details = [] # Store dicts from generate_security_alert

    print("🔒 COMPREHENSIVE SECURITY ASSESSMENT")
    print("="*50)

    # Test passwords
    print("\n1. PASSWORD STRENGTH ANALYSIS:")
    print("-" * 30)
    test_passwords = ["password", "SecurePass123!", "MyP@ssw0rd2023"]
    for pwd in test_passwords:
        result = analyze_password(pwd)
        password_analysis_results.append(result)
        print(f"Password: {'*' * len(pwd)} | Score: {result['score']}/100 | Strength: {result['strength']}")
        if result['recommendations']:
            print(f"  Recommendations: {', '.join(result['recommendations'])}")

    # Network scan
    print("\n2. NETWORK SCAN RESULTS:")
    print("-" * 30)
    network_scan_results = scan_network_range("192.168.1", 1, 3, target_port=80)
    print(f"Open hosts (port 80): {network_scan_results['open_hosts']}")
    print(f"Closed hosts: {network_scan_results['closed_hosts']}")

    # Log analysis
    print("\n3. LOG ANALYSIS:")
    print("-" * 30)
    sample_log_lines = [
        "2023-10-01 14:30:15 INFO User login successful",
        "2023-10-01 14:35:22 WARNING Multiple failed login attempts",
        "Malformed log" # This will test the error handling in parse_security_event
    ]
    for log_line in sample_log_lines:
        parsed = parse_security_event(log_line)
        parsed_log_results.append(parsed)
        print(f"[{parsed['severity']}] {parsed['timestamp']}: {parsed['description']}")

    # Generate alerts
    print("\n4. GENERATING ALERTS:")
    print("-" * 30)
    if any(p_res["strength"] in ["Weak", "Fair"] for p_res in password_analysis_results):
        alert_data = generate_security_alert("Weak Password(s) Detected", "MEDIUM", ["User Accounts"], "One or more users have weak or fair passwords.")
        print(alert_data["formatted_message"]) # Print the formatted message here
        generated_alerts_details.append(alert_data)

    if any(log_res["severity"] in ["CRITICAL", "HIGH", "ERROR"] for log_res in parsed_log_results if log_res): # Check if log_res is not None
        alert_data = generate_security_alert("High Severity Log Event", "HIGH", ["System Logs"], "Critical, High, or Error level events found in logs.")
        print(alert_data["formatted_message"])
        generated_alerts_details.append(alert_data)

    if network_scan_results.get("open_hosts"):
         alert_data = generate_security_alert("Open Ports Discovered", "MEDIUM", network_scan_results["open_hosts"], "Network scan found open ports.")
         print(alert_data["formatted_message"])
         generated_alerts_details.append(alert_data)

    # Summary report printed by run_security_assessment
    print(f"\n5. ASSESSMENT SUMMARY (Illustrative Print):")
    print("-" * 30)
    print(f"Passwords analyzed: {len(password_analysis_results)}")
    print(f"Network hosts scanned: {len(network_scan_results.get('open_hosts',[])) + len(network_scan_results.get('closed_hosts',[]))}")
    print(f"Log entries processed: {len(parsed_log_results)}")
    print(f"Alerts generated: {len(generated_alerts_details)}")

    return {
        "password_analysis_results": password_analysis_results,
        "network_scan_results": network_scan_results,
        "parsed_log_results": parsed_log_results,
        "generated_alerts_details": generated_alerts_details
    }

# Run the comprehensive assessment if the script is run directly (for user's own testing)
if __name__ == "__main__":
    run_security_assessment()


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_functions(): # Renamed
    """Test the warm-up functions."""
    print("--- Testing Warm-up Exercises ---")
    passed_count = 0
    # Test 1
    try:
        assert check_system_status_warmup() == "System status: Online", "Warmup 1 Failed"
        print("✅ Warm-up 1 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 1 FAILED: {e}")
    # Test 2
    try:
        assert greet_user_warmup("tester") == "Hello, tester", "Warmup 2 Failed"
        print("✅ Warm-up 2 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 2 FAILED: {e}")
    # Test 3
    try:
        assert calculate_security_score_warmup(2, 10) == 8, "Warmup 3 Failed"
        print("✅ Warm-up 3 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 3 FAILED: {e}")
    # Test 4
    try:
        assert assess_port_warmup(22) == "SSH port", "Warmup 4 Failed: SSH"
        assert assess_port_warmup(80) == "HTTP port", "Warm-up 4 Failed: HTTP"
        assert assess_port_warmup(100) == "Unknown port", "Warm-up 4 Failed: Unknown"
        print("✅ Warm-up 4 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 4 FAILED: {e}")

    print(f"Warm-up Score: {passed_count}/4 passed.")
    return passed_count == 4

def test_main_security_toolkit_functions(): # Renamed
    """Test function to verify your main exercise function implementations are correct."""
    print("\n--- Testing Main Exercise Functions ---")
    main_passed = True

    # Test analyze_password
    try:
        res_strong = analyze_password("Str0ngP@ss!") # Example of strong password
        assert isinstance(res_strong, dict) and "score" in res_strong and "strength" in res_strong and "recommendations" in res_strong, \
            "analyze_password did not return a dictionary with all required keys."
        # A more thorough test would check specific scores/strengths/recommendations for various inputs.
        print("✅ Main Test (analyze_password): PASSED (structure check)")
    except (NameError, AssertionError, Exception) as e:
        print(f"❌ Main Test (analyze_password): FAILED - {e}")
        main_passed = False

    # Test scan_network_range
    try:
        res_scan = scan_network_range("10.0.0", 1, 2)
        assert isinstance(res_scan, dict) and "open_hosts" in res_scan and "closed_hosts" in res_scan, \
            "scan_network_range did not return a dictionary with 'open_hosts' and 'closed_hosts' keys."
        print("✅ Main Test (scan_network_range): PASSED (structure check)")
    except (NameError, AssertionError, Exception) as e:
        print(f"❌ Main Test (scan_network_range): FAILED - {e}")
        main_passed = False

    # Test parse_security_event
    try:
        res_log_valid = parse_security_event("2023-01-01 10:00:00 INFO Test event")
        assert isinstance(res_log_valid, dict) and res_log_valid.get("severity") == "INFO", \
            "parse_security_event valid log test failed."
        res_log_invalid = parse_security_event("Invalid log") # Test malformed
        assert isinstance(res_log_invalid, dict) and res_log_invalid.get("severity") == "ERROR", \
            "parse_security_event invalid log test failed (should default to ERROR severity or similar)."
        print("✅ Main Test (parse_security_event): PASSED (basic checks)")
    except (NameError, AssertionError, Exception) as e:
        print(f"❌ Main Test (parse_security_event): FAILED - {e}")
        main_passed = False

    # Test generate_security_alert
    try:
        res_alert = generate_security_alert("Test Event", "HIGH", ["system1"], "Test details")
        assert isinstance(res_alert, dict) and "alert_id" in res_alert and "formatted_message" in res_alert, \
            "generate_security_alert did not return a dictionary with 'alert_id' and 'formatted_message'."
        assert res_alert["alert_id"].startswith("ALERT-"), "generate_security_alert: alert_id format error."
        assert "HIGH SEVERITY" in res_alert["formatted_message"], "generate_security_alert: message format error (severity)."
        print("✅ Main Test (generate_security_alert): PASSED (structure and basic content check)")
    except (NameError, AssertionError, Exception) as e:
        print(f"❌ Main Test (generate_security_alert): FAILED - {e}")
        main_passed = False

    # Test run_security_assessment (structure of returned dict)
    try:
        summary = run_security_assessment()
        assert isinstance(summary, dict), "run_security_assessment should return a dictionary."
        expected_keys = ["password_analysis_results", "network_scan_results", "parsed_log_results", "generated_alerts_details"]
        for k in expected_keys:
            assert k in summary, f"run_security_assessment summary missing key: {k}"
            assert isinstance(summary[k], list) or isinstance(summary[k], dict), f"run_security_assessment: value for {k} has unexpected type."
        print("✅ Main Test (run_security_assessment): PASSED (structure check)")
    except (NameError, AssertionError, Exception) as e:
        print(f"❌ Main Test (run_security_assessment): FAILED - {e}")
        main_passed = False

    if main_passed:
        print("\n🎉 All Main Exercise function basic tests passed!")
    else:
        print("\n❌ Some Main Exercise function tests FAILED.")
    return main_passed

def run_all_tests(): # Renamed from test_functions
    """Run all tests for Module 7."""
    warmup_ok = test_warmup_functions()
    main_ok = test_main_security_toolkit_functions()

    if warmup_ok and main_ok:
        print("\n✅ CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python functions!")
        print("Ready for Module 8: File I/O")
    else:
        print("\n📚 Keep practicing! Review the failed tests or messages above.")

# Run the tests
run_all_tests() # Updated call

# ============================================================================
# WHAT'S NEXT?
# ============================================================================
"""
Excellent work completing Module 7! Here's what you learned:

✅ Defining and calling functions for code organization
✅ Using parameters and arguments to make functions flexible
✅ Returning values and handling multiple return values
✅ Default parameters and keyword arguments
✅ Variable scope and global vs local variables
✅ Documenting functions with docstrings
✅ Building modular cybersecurity tools

CYBERSECURITY SKILLS GAINED:
- Password strength analysis and validation
- Network scanning and port discovery
- Log parsing and security event analysis
- Automated alert generation and incident response
- Modular security tool development
- Code reusability and maintainability

NEXT MODULE: 08_file_io.py
In the next module, you'll learn File Input/Output - how to read configuration
files, parse security logs, write reports, and work with data files that are
essential for cybersecurity administration and automation!

You're building professional cybersecurity programming capabilities! 🛠️📁
"""
