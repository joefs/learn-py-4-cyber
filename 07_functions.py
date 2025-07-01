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
PRACTICE: Basic Function

Write a function `check_system_status_warmup()` that returns the string
"System status: Online".
"""
# TODO: Implement the function check_system_status_warmup
def check_system_status_warmup():
    pass # Placeholder


# Exercise 2: Function with one parameter
"""
PRACTICE: Function with Parameter

Write a function `greet_user_warmup(username)` that accepts a username string.
The function should return a personalized greeting string: "Hello, [username]".
"""
# TODO: Implement the function greet_user_warmup
def greet_user_warmup(username):
    pass # Placeholder


# Exercise 3: Function that returns a value
"""
PRACTICE: Function with Return Value

Write a function `calculate_security_score_warmup(threats, defenses)` that
accepts two integers: `threats` and `defenses`.
The function should calculate and return the security score using the formula:
score = defenses - threats.
"""
# TODO: Implement the function calculate_security_score_warmup
def calculate_security_score_warmup(threats, defenses):
    pass # Placeholder


# Exercise 4: Function with conditional logic
"""
PRACTICE: Function with Logic

Write a function `assess_port_warmup(port_number)` that accepts an integer `port_number`.
It should return:
- "SSH port" if port_number is 22
- "HTTP port" if port_number is 80
- "Unknown port" for any other port_number.
"""
# TODO: Implement the function assess_port_warmup
def assess_port_warmup(port_number):
    pass # Placeholder


# ============================================================================
# YOUR MAIN EXERCISE: Build Modular Security Tools
# ============================================================================
"""
MODULAR SECURITY TOOLKIT DEVELOPMENT

You are building a comprehensive security toolkit that can be reused across different
security operations. The toolkit should provide modular functions for common cybersecurity
tasks including password analysis, network reconnaissance, log processing, and incident alerting.

PASSWORD SECURITY ANALYZER:
Create a function named `analyze_password(password_string)` that evaluates password strength.
Criteria:
- Minimum length of 8 characters (20 points)
- Presence of uppercase letters (20 points)
- Presence of lowercase letters (20 points)
- Inclusion of numbers (20 points)
- Use of special characters from "!@#$%^&*" (20 points)

Return a dictionary with:
- "score": (integer, 0-100)
- "strength": (string: "Weak" (0-40), "Fair" (41-60), "Good" (61-80), "Strong" (81-100))
- "recommendations": (list of strings for unmet criteria, e.g., "Add uppercase letters.")

NETWORK RECONNAISSANCE SCANNER:
Create a function `scan_network_range(network_base, start_host, end_host, target_port=80)`.
`network_base` is like "192.168.1". `start_host` and `end_host` define the range.
Simulate scanning: for each IP, randomly decide if `target_port` is open or closed.
Return a dictionary: {"open_hosts": [list_of_ips], "closed_hosts": [list_of_ips]}.

SECURITY LOG PROCESSOR:
Create a function `parse_security_event(log_line_string)`.
Log format: "YYYY-MM-DD HH:MM:SS SEVERITY Event description"
   (Note: SEVERITY is a single word, then a space, then description)
   Example: "2023-10-01 14:30:15 WARNING Multiple failed login attempts"
Return a dictionary: {"timestamp": "YYYY-MM-DD HH:MM:SS", "severity": "SEVERITY", "description": "Event description"}.
If malformed (e.g., not enough parts), return:
  {"timestamp": "Unknown", "severity": "ERROR", "description": "Malformed log entry: [original_log_line]"}.

INCIDENT ALERT GENERATOR:
Create a function `generate_security_alert(event_type, severity, affected_systems_list, details_string)`.
`severity` can be "LOW", "MEDIUM", "HIGH", "CRITICAL".
Generate an `alert_id` like "ALERT-YYYYMMDD-HHMMSSMS" (e.g., ALERT-20231028-153000123456).
The function should print a formatted alert message to the console (as specified in the original problem).
Return a dictionary:
- "alert_id": (string)
- "formatted_message": (string, the same comprehensive alert message that was printed).

INTEGRATED SECURITY ASSESSMENT (Main Function):
Create `run_security_assessment()` that uses the functions above.
1. Test passwords: "password", "SecurePass123!", "MyP@ssw0rd2023". Store results.
2. Scan network: "192.168.1", hosts 1-3, port 80. Store results.
3. Process logs:
   - "2023-10-01 14:30:15 INFO User login successful"
   - "2023-10-01 14:35:22 WARNING Multiple failed login attempts"
   - "Malformed log"
   Store parsed logs.
4. Generate alerts:
   - If any password is "Weak" or "Fair".
   - If any critical/high severity logs are found.
   - If any hosts are found with open ports in the scan.
   Store alert dictionaries.
5. The `run_security_assessment` function should print its step-by-step findings/summaries
   as described in the original problem for illustrative purposes.
6. Finally, `run_security_assessment` should return a summary dictionary containing:
   - "password_analysis_results": list of results from analyze_password
   - "network_scan_results": result from scan_network_range
   - "parsed_log_results": list of results from parse_security_event
   - "generated_alerts_details": list of alert dictionaries from generate_security_alert
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
    # ... (add other checks) ...
    if score > 80: strength = "Strong" # Simplified strength logic for placeholder
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
    parts = log_line_string.split(" ", 2)
    if len(parts) < 3:
        return {"timestamp": "Unknown", "severity": "ERROR", "description": f"Malformed log entry: {log_line_string}"}
    timestamp = f"{parts[0]} {parts[1]}"
    severity_desc = parts[2].split(" ", 1)
    severity = severity_desc[0]
    description = severity_desc[1] if len(severity_desc) > 1 else ""
    return {"timestamp": timestamp, "severity": severity, "description": description}


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
    print(formatted_message) # As per problem spec, this function prints
    return {"alert_id": alert_id, "formatted_message": formatted_message}


# PART 5: Integration Test Function
# TODO: Implement run_security_assessment function
def run_security_assessment():
    print("🔒 COMPREHENSIVE SECURITY ASSESSMENT")
    # ... (rest of the function as provided, ensuring it calls the above and returns the summary dict) ...
    password_analysis_results = [analyze_password(p) for p in ["password", "SecurePass123!", "MyP@ssw0rd2023"]]
    network_scan_results = scan_network_range("192.168.1", 1, 3, target_port=80)
    log_lines = ["2023-10-01 14:30:15 INFO User login successful", "2023-10-01 14:35:22 WARNING Multiple failed login attempts", "Malformed log"]
    parsed_log_results = [parse_security_event(log) for log in log_lines]
    generated_alerts_details = []
    # Simplified alert generation logic for placeholder
    if any(p_res["strength"] in ["Weak", "Fair"] for p_res in password_analysis_results):
        generated_alerts_details.append(generate_security_alert("Weak Password Detected", "MEDIUM", ["User Accounts"], "One or more weak passwords found."))
    # ... (other prints and logic from original) ...

    # Illustrative prints from original problem
    print("\n1. PASSWORD STRENGTH ANALYSIS:")
    for res in password_analysis_results: print(f" - Score: {res['score']}, Strength: {res['strength']}")
    print("\n2. NETWORK SCAN RESULTS:")
    print(f" - Open Hosts: {network_scan_results['open_hosts']}")
    print("\n3. LOG ANALYSIS:")
    for res in parsed_log_results: print(f" - Severity: {res['severity']}, Desc: {res['description']}")
    print("\n4. GENERATED ALERTS (details in console above):")
    for alert_detail in generated_alerts_details: print(f" - Alert ID: {alert_detail['alert_id']}")

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
        assert check_system_status_warmup() == "System status: Online", "Warm-up 1 Failed"
        print("✅ Warm-up 1 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 1 FAILED: {e}")
    # Test 2
    try:
        assert greet_user_warmup("tester") == "Hello, tester", "Warm-up 2 Failed"
        print("✅ Warm-up 2 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 2 FAILED: {e}")
    # Test 3
    try:
        assert calculate_security_score_warmup(2, 10) == 8, "Warm-up 3 Failed"
        print("✅ Warm-up 3 PASSED")
        passed_count += 1
    except (NameError, AssertionError) as e: print(f"❌ Warm-up 3 FAILED: {e}")
    # Test 4
    try:
        assert assess_port_warmup(22) == "SSH port", "Warm-up 4 Failed: SSH"
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
        res_strong = analyze_password("Str0ngP@ss!")
        assert isinstance(res_strong, dict) and res_strong.get("score") is not None, "analyze_password strong test failed (structure/score)"
        res_weak = analyze_password("pass")
        assert isinstance(res_weak, dict) and res_weak.get("score") is not None, "analyze_password weak test failed (structure/score)"
        print("✅ Main Test (analyze_password): PASSED")
    except (NameError, AssertionError, Exception) as e: # Catch generic for robustness
        print(f"❌ Main Test (analyze_password): FAILED - {e}")
        main_passed = False

    # Test scan_network_range
    try:
        res_scan = scan_network_range("10.0.0", 1, 2)
        assert isinstance(res_scan, dict) and "open_hosts" in res_scan and "closed_hosts" in res_scan, "scan_network_range test failed (structure)"
        print("✅ Main Test (scan_network_range): PASSED")
    except (NameError, AssertionError, Exception) as e:
        print(f"❌ Main Test (scan_network_range): FAILED - {e}")
        main_passed = False

    # Test parse_security_event
    try:
        res_log_valid = parse_security_event("2023-01-01 10:00:00 INFO Test event")
        assert isinstance(res_log_valid, dict) and res_log_valid.get("severity") == "INFO", "parse_security_event valid log test failed"
        res_log_invalid = parse_security_event("Invalid log")
        assert isinstance(res_log_invalid, dict) and res_log_invalid.get("severity") == "ERROR", "parse_security_event invalid log test failed"
        print("✅ Main Test (parse_security_event): PASSED")
    except (NameError, AssertionError, Exception) as e:
        print(f"❌ Main Test (parse_security_event): FAILED - {e}")
        main_passed = False

    # Test generate_security_alert
    try:
        res_alert = generate_security_alert("Test Event", "HIGH", ["system1"], "Test details")
        assert isinstance(res_alert, dict) and "alert_id" in res_alert and "formatted_message" in res_alert, "generate_security_alert test failed (structure)"
        assert res_alert["alert_id"].startswith("ALERT-"), "generate_security_alert: alert_id format error."
        print("✅ Main Test (generate_security_alert): PASSED")
    except (NameError, AssertionError, Exception) as e:
        print(f"❌ Main Test (generate_security_alert): FAILED - {e}")
        main_passed = False

    # Test run_security_assessment (structure of returned dict)
    try:
        summary = run_security_assessment() # Call the main driver
        assert isinstance(summary, dict), "run_security_assessment should return a dictionary."
        expected_keys = ["password_analysis_results", "network_scan_results", "parsed_log_results", "generated_alerts_details"]
        for k in expected_keys:
            assert k in summary, f"run_security_assessment summary missing key: {k}"
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
