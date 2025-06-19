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

# ============================================================================
# CONCEPT EXPLANATION: Basic Function Definition and Calling
# ============================================================================

print("=== BASIC FUNCTION DEFINITION AND CALLING ===")
print()

# Define a simple function
def check_port_status():
    """Check if a specific port is in the common secure ports list."""
    secure_ports = [22, 80, 443, 993, 995]
    port_to_check = 443
    
    if port_to_check in secure_ports:
        print(f"✅ Port {port_to_check} is a standard secure port")
    else:
        print(f"⚠️  Port {port_to_check} is not in standard secure ports list")

# Call the function
print("Calling check_port_status():")
check_port_status()
print()

# Function that performs a calculation
def calculate_password_strength():
    """Calculate a basic password strength score."""
    password = "SecurePass123!"
    score = 0
    
    if len(password) >= 8:
        score += 25
    if any(c.isupper() for c in password):
        score += 25
    if any(c.islower() for c in password):
        score += 25
    if any(c.isdigit() for c in password):
        score += 15
    if any(c in "!@#$%^&*" for c in password):
        score += 10
    
    print(f"Password: {password}")
    print(f"Strength score: {score}/100")
    return score

print("Calling calculate_password_strength():")
strength = calculate_password_strength()
print(f"Returned score: {strength}")
print()

# ============================================================================
# CONCEPT EXPLANATION: Functions with Parameters
# ============================================================================

print("=== FUNCTIONS WITH PARAMETERS ===")
print()

def scan_ip_address(ip_address, port):
    """Simulate scanning a specific IP address and port."""
    print(f"Scanning {ip_address}:{port}...")
    
    # Simulate scan results (in real scenario, this would actually scan)
    import random
    is_open = random.choice([True, False])
    
    if is_open:
        print(f"✅ Port {port} is OPEN on {ip_address}")
        return "open"
    else:
        print(f"❌ Port {port} is CLOSED on {ip_address}")
        return "closed"

# Call function with different parameters
print("Scanning different targets:")
result1 = scan_ip_address("192.168.1.1", 22)
result2 = scan_ip_address("10.0.0.1", 80)
result3 = scan_ip_address("172.16.0.1", 443)
print()

def analyze_login_attempt(username, ip_address, success, timestamp):
    """Analyze a login attempt for security patterns."""
    print(f"Analyzing login attempt:")
    print(f"  User: {username}")
    print(f"  IP: {ip_address}")
    print(f"  Success: {success}")
    print(f"  Time: {timestamp}")
    
    # Security analysis
    external_ip = not ip_address.startswith(("192.168.", "10.", "172.16."))
    admin_account = "admin" in username.lower()
    
    risk_level = "LOW"
    if not success and external_ip:
        risk_level = "HIGH"
    elif not success and admin_account:
        risk_level = "MEDIUM"
    elif external_ip and admin_account:
        risk_level = "MEDIUM"
    
    print(f"  Risk Assessment: {risk_level}")
    return risk_level

# Analyze different login scenarios
print("Login Analysis Examples:")
analyze_login_attempt("john_user", "192.168.1.100", True, "2023-10-01 09:15")
print()
analyze_login_attempt("admin", "203.0.113.42", False, "2023-10-01 09:20")
print()

# ============================================================================
# CONCEPT EXPLANATION: Default Parameters and Return Values
# ============================================================================

print("=== DEFAULT PARAMETERS AND RETURN VALUES ===")
print()

def check_system_health(cpu_threshold=80, memory_threshold=85, disk_threshold=90):
    """Check system health against configurable thresholds."""
    # Simulate current system metrics
    import random
    current_cpu = random.randint(30, 95)
    current_memory = random.randint(40, 90)
    current_disk = random.randint(20, 95)
    
    print(f"System Health Check (Thresholds: CPU={cpu_threshold}%, Memory={memory_threshold}%, Disk={disk_threshold}%)")
    print(f"Current metrics: CPU={current_cpu}%, Memory={current_memory}%, Disk={current_disk}%")
    
    issues = []
    if current_cpu > cpu_threshold:
        issues.append(f"High CPU usage: {current_cpu}%")
    if current_memory > memory_threshold:
        issues.append(f"High memory usage: {current_memory}%")
    if current_disk > disk_threshold:
        issues.append(f"High disk usage: {current_disk}%")
    
    if issues:
        print("⚠️  Issues found:")
        for issue in issues:
            print(f"   - {issue}")
        return issues
    else:
        print("✅ All systems healthy")
        return []

# Call with default parameters
print("Using default thresholds:")
health_issues = check_system_health()
print()

# Call with custom parameters
print("Using strict thresholds:")
strict_issues = check_system_health(70, 75, 80)
print()

# Call with some custom parameters (keyword arguments)
print("Using mixed parameters:")
mixed_issues = check_system_health(cpu_threshold=60, disk_threshold=70)
print()

# ============================================================================
# CONCEPT EXPLANATION: Multiple Return Values and Docstrings
# ============================================================================

print("=== MULTIPLE RETURN VALUES AND DOCSTRINGS ===")
print()

def analyze_security_log(log_entries):
    """
    Analyze security log entries and return comprehensive statistics.
    
    Args:
        log_entries (list): List of log entry strings
        
    Returns:
        tuple: (total_entries, error_count, warning_count, critical_count, summary_dict)
    """
    total_entries = len(log_entries)
    error_count = 0
    warning_count = 0
    critical_count = 0
    info_count = 0
    
    for entry in log_entries:
        if "ERROR" in entry:
            error_count += 1
        elif "WARNING" in entry:
            warning_count += 1
        elif "CRITICAL" in entry:
            critical_count += 1
        elif "INFO" in entry:
            info_count += 1
    
    summary = {
        "total": total_entries,
        "critical": critical_count,
        "errors": error_count,
        "warnings": warning_count,
        "info": info_count
    }
    
    return total_entries, error_count, warning_count, critical_count, summary

# Sample log entries
sample_logs = [
    "INFO: User login successful",
    "WARNING: High CPU usage detected",
    "ERROR: Database connection failed",
    "INFO: Backup completed",
    "CRITICAL: Security breach detected",
    "WARNING: Multiple failed login attempts",
    "ERROR: Service unavailable",
    "INFO: System restart completed"
]

print("Analyzing security logs:")
total, errors, warnings, critical, summary_dict = analyze_security_log(sample_logs)

print(f"Total entries: {total}")
print(f"Critical alerts: {critical}")
print(f"Errors: {errors}")
print(f"Warnings: {warnings}")
print(f"Summary dictionary: {summary_dict}")
print()

# ============================================================================
# CONCEPT EXPLANATION: Variable Scope
# ============================================================================

print("=== VARIABLE SCOPE ===")
print()

# Global variables
global_threat_level = "MEDIUM"
global_admin_count = 3

def update_threat_level(new_level):
    """Update the global threat level."""
    global global_threat_level  # Declare we want to modify the global variable
    old_level = global_threat_level
    global_threat_level = new_level
    print(f"Threat level updated: {old_level} -> {new_level}")

def get_security_status():
    """Get current security status using global variables."""
    # Can read global variables without declaring them
    print(f"Current threat level: {global_threat_level}")
    print(f"Active administrators: {global_admin_count}")
    
    # Local variable (only exists in this function)
    local_scan_time = "2023-10-01 16:30"
    print(f"Last scan: {local_scan_time}")

print("Scope demonstration:")
get_security_status()
print()

update_threat_level("HIGH")
get_security_status()
print()

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

print("=== CYBERSECURITY FUNCTION EXAMPLES ===")

def validate_ip_address(ip):
    """
    Validate if an IP address is properly formatted and categorize it.
    
    Args:
        ip (str): IP address string to validate
        
    Returns:
        dict: Validation results and categorization
    """
    parts = ip.split('.')
    
    # Basic format validation
    if len(parts) != 4:
        return {"valid": False, "reason": "Invalid format", "category": "invalid"}
    
    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return {"valid": False, "reason": "Non-numeric octets", "category": "invalid"}
    
    # Range validation
    if not all(0 <= octet <= 255 for octet in octets):
        return {"valid": False, "reason": "Octet out of range", "category": "invalid"}
    
    # Categorize valid IPs
    first_octet = octets[0]
    if first_octet == 10 or (first_octet == 172 and 16 <= octets[1] <= 31) or (first_octet == 192 and octets[1] == 168):
        category = "private"
    elif first_octet == 127:
        category = "loopback"
    elif 224 <= first_octet <= 239:
        category = "multicast"
    else:
        category = "public"
    
    return {"valid": True, "reason": "Valid IP address", "category": category}

def security_score_calculator(system_info):
    """
    Calculate a security score based on system configuration.
    
    Args:
        system_info (dict): System configuration details
        
    Returns:
        int: Security score from 0-100
    """
    score = 0
    max_score = 100
    
    # Firewall check (20 points)
    if system_info.get("firewall_enabled", False):
        score += 20
    
    # Antivirus check (15 points)
    if system_info.get("antivirus_active", False):
        score += 15
    
    # Updates check (20 points)
    days_since_update = system_info.get("days_since_update", 999)
    if days_since_update <= 7:
        score += 20
    elif days_since_update <= 30:
        score += 10
    
    # Password policy (15 points)
    password_policy = system_info.get("password_policy_enforced", False)
    if password_policy:
        score += 15
    
    # Encryption check (15 points)
    if system_info.get("disk_encrypted", False):
        score += 15
    
    # Access control (15 points)
    if system_info.get("access_control_enabled", False):
        score += 15
    
    return min(score, max_score)

# Test the cybersecurity functions
print("IP Address Validation Examples:")
test_ips = ["192.168.1.1", "10.0.0.256", "invalid.ip", "203.0.113.42", "127.0.0.1"]

for ip in test_ips:
    result = validate_ip_address(ip)
    status = "✅" if result["valid"] else "❌"
    print(f"{status} {ip}: {result['reason']} ({result['category']})")
print()

print("Security Score Examples:")
test_systems = [
    {
        "name": "Secure Server",
        "firewall_enabled": True,
        "antivirus_active": True,
        "days_since_update": 3,
        "password_policy_enforced": True,
        "disk_encrypted": True,
        "access_control_enabled": True
    },
    {
        "name": "Basic Workstation",
        "firewall_enabled": True,
        "antivirus_active": False,
        "days_since_update": 45,
        "password_policy_enforced": False,
        "disk_encrypted": False,
        "access_control_enabled": True
    }
]

for system in test_systems:
    score = security_score_calculator(system)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    print(f"{system['name']}: {score}/100 (Grade: {grade})")
print()

# ============================================================================
# WARM-UP EXERCISES: Practice Creating Functions
# ============================================================================

# Exercise 1: Simple function with no parameters
"""
PRACTICE: Basic Function

Your security operations center needs automated status reporting functions.
Create a function called check_system that displays "System status: Online" when called.
Execute the function to demonstrate basic automated status reporting.
This establishes the foundation for building more complex security automation tools.
"""
# TODO: Create function check_system and call it


# Exercise 2: Function with one parameter
"""
PRACTICE: Function with Parameter

Your user management system requires personalized security notifications.
Create a function called greet_user that accepts a username parameter.
The function should display "Hello, [username]" for personalized administrator greetings.
Test the function by calling it with "admin" as the username parameter.
"""
# TODO: Create function greet_user with username parameter and call it


# Exercise 3: Function that returns a value
"""
PRACTICE: Function with Return Value

Your security assessment system calculates protection effectiveness scores.
Create a function called calculate_security_score that accepts threats and defenses parameters.
The function should calculate and return the security score using: defenses minus threats.
Test by calling with threats=3 and defenses=8, then display the calculated security score.
"""
# TODO: Create function calculate_security_score with return value


# Exercise 4: Function with conditional logic
"""
PRACTICE: Function with Logic

Your network security analyzer identifies services by port numbers.
Create a function called assess_port that accepts a port_number parameter.
Implement logic to return "SSH port" for port 22, "HTTP port" for port 80, 
and "Unknown port" for other values.
Test the function with ports 22, 80, and 443 to verify service identification.
"""
# TODO: Create function assess_port with conditional logic


print("\n" + "="*50)
print("WARM-UP COMPLETE - NOW THE MAIN EXERCISE")
print("="*50 + "\n")

# ============================================================================
# YOUR MAIN EXERCISE: Build Modular Security Tools
# ============================================================================
"""
MODULAR SECURITY TOOLKIT DEVELOPMENT

You are building a comprehensive security toolkit that can be reused across different 
security operations. The toolkit should provide modular functions for common cybersecurity 
tasks including password analysis, network reconnaissance, log processing, and incident alerting.

PASSWORD SECURITY ANALYZER:
Create a function named analyze_password that evaluates password strength based on industry 
security standards. The function should assess passwords against five criteria: minimum 
length of 8 characters, presence of uppercase letters, presence of lowercase letters, 
inclusion of numbers, and use of special characters (!@#$%^&*).

The analyzer should assign 20 points for each met criterion (maximum 100 points) and 
categorize passwords as: Weak (0-40 points), Fair (41-60 points), Good (61-80 points), 
or Strong (81-100 points). Return the score, strength category, and specific recommendations 
for improvement.

NETWORK RECONNAISSANCE SCANNER:
Create a function named scan_network_range that performs automated network discovery 
across IP address ranges. The function should accept a network base (like "192.168.1"), 
starting host number, ending host number, and optional target port (defaulting to port 80).

Simulate the scanning process and return which hosts have the target port open versus 
closed. This tool helps security teams map network infrastructure and identify potential 
entry points.

SECURITY LOG PROCESSOR:
Create a function named parse_security_event that processes security log entries to extract 
critical information. The function should parse log lines in the format "YYYY-MM-DD HH:MM:SS 
SEVERITY event_description" and extract the timestamp, severity level (INFO, WARNING, ERROR, 
CRITICAL), and event description.

Handle malformed log entries gracefully by returning appropriate error information when 
the expected format is not found.

INCIDENT ALERT GENERATOR:
Create a function named generate_security_alert that produces formatted security alerts 
for incident response teams. The function should accept an event type, severity level 
(LOW, MEDIUM, HIGH, CRITICAL), list of affected systems, and detailed description.

Generate a unique alert ID using the current timestamp in "ALERT-YYYY-MM-DD-HHMMSS" format, 
display a formatted alert message, and return the alert ID for tracking purposes.

INTEGRATED SECURITY ASSESSMENT:
Create a main function named run_security_assessment that demonstrates the complete toolkit 
by testing various passwords for strength, scanning a network range for open ports, processing 
sample security log entries, generating appropriate alerts based on findings, and producing 
a comprehensive summary report of all security assessment results.
"""

# YOUR CODE GOES HERE
# ============================================================================

print("=== MODULAR SECURITY TOOLKIT ===")
print()

# PART 1: Password Security Function
# TODO: Create analyze_password function
# TODO: Create your analyze_password function here

# PART 2: Network Scanner Function
# TODO: Create scan_network_range function
def scan_network_range(network_base, start_host, end_host, target_port=80):
    """
    Scan a range of IP addresses for open ports.
    
    Args:
        network_base (str): Base network (e.g., "192.168.1")
        start_host (int): Starting host number
        end_host (int): Ending host number
        target_port (int): Port to scan (default 80)
        
    Returns:
        dict: Results with open_hosts and closed_hosts lists
    """
    import random
    
    open_hosts = []
    closed_hosts = []
    
    for host_num in range(start_host, end_host + 1):
        ip_address = f"{network_base}.{host_num}"
        
        # Simulate port scan (random result for demo)
        is_open = random.choice([True, False])
        
        if is_open:
            open_hosts.append(ip_address)
        else:
            closed_hosts.append(ip_address)
    
    return {
        "open_hosts": open_hosts,
        "closed_hosts": closed_hosts
    }

# PART 3: Log Analysis Function
# TODO: Create parse_security_event function
def parse_security_event(log_line):
    """
    Parse a security log entry and extract key information.
    
    Args:
        log_line (str): Raw log entry string
        
    Returns:
        dict: Parsed log data with timestamp, severity, and description
    """
    try:
        # Expected format: "YYYY-MM-DD HH:MM:SS SEVERITY: Description"
        parts = log_line.split(' ', 2)  # Split into max 3 parts
        
        if len(parts) < 3:
            return {
                "timestamp": "Unknown",
                "severity": "Unknown",
                "description": log_line
            }
        
        date_part = parts[0]
        time_part = parts[1]
        rest = parts[2]
        
        timestamp = f"{date_part} {time_part}"
        
        # Extract severity and description
        if ':' in rest:
            severity_part, description = rest.split(':', 1)
            severity = severity_part.strip()
            description = description.strip()
        else:
            severity = "INFO"
            description = rest
        
        return {
            "timestamp": timestamp,
            "severity": severity,
            "description": description
        }
    
    except Exception:
        return {
            "timestamp": "Unknown",
            "severity": "ERROR",
            "description": "Malformed log entry"
        }

# PART 4: Security Alert Function
# TODO: Create generate_security_alert function
def generate_security_alert(event_type, severity, affected_systems, details):
    """
    Generate a formatted security alert.
    
    Args:
        event_type (str): Type of security event
        severity (str): Severity level
        affected_systems (list): List of affected systems
        details (str): Event description
        
    Returns:
        str: Alert ID
    """
    from datetime import datetime
    
    # Generate alert ID with current timestamp
    now = datetime.now()
    alert_id = f"ALERT-{now.strftime('%Y-%m-%d-%H%M%S')}"
    
    # Severity icons
    severity_icons = {
        "LOW": "🟢",
        "MEDIUM": "🟡", 
        "HIGH": "🟠",
        "CRITICAL": "🔴"
    }
    
    icon = severity_icons.get(severity, "⚪")
    
    print(f"\n{'='*60}")
    print(f"{icon} SECURITY ALERT - {severity} SEVERITY")
    print(f"{'='*60}")
    print(f"Alert ID: {alert_id}")
    print(f"Event Type: {event_type}")
    print(f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Affected Systems: {', '.join(affected_systems)}")
    print(f"Details: {details}")
    print(f"{'='*60}")
    
    return alert_id

# PART 5: Integration Test
# TODO: Create run_security_assessment function
def run_security_assessment():
    """
    Run a comprehensive security assessment using all toolkit functions.
    """
    print("🔒 COMPREHENSIVE SECURITY ASSESSMENT")
    print("="*50)
    
    # Test passwords
    print("\n1. PASSWORD STRENGTH ANALYSIS:")
    print("-" * 30)
    test_passwords = ["password", "SecurePass123!", "abc", "MyP@ssw0rd2023"]
    
    weak_passwords = []
    for pwd in test_passwords:
        result = analyze_password(pwd)
        print(f"Password: {'*' * len(pwd)} | Score: {result['score']}/100 | Strength: {result['strength']}")
        if result['score'] < 60:
            weak_passwords.append(pwd)
    
    # Network scan
    print("\n2. NETWORK SCAN RESULTS:")
    print("-" * 30)
    scan_results = scan_network_range("192.168.1", 1, 5, 80)
    print(f"Open hosts (port 80): {scan_results['open_hosts']}")
    print(f"Closed hosts: {scan_results['closed_hosts']}")
    
    # Log analysis
    print("\n3. LOG ANALYSIS:")
    print("-" * 30)
    sample_logs = [
        "2023-10-01 14:30:15 INFO: User login successful",
        "2023-10-01 14:35:22 WARNING: Multiple failed login attempts",
        "2023-10-01 14:40:33 CRITICAL: Unauthorized access detected",
        "Malformed log entry without proper format"
    ]
    
    critical_events = []
    for log in sample_logs:
        parsed = parse_security_event(log)
        print(f"[{parsed['severity']}] {parsed['timestamp']}: {parsed['description']}")
        if parsed['severity'] == 'CRITICAL':
            critical_events.append(parsed)
    
    # Generate alerts for critical findings
    print("\n4. SECURITY ALERTS:")
    print("-" * 30)
    
    alerts_generated = []
    
    if weak_passwords:
        alert_id = generate_security_alert(
            "Password Policy Violation",
            "MEDIUM",
            ["User Workstations"],
            f"Found {len(weak_passwords)} weak passwords requiring immediate change"
        )
        alerts_generated.append(alert_id)
    
    if critical_events:
        alert_id = generate_security_alert(
            "Security Breach",
            "CRITICAL",
            ["Network Infrastructure"],
            f"Critical security events detected in logs: {len(critical_events)} incidents"
        )
        alerts_generated.append(alert_id)
    
    if len(scan_results['open_hosts']) > 3:
        alert_id = generate_security_alert(
            "Network Exposure",
            "HIGH",
            scan_results['open_hosts'],
            f"Multiple systems with open ports detected: {len(scan_results['open_hosts'])} hosts"
        )
        alerts_generated.append(alert_id)
    
    # Summary report
    print(f"\n5. ASSESSMENT SUMMARY:")
    print("-" * 30)
    print(f"📊 Passwords analyzed: {len(test_passwords)}")
    print(f"📊 Weak passwords found: {len(weak_passwords)}")
    print(f"📊 Network hosts scanned: {len(scan_results['open_hosts']) + len(scan_results['closed_hosts'])}")
    print(f"📊 Open hosts discovered: {len(scan_results['open_hosts'])}")
    print(f"📊 Log entries processed: {len(sample_logs)}")
    print(f"📊 Critical events found: {len(critical_events)}")
    print(f"📊 Security alerts generated: {len(alerts_generated)}")
    
    if alerts_generated:
        print(f"\n⚠️  ATTENTION REQUIRED: {len(alerts_generated)} security alerts need immediate review")
    else:
        print(f"\n✅ ASSESSMENT COMPLETE: No critical security issues detected")

# Run the comprehensive assessment
run_security_assessment()

# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_functions():
    """Test function to verify your function implementations are correct."""
    
    try:
        # Test Part 1: Password analysis function
        test_result = analyze_password("TestPass123!")
        assert "score" in test_result, "analyze_password should return a dictionary with 'score' key"
        assert "strength" in test_result, "analyze_password should return a dictionary with 'strength' key"
        assert "recommendations" in test_result, "analyze_password should return a dictionary with 'recommendations' key"
        assert test_result["score"] == 100, f"Strong password should score 100, got {test_result['score']}"
        print("✅ Test 1 PASSED: analyze_password function works correctly")
        
        # Test Part 2: Network scanner function
        scan_result = scan_network_range("192.168.1", 1, 3, 80)
        assert "open_hosts" in scan_result, "scan_network_range should return dictionary with 'open_hosts' key"
        assert "closed_hosts" in scan_result, "scan_network_range should return dictionary with 'closed_hosts' key"
        total_hosts = len(scan_result["open_hosts"]) + len(scan_result["closed_hosts"])
        assert total_hosts == 3, f"Should scan 3 hosts, got {total_hosts}"
        print("✅ Test 2 PASSED: scan_network_range function works correctly")
        
        # Test Part 3: Log parsing function
        test_log = "2023-10-01 14:30:15 WARNING: Test log entry"
        parsed = parse_security_event(test_log)
        assert "timestamp" in parsed, "parse_security_event should return dictionary with 'timestamp' key"
        assert "severity" in parsed, "parse_security_event should return dictionary with 'severity' key"
        assert "description" in parsed, "parse_security_event should return dictionary with 'description' key"
        assert parsed["severity"] == "WARNING", f"Should extract WARNING severity, got {parsed['severity']}"
        print("✅ Test 3 PASSED: parse_security_event function works correctly")
        
        # Test Part 4: Alert generation function  
        alert_id = generate_security_alert("Test Event", "HIGH", ["system1"], "Test details")
        assert alert_id.startswith("ALERT-"), f"Alert ID should start with 'ALERT-', got {alert_id}"
        assert len(alert_id) > 10, f"Alert ID should be longer than 10 characters, got {len(alert_id)}"
        print("✅ Test 4 PASSED: generate_security_alert function works correctly")
        
        # Test Part 5: Main assessment function exists
        assert callable(run_security_assessment), "run_security_assessment should be a callable function"
        print("✅ Test 5 PASSED: run_security_assessment function is defined")
        
        print("\n🎉 CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python functions!")
        print("Ready for Module 8: File I/O")
        
    except NameError as e:
        print(f"❌ ERROR: Function not found - {e}")
        print("Make sure you've defined all required functions.")
    except AssertionError as e:
        print(f"❌ TEST FAILED: {e}")
        print("Check your function implementations and try again.")
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")

# Run the tests
test_functions()

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
