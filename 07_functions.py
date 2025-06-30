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
    # Your code here
    pass


# Exercise 2: Function with one parameter
"""
PRACTICE: Function with Parameter

Write a function `greet_user_warmup(username)` that accepts a username string.
The function should return a personalized greeting string: "Hello, [username]".
"""
# TODO: Implement the function greet_user_warmup
def greet_user_warmup(username):
    # Your code here
    pass


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
    # Your code here
    pass


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
    # Your code here
    pass


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
Return a dictionary:
- "alert_id": (string)
- "formatted_message": (string, a comprehensive alert message including all input details and the ID).
  Example:
  "🔴 CRITICAL SECURITY ALERT 🔴\nAlert ID: ALERT-...\nEvent: ...\nAffected: ...\nDetails: ..."
  (Use appropriate emoji for severity: 🟢 LOW, 🟡 MEDIUM, 🟠 HIGH, 🔴 CRITICAL)

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
5. Return a summary dictionary from `run_security_assessment` containing:
   - "password_analysis_results": list of results from analyze_password
   - "network_scan_results": result from scan_network_range
   - "parsed_log_results": list of results from parse_security_event
   - "generated_alerts_details": list of alert dictionaries from generate_security_alert
"""

# YOUR CODE GOES HERE
# ============================================================================


# PART 1: Password Security Function
# TODO: Implement analyze_password function
def analyze_password(password_string):
    # Your code here
    pass

# PART 2: Network Scanner Function
# TODO: Implement scan_network_range function
def scan_network_range(network_base, start_host, end_host, target_port=80):
    # Your code here
    # Remember to import random if you use it inside this function specifically
    # and not globally at the top of the file.
    pass

# PART 3: Log Analysis Function
# TODO: Implement parse_security_event function
def parse_security_event(log_line_string):
    # Your code here
    pass

# PART 4: Security Alert Function
# TODO: Implement generate_security_alert function
def generate_security_alert(event_type, severity, affected_systems_list, details_string):
    # Your code here
    # Remember to import datetime if you use it inside this function specifically
    # and not globally at the top of the file.
    pass

# PART 5: Integration Test Function
# TODO: Implement run_security_assessment function
def run_security_assessment():
    # This function will call the other functions you've defined.
    # Store their results and then return the final summary dictionary.
    # password_analysis_results = []
    # network_scan_results = {}
    # parsed_log_results = []
    # generated_alerts_details = []
    # Your code here
    pass


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

def test_warmup_functions():
    """Test the warm-up functions."""
    warmup_passed = 0
    total_warmup_tests = 4

    # Test Exercise 1
    try:
        assert check_system_status_warmup() == "System status: Online", "Warm-up 1 Failed"
        print("✅ Warm-up Exercise 1 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 1 FAILED: Function 'check_system_status_warmup' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 1 FAILED: Unexpected error - {e}")

    # Test Exercise 2
    try:
        assert greet_user_warmup("admin") == "Hello, admin", "Warm-up 2 Failed: Test 'admin'"
        assert greet_user_warmup("test_user") == "Hello, test_user", "Warm-up 2 Failed: Test 'test_user'"
        print("✅ Warm-up Exercise 2 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 2 FAILED: Function 'greet_user_warmup' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 2 FAILED: Unexpected error - {e}")

    # Test Exercise 3
    try:
        assert calculate_security_score_warmup(3, 8) == 5, "Warm-up 3 Failed: 8 - 3 = 5"
        assert calculate_security_score_warmup(5, 5) == 0, "Warm-up 3 Failed: 5 - 5 = 0"
        assert calculate_security_score_warmup(0, 10) == 10, "Warm-up 3 Failed: 10 - 0 = 10"
        print("✅ Warm-up Exercise 3 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 3 FAILED: Function 'calculate_security_score_warmup' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 3 FAILED: Unexpected error - {e}")

    # Test Exercise 4
    try:
        assert assess_port_warmup(22) == "SSH port", "Warm-up 4 Failed: Port 22"
        assert assess_port_warmup(80) == "HTTP port", "Warm-up 4 Failed: Port 80"
        assert assess_port_warmup(443) == "Unknown port", "Warm-up 4 Failed: Port 443"
        assert assess_port_warmup(123) == "Unknown port", "Warm-up 4 Failed: Port 123"
        print("✅ Warm-up Exercise 4 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Warm-up Exercise 4 FAILED: Function 'assess_port_warmup' not defined.")
    except Exception as e:
        print(f"❌ Warm-up Exercise 4 FAILED: Unexpected error - {e}")

    print(f"\nWarm-up Score: {warmup_passed}/{total_warmup_tests} exercises completed correctly.")
    return warmup_passed == total_warmup_tests


def test_main_security_toolkit_functions():
    """Test function to verify your main exercise function implementations are correct."""
    main_passed = True
    missing_funcs = []

    def check_func(func_name):
        if func_name not in globals() or not callable(globals()[func_name]):
            missing_funcs.append(func_name)
            return False
        return True

    # Check if all main functions are defined
    main_functions = ["analyze_password", "scan_network_range", "parse_security_event", "generate_security_alert", "run_security_assessment"]
    for func_name in main_functions:
        if not check_func(func_name):
            main_passed = False
    
    if not main_passed:
        print(f"❌ ERROR: Main exercise functions not defined: {', '.join(missing_funcs)}")
        return False

    # Test analyze_password
    try:
        # Strong password
        res_strong = analyze_password("Str0ngP@ss!")
        assert isinstance(res_strong, dict), "analyze_password should return a dict."
        assert res_strong.get("score") == 100, "analyze_password: 'Str0ngP@ss!' score should be 100."
        assert res_strong.get("strength") == "Strong", "analyze_password: 'Str0ngP@ss!' strength should be 'Strong'."
        assert isinstance(res_strong.get("recommendations"), list) and not res_strong.get("recommendations"), "analyze_password: 'Str0ngP@ss!' should have no recommendations."
        # Weak password
        res_weak = analyze_password("pass")
        assert res_weak.get("score") == 20, f"analyze_password: 'pass' score should be 20, got {res_weak.get('score')}." # Only lowercase
        assert res_weak.get("strength") == "Weak", "analyze_password: 'pass' strength should be 'Weak'."
        assert len(res_weak.get("recommendations", [])) == 4, "analyze_password: 'pass' should have 4 recommendations."
        print("✅ Main Test 1 PASSED: analyze_password basic checks.")
    except Exception as e:
        print(f"❌ Main Test 1 FAILED: analyze_password error - {e}")
        main_passed = False

    # Test scan_network_range
    try:
        # Override random.choice for predictable testing
        original_random_choice = random.choice
        def mock_random_choice(seq): return True if seq[0] is True else False # Make it deterministic for test
        random.choice = mock_random_choice
        
        res_scan = scan_network_range("10.0.0", 1, 2, target_port=22)
        assert isinstance(res_scan, dict), "scan_network_range should return a dict."
        assert "open_hosts" in res_scan and "closed_hosts" in res_scan, "scan_network_range dict missing keys."
        # Based on mock, it will always choose the first element. If [True,False] is choice, True is picked.
        # This means it will always report open.
        assert len(res_scan["open_hosts"]) == 2, f"scan_network_range open_hosts count error. Expected 2, got {len(res_scan['open_hosts'])}"
        assert "10.0.0.1" in res_scan["open_hosts"], "scan_network_range specific IP check failed."
        random.choice = original_random_choice # Restore original
        print("✅ Main Test 2 PASSED: scan_network_range basic checks.")
    except Exception as e:
        print(f"❌ Main Test 2 FAILED: scan_network_range error - {e}")
        random.choice = original_random_choice # Ensure restoration on error
        main_passed = False

    # Test parse_security_event
    try:
        log1 = "2023-10-01 14:30:15 INFO User login successful"
        res_log1 = parse_security_event(log1)
        assert isinstance(res_log1, dict), "parse_security_event should return a dict."
        assert res_log1.get("timestamp") == "2023-10-01 14:30:15", "parse_security_event: timestamp parsing error."
        assert res_log1.get("severity") == "INFO", "parse_security_event: severity parsing error."
        assert res_log1.get("description") == "User login successful", "parse_security_event: description parsing error."
        
        log_malformed = "This is not a log"
        res_log_malformed = parse_security_event(log_malformed)
        assert res_log_malformed.get("severity") == "ERROR", "parse_security_event: malformed log severity error."
        assert "Malformed log entry" in res_log_malformed.get("description", ""), "parse_security_event: malformed log description error."
        print("✅ Main Test 3 PASSED: parse_security_event basic checks.")
    except Exception as e:
        print(f"❌ Main Test 3 FAILED: parse_security_event error - {e}")
        main_passed = False

    # Test generate_security_alert
    try:
        res_alert = generate_security_alert("Test Event", "CRITICAL", ["sys1", "sys2"], "Details here")
        assert isinstance(res_alert, dict), "generate_security_alert should return a dict."
        assert "alert_id" in res_alert and "formatted_message" in res_alert, "generate_security_alert dict missing keys."
        assert res_alert["alert_id"].startswith("ALERT-"), "generate_security_alert: alert_id format error."
        assert "CRITICAL SECURITY ALERT" in res_alert["formatted_message"], "generate_security_alert: message format error (severity)."
        assert "sys1, sys2" in res_alert["formatted_message"], "generate_security_alert: message format error (affected systems)."
        print("✅ Main Test 4 PASSED: generate_security_alert basic checks.")
    except Exception as e:
        print(f"❌ Main Test 4 FAILED: generate_security_alert error - {e}")
        main_passed = False

    # Test run_security_assessment structure
    try:
        # Override random.choice for predictable testing of scan_network_range inside run_security_assessment
        original_random_choice_run = random.choice
        def mock_random_choice_run(seq): return True # Always open for simplicity
        random.choice = mock_random_choice_run

        summary = run_security_assessment()
        assert isinstance(summary, dict), "run_security_assessment should return a dict."
        expected_keys = ["password_analysis_results", "network_scan_results", "parsed_log_results", "generated_alerts_details"]
        for k in expected_keys:
            assert k in summary, f"run_security_assessment summary missing key: {k}"
            if "results" in k or "details" in k : # These should be lists
                 assert isinstance(summary[k], list), f"run_security_assessment: {k} should be a list."
        
        # Check if lists within summary are populated (basic check)
        assert len(summary["password_analysis_results"]) == 3, "run_security_assessment: password_analysis_results not populated as expected."
        assert len(summary["network_scan_results"].get("open_hosts", [])) == 3, "run_security_assessment: network_scan_results not populated as expected."
        assert len(summary["parsed_log_results"]) == 3, "run_security_assessment: parsed_log_results not populated as expected."
        # Number of alerts can vary based on logic, so just check presence and type
        assert isinstance(summary["generated_alerts_details"], list), "run_security_assessment: generated_alerts_details should be a list."

        random.choice = original_random_choice_run # Restore
        print("✅ Main Test 5 PASSED: run_security_assessment structure and basic content checks.")
    except Exception as e:
        print(f"❌ Main Test 5 FAILED: run_security_assessment error - {e}")
        random.choice = original_random_choice_run # Ensure restoration
        main_passed = False

    if main_passed and not missing_funcs:
        print("\n🎉 ALL MAIN EXERCISE TESTS PASSED (basic functionality)!")
    else:
        print("\n❌ SOME MAIN EXERCISE TESTS FAILED or functions missing.")
    return main_passed and not missing_funcs


def run_all_tests():
    """Run all tests for Module 7."""
    print("="*50)
    print("RUNNING WARM-UP TESTS...")
    print("="*50)
    warmup_success = test_warmup_functions()

    print("\n" + "="*50)
    print("RUNNING MAIN EXERCISE CHECKS...")
    print("="*50)
    # Temporarily disable prints from main functions for cleaner test output
    # Note: This is a simple way; a more robust solution would involve decorators or context managers
    # if the functions themselves print a lot. Here, generate_security_alert prints.
    # For this exercise, the main function's prints are illustrative, so we can let them run.

    main_exercise_success = test_main_security_toolkit_functions()

    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    if warmup_success and main_exercise_success:
        print("\n✅ All warm-up and main exercise tests passed!")
        print("You've successfully mastered Python functions!")
        print("Ready for Module 8: File I/O")
    else:
        print("\n📚 Keep practicing! Review the failed tests or checks above.")
        if not warmup_success:
            print("- Some warm-up exercises have issues.")
        if not main_exercise_success:
            print("- The main exercise has issues or missing functions.")

# Run the tests if the script is executed directly
if __name__ == "__main__":
    # Example calls to main exercise functions for user to see output during development
    # (These are not part of the tests, but help visualize)
    # print("--- Example: analyze_password ---")
    # print(analyze_password("Short1!"))
    # print("\n--- Example: scan_network_range ---")
    # print(scan_network_range("10.0.1", 10, 12, target_port=443))
    # print("\n--- Example: parse_security_event ---")
    # print(parse_security_event("2023-10-28 10:00:00 CRITICAL System compromised"))
    # print(parse_security_event("Invalid log line"))
    # print("\n--- Example: generate_security_alert ---")
    # print(generate_security_alert("Malware Detected", "HIGH", ["ServerA", "Workstation3"], "Ransomware variant XYZ found."))

    # print("\n--- Running Full Assessment ---")
    # assessment_summary = run_security_assessment()
    # print("\n--- Full Assessment Summary (returned data) ---")
    # for key, value in assessment_summary.items():
    #     print(f"{key}: {value}")

    run_all_tests()
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
