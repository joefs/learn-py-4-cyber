"""
====================================================================
MODULE 8: FILE INPUT/OUTPUT - Working with Security Data Files 📁
====================================================================

Welcome to Module 8! Functions help you organize code, but cybersecurity work
involves lots of data stored in files: configuration files, log files,
reports, and data exports. You'll learn to read, write, and process files
that are essential for security administration.

WHAT IS FILE I/O?
File Input/Output (I/O) lets your programs interact with files on the system.
In cybersecurity, you constantly work with files: reading configuration files,
parsing log files, generating reports, and storing security data.

FILE I/O CONCEPTS WE'LL COVER:
- Opening and closing files safely
- Reading files: full content, line by line
- Writing files: creating and appending data
- Working with CSV files for structured data
- Processing common cybersecurity file formats
"""

"""
====================================================================
MODULE 8: FILE INPUT/OUTPUT - Working with Security Data Files 📁
====================================================================

Welcome to Module 8! Functions help you organize code, but cybersecurity work
involves lots of data stored in files: configuration files, log files,
reports, and data exports. You'll learn to read, write, and process files
that are essential for security administration.

WHAT IS FILE I/O?
File Input/Output (I/O) lets your programs interact with files on the system.
In cybersecurity, you constantly work with files: reading configuration files,
parsing log files, generating reports, and storing security data.

FILE I/O CONCEPTS WE'LL COVER:
- Opening and closing files safely
- Reading files: full content, line by line
- Writing files: creating and appending data
- Working with CSV files for structured data
- Processing common cybersecurity file formats
"""
import os
import re
from datetime import datetime

# ============================================================================
# CONCEPT EXPLANATION: Basic File Reading (Conceptual - prints are illustrative)
# ============================================================================
# This block and its prints are for teaching and will be kept.
# Sample file creation for conceptual examples:
conceptual_config_content = """# Security Configuration File
firewall_enabled=true
log_level=INFO
"""
with open("conceptual_security_config.txt", "w") as f:
    f.write(conceptual_config_content)
print("Created conceptual_security_config.txt for demonstration.")

print("\nReading entire conceptual file:")
with open("conceptual_security_config.txt", "r") as file:
    conceptual_content = file.read()
    print(conceptual_content)

print("Reading conceptual file line by line:")
with open("conceptual_security_config.txt", "r") as file:
    for line_num, line_text in enumerate(file, 1):
        stripped_line = line_text.strip()
        if stripped_line and not stripped_line.startswith("#"):
            print(f"Conceptual Line {line_num}: {stripped_line}")

# ============================================================================
# HELPER FUNCTIONS (These might be used by your main exercise functions)
# ============================================================================
def analyze_security_log(log_filename): # This helper is used by main exercise
    stats = {
        "total_entries": 0,
        "by_severity": {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0},
        "failed_logins": 0, "suspicious_ips": set(), "critical_events": []
    }
    if not os.path.exists(log_filename): return stats
    try:
        with open(log_filename, "r") as log_file:
            for line in log_file:
                line = line.strip()
                if not line: continue
                stats["total_entries"] += 1
                for sev in stats["by_severity"].keys():
                    if sev in line: stats["by_severity"][sev] += 1; break
                if "failed login" in line.lower(): stats["failed_logins"] += 1
                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if ips and ("failed" in line.lower() or "suspicious" in line.lower()):
                    stats["suspicious_ips"].update(ips)
                if "CRITICAL" in line: stats["critical_events"].append(line)
    except Exception: pass
    stats["suspicious_ips"] = list(stats["suspicious_ips"])
    return stats

# ============================================================================
# WARM-UP EXERCISES: Practice File Operations
# ============================================================================

# Exercise 1: Write a simple file
"""
PRACTICE: Recording System Status

Your security system needs to periodically save its current status to a file.
Create a tool (a function) that takes a filename and a status message.
This tool should write the given status message into the specified file.
It should indicate whether the operation was successful.

(Define this as a function `write_status_to_file_warmup(filename, status_message)`
that returns True if writing was successful, False otherwise.)
"""
# TODO: Implement write_status_to_file_warmup
def write_status_to_file_warmup(filename, status_message):
    pass

# Exercise 2: Read a simple file
"""
PRACTICE: Retrieving System Status

Complementary to the previous exercise, you need a tool to read the last saved
system status from a file. This tool should take a filename, attempt to read
its entire content, and return that content. If the file cannot be found or
read, it should return a special value (None) to indicate failure.

(Define this as a function `read_status_from_file_warmup(filename)`
that returns the file content or None.)
"""
# TODO: Implement read_status_from_file_warmup
def read_status_from_file_warmup(filename):
    pass

# Exercise 3: Append to a file
"""
PRACTICE: Continuous Logging

Your system generates log messages that need to be added to an ongoing log file.
Create a utility that takes a filename and a new log message. This utility
should append the new message to the end of the file. To keep the log readable,
if the file isn't empty and doesn't already end with a newline, a newline
should be added before the new message. The utility should report its success.

(Define this as a function `append_log_to_file_warmup(filename, log_message)`
that returns True if appending was successful, False otherwise.)
"""
# TODO: Implement append_log_to_file_warmup
def append_log_to_file_warmup(filename, log_message):
    pass

# Exercise 4: Process file line by line
"""
PRACTICE: Server Checkup from List

You have a list of servers stored in a file, one server name per line.
First, your utility needs to create this server list file from a given string
(where server names in the string are separated by newlines).
Then, it must read this file line by line. For each server name found (ignoring
any empty lines), it should generate a status message "Checking: [server_name]".
Collect all such status messages. If the file, once created, cannot be read,
return an empty collection of messages.

(Define this as a function `get_servers_from_file_warmup(filename, server_list_content_str)`
that returns a list of formatted "Checking: ..." strings.)
"""
# TODO: Implement get_servers_from_file_warmup
def get_servers_from_file_warmup(filename, server_list_content_str):
    pass

# ============================================================================
# YOUR MAIN EXERCISE: Build a Security File Management System
# ============================================================================
"""
CHALLENGE: SECURITY FILE MANAGEMENT SYSTEM

You are tasked with developing a suite of tools for managing various security-related
files. Each tool will be a function designed for a specific file operation task.

TOOL 1: USER ACCOUNT DATA PROCESSOR
   Function Name: `process_user_list`
   Input: `csv_filepath` (string path to a CSV file)
   CSV File Format: Each line contains user data: `username,role,email,last_login_date,status`
     (e.g., "jdoe,user,jdoe@example.com,2023-01-15,active")
   Task: Read the CSV file. Parse each line to extract user information.
   Output: Return a dictionary summarizing the data:
     - "total_users": Total number of users in the file.
     - "active_users": A list of usernames for users whose status is "active".
     - "inactive_users": A list of usernames for users whose status is "inactive".
     - "admin_users": A list of usernames for users whose role is "admin" or "administrator" (case-insensitive).
   Error Handling: If the file is not found or a significant parsing error occurs (e.g., incorrect CSV format
                   that prevents basic processing), return `None`.

TOOL 2: SECURITY ALERT FILTERING SYSTEM
   Function Name: `process_security_alerts`
   Inputs: `alerts_filepath` (path to the input alerts file), `output_report_filepath` (path for the filtered report)
   Alerts File Format: Each line is a pipe-separated string: "timestamp|severity|source_system|description"
     (e.g., "2023-10-01T09:30:00Z|HIGH|firewall-01|Suspicious outbound connection")
   Task: Read the alerts file. Identify and filter alerts that are of "HIGH" or "CRITICAL" severity.
         Write these selected high-priority alerts to the `output_report_filepath`. Each alert in the
         output file should be formatted as: "ALERT: [timestamp] - [severity] - [source] - [description]".
   Output: Return the count of high-priority alerts that were processed and written to the report.
   Error Handling: If any file operation fails, return -1.

TOOL 3: CONFIGURATION MANAGEMENT TOOL
   Function Name: `update_security_config`
   Inputs: `config_filepath` (path to a configuration file), `updates_dict` (a dictionary like `{"key_to_update": "new_value"}`)
   Config File Format: Standard "key=value" pairs, one per line. Lines starting with "#" are comments and should be preserved.
   Task: Read the existing configuration file. For each key in `updates_dict`:
         - If the key exists in the config file, update its value.
         - If the key does not exist, add it as a new "key=value" pair at the end of the file.
         Preserve all comments and unchanged lines in their original positions. Write the modified
         content back to the `config_filepath`, overwriting the original.
   Output: Return `True` if the update process completes successfully.
   Error Handling: Return `False` if any file operation fails.

TOOL 4: LOG ARCHIVE SYSTEM
   Function Name: `archive_old_logs`
   Inputs: `source_directory` (path to a directory containing log files), `archive_filepath` (path for the consolidated archive file)
   Task: Search `source_directory` for all files ending with ".log" or ".txt". For each found file
         (excluding the `archive_filepath` itself if it's in the same directory):
         1. Get the current timestamp (e.g., "YYYY-MM-DD HH:MM:SS").
         2. Append a header to `archive_filepath`: "--- Start of [filename] (Archived: [timestamp]) ---".
         3. Append the entire content of the found log file to `archive_filepath`.
         4. Append a footer: "--- End of [filename] ---".
         Ensure each appended section (header, content, footer) is followed by a newline in the archive.
   Output: Return a list of filenames that were successfully archived.
   Error Handling: If the `source_directory` doesn't exist or other major file operation errors occur,
                   return an empty list. Individual file read errors should be skipped, and archiving should continue if possible.

TOOL 5: SECURITY METRICS ANALYZER
   Function Name: `generate_metrics_report`
   Inputs: `user_csv_filepath` (for user data), `alerts_input_filepath` (for alert data), `output_metrics_filepath` (for the report)
   Task:
     1. Analyze user data (similar to `process_user_list` or by calling it if available and robust) to get:
        total user count, active user count, and admin user count. Calculate active user percentage.
     2. Analyze the alerts file (similar to `process_security_alerts` but only for counting, not writing a filtered report) to get:
        total alert count, count of "HIGH" or "CRITICAL" alerts, and count of "CRITICAL" alerts only.
     3. Write all these calculated metrics into `output_metrics_filepath` in a human-readable format
        (e.g., "Total Users: 50\nActive User Percentage: 90.0%\n...").
   Output: Return a dictionary containing all the calculated metrics (e.g., `{"total_users": ...,
           "active_user_percentage": ..., "admin_user_count": ..., "total_alerts": ...,
           "high_priority_alert_count": ..., "critical_alert_count": ...}`).
   Error Handling: If essential input files are missing or major processing fails, return an empty dictionary.
"""

# YOUR CODE GOES HERE
# ============================================================================

# PART 1: User Management File Operations
# TODO: Implement process_user_list function
def process_user_list(csv_filepath):
    pass

# PART 2: Security Alert File Processing
# TODO: Implement process_security_alerts function
def process_security_alerts(alerts_filepath, output_report_filepath):
    pass

# PART 3: Configuration File Management
# TODO: Implement update_security_config function
def update_security_config(config_filepath, updates_dict):
    pass

# PART 4: Log File Archiving
# TODO: Implement archive_old_logs function
def archive_old_logs(source_directory, archive_filepath):
    pass

# PART 5: Security Metrics Report
# TODO: Implement generate_metrics_report function
def generate_metrics_report(user_csv_filepath, alerts_input_filepath, output_metrics_filepath):
    pass


# ============================================================================
# INTEGRATED TESTING FRAMEWORK (Illustrative - Not part of student's required code)
# ============================================================================
def run_integrated_tests():
    print("\n" + "="*50)
    print("RUNNING INTEGRATED FILE MANAGEMENT SYSTEM TESTS...")
    print("="*50)

    # Setup sample files
    sample_users_content = "username,role,email,last_login,status\nalice,admin,a@example.com,2023-01-01,active\nbob,user,b@example.com,2023-01-02,active\ncharlie,user,c@example.com,2022-01-01,inactive"
    with open("test_users.csv", "w") as f: f.write(sample_users_content)

    sample_alerts_content = "2023-01-01T10:00:00Z|CRITICAL|app01|System breach\n2023-01-01T11:00:00Z|LOW|db01|Low disk space\n2023-01-01T12:00:00Z|HIGH|net01|DDoS attempt"
    with open("test_alerts.txt", "w") as f: f.write(sample_alerts_content)

    sample_config_content = "# Initial Config\nsetting1=value1\nsetting2=old_value"
    with open("test_config.ini", "w") as f: f.write(sample_config_content)

    with open("test_log1.log", "w") as f: f.write("Log A line 1\nLog A line 2")
    with open("test_log2.txt", "w") as f: f.write("Log B line 1")
    # Ensure archive file does not exist or is empty before test
    if os.path.exists("test_archive_main.txt"): os.remove("test_archive_main.txt")


    print("\n--- Testing process_user_list ---")
    user_data = process_user_list("test_users.csv")
    if user_data:
        print(f"  Processed Users: Total={user_data.get('total_users')}, Admins={len(user_data.get('admin_users', []))}")
    else:
        print("  process_user_list returned None or error.")

    print("\n--- Testing process_security_alerts ---")
    high_prio_count = process_security_alerts("test_alerts.txt", "test_filtered_alerts_report.txt")
    print(f"  High-priority alerts processed and written: {high_prio_count}")
    if os.path.exists("test_filtered_alerts_report.txt"):
        with open("test_filtered_alerts_report.txt", "r") as f:
            print("  Filtered alerts report content (first few lines):")
            for i, line in enumerate(f):
                if i < 3: print(f"    {line.strip()}")
                else: break

    print("\n--- Testing update_security_config ---")
    update_success = update_security_config("test_config.ini", {"setting2": "new_value", "setting3": "added"})
    print(f"  Config update successful: {update_success}")
    if update_success and os.path.exists("test_config.ini"):
        with open("test_config.ini", "r") as f:
            print("  Updated config file content:")
            print(f.read())

    print("\n--- Testing archive_old_logs ---")
    # Create some more dummy logs for archiving in current dir if they don't exist from other tests
    if not os.path.exists("main_dummy1.log"): open("main_dummy1.log","w").write("dummy log1")
    if not os.path.exists("main_dummy2.txt"): open("main_dummy2.txt","w").write("dummy log2")

    archived = archive_old_logs(".", "test_archive_main.txt")
    print(f"  Archived {len(archived)} files into test_archive_main.txt: {archived}")
    if os.path.exists("test_archive_main.txt"):
         with open("test_archive_main.txt", "r") as f:
            print(f"  Archive content starts with: {f.readline().strip()}")


    print("\n--- Testing generate_metrics_report ---")
    metrics = generate_metrics_report("test_users.csv", "test_alerts.txt", "test_metrics_report.txt")
    if metrics:
        print(f"  Generated Metrics: {metrics}")
        if os.path.exists("test_metrics_report.txt"):
            with open("test_metrics_report.txt", "r") as f:
                print("  Metrics report content (first few lines):")
                for i, line in enumerate(f):
                    if i < 5: print(f"    {line.strip()}")
                    else: break
    else:
        print("  generate_metrics_report returned None or error.")

    # Cleanup illustrative test files
    illustrative_cleanup = ["test_users.csv", "test_alerts.txt", "test_config.ini",
                            "test_filtered_alerts_report.txt", "test_archive_main.txt",
                            "test_metrics_report.txt", "conceptual_security_config.txt",
                            "main_dummy1.log", "main_dummy2.log"] # Added conceptual
    for f_name in illustrative_cleanup:
        if os.path.exists(f_name):
            try: os.remove(f_name)
            except OSError: pass


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_file_io():
    warmup_passed = 0
    total_warmup_tests = 4
    setup_test_files()

    # Test 1
    try:
        assert write_status_to_file_warmup("warmup_test.txt", "Security System Active") is True
        with open("warmup_test.txt", "r") as f: assert f.read() == "Security System Active"
        print("✅ Warm-up Exercise 1 PASSED")
        warmup_passed += 1
    except Exception as e: print(f"❌ Warm-up Exercise 1 FAILED: {e}")

    # Test 2
    try:
        assert read_status_from_file_warmup("warmup_test.txt") == "Security System Active"
        assert read_status_from_file_warmup("non_existent.txt") is None
        print("✅ Warm-up Exercise 2 PASSED")
        warmup_passed += 1
    except Exception as e: print(f"❌ Warm-up Exercise 2 FAILED: {e}")

    # Test 3
    try:
        write_status_to_file_warmup("warmup_test.txt", "First line.") # Reset file
        assert append_log_to_file_warmup("warmup_test.txt", "Second line.") is True
        with open("warmup_test.txt", "r") as f: content = f.read()
        assert content == "First line.\nSecond line." or content == "First line.Second line." # Allow flexibility
        print("✅ Warm-up Exercise 3 PASSED")
        warmup_passed += 1
    except Exception as e: print(f"❌ Warm-up Exercise 3 FAILED: {e}")

    # Test 4
    try:
        servers_content = "serverA\nserverB\n\nserverC"
        expected_lines = ["Checking: serverA", "Checking: serverB", "Checking: serverC"]
        assert get_servers_from_file_warmup("warmup_servers.txt", servers_content) == expected_lines
        assert get_servers_from_file_warmup("non_existent_servers.txt", "") == [] # Test non-existent after attempting create
        print("✅ Warm-up Exercise 4 PASSED")
        warmup_passed += 1
    except Exception as e: print(f"❌ Warm-up Exercise 4 FAILED: {e}")

    print(f"\nWarm-up Score: {warmup_passed}/{total_warmup_tests} exercises completed correctly.")
    return warmup_passed == total_warmup_tests

def test_main_file_io_functions(): # Renamed
    main_passed = True

    # Test process_user_list
    try:
        user_stats = process_user_list("users.csv") # Uses file from setup_test_files
        assert user_stats["total_users"] == 3
        assert "admin_user" in user_stats["admin_users"]
        print("✅ Main Test 1 (process_user_list): PASSED")
    except (NameError, AssertionError, TypeError, FileNotFoundError) as e:
        print(f"❌ Main Test 1 (process_user_list): FAILED - {e}")
        main_passed = False

    # Test process_security_alerts
    try:
        count = process_security_alerts("alerts.txt", "filtered_alerts.txt") # Uses file from setup
        assert count == 2 # CRITICAL and HIGH
        assert os.path.exists("filtered_alerts.txt")
        with open("filtered_alerts.txt", "r") as f: content = f.read()
        assert "CRITICAL" in content and "HIGH" in content and "LOW" not in content
        print("✅ Main Test 2 (process_security_alerts): PASSED")
    except (NameError, AssertionError, TypeError, FileNotFoundError) as e:
        print(f"❌ Main Test 2 (process_security_alerts): FAILED - {e}")
        main_passed = False

    # Test update_security_config
    try:
        updates = {"setting2": "new_value", "setting_new": "added_value"}
        assert update_security_config("config.ini", updates) is True # Uses file from setup
        with open("config.ini", "r") as f: content = f.read()
        assert "setting1=value1" in content and "setting2=new_value" in content and "setting_new=added_value" in content
        print("✅ Main Test 3 (update_security_config): PASSED")
    except (NameError, AssertionError, TypeError, FileNotFoundError) as e:
        print(f"❌ Main Test 3 (update_security_config): FAILED - {e}")
        main_passed = False

    # Test archive_old_logs
    try:
        # Create some additional dummy files for this specific test in current dir
        with open("dummy_archive_test1.log", "w") as f: f.write("dummy1")
        with open("dummy_archive_test2.txt", "w") as f: f.write("dummy2")
        archived = archive_old_logs(".", "main_test_archive.txt")
        assert "dummy_archive_test1.log" in archived
        assert "dummy_archive_test2.txt" in archived
        assert os.path.exists("main_test_archive.txt")
        with open("main_test_archive.txt", "r") as f: content = f.read()
        assert "dummy1" in content and "dummy2" in content
        print("✅ Main Test 4 (archive_old_logs): PASSED")
        # Clean up specific dummy files for this test
        if os.path.exists("dummy_archive_test1.log"): os.remove("dummy_archive_test1.log")
        if os.path.exists("dummy_archive_test2.txt"): os.remove("dummy_archive_test2.txt")
        if os.path.exists("main_test_archive.txt"): os.remove("main_test_archive.txt")
    except (NameError, AssertionError, TypeError, FileNotFoundError) as e:
        print(f"❌ Main Test 4 (archive_old_logs): FAILED - {e}")
        main_passed = False


    # Test generate_metrics_report
    try:
        # Need a dummy log file for analyze_security_log if it's called internally
        if not os.path.exists("dummy_metrics_log.log"):
             with open("dummy_metrics_log.log", "w") as f: f.write("INFO: app start\nCRITICAL: failure")

        metrics = generate_metrics_report("users.csv", "alerts.txt", "metrics_report_main.txt") # Uses files from setup
        assert isinstance(metrics, dict) and "total_users" in metrics and "critical_alert_count" in metrics
        assert metrics.get("total_users") == 3
        assert metrics.get("critical_alert_count") == 1 # From sample_alerts.txt
        assert os.path.exists("metrics_report_main.txt")
        print("✅ Main Test 5 (generate_metrics_report): PASSED")
        if os.path.exists("dummy_metrics_log.log"): os.remove("dummy_metrics_log.log")
        if os.path.exists("metrics_report_main.txt"): os.remove("metrics_report_main.txt")

    except (NameError, AssertionError, TypeError, FileNotFoundError) as e:
        print(f"❌ Main Test 5 (generate_metrics_report): FAILED - {e}")
        main_passed = False

    if main_passed:
        print("\n🎉 All Main Exercise function basic tests passed!")
    else:
        print("\n❌ Some Main Exercise function tests FAILED.")
    return main_passed

def run_all_tests(): # Renamed from test_file_io
    """Run all tests for Module 8."""
    setup_test_files() # Setup files once for all tests in this run

    print("="*50)
    print("RUNNING WARM-UP TESTS...")
    print("="*50)
    warmup_success = test_warmup_file_io()

    print("\n" + "="*50)
    print("RUNNING MAIN EXERCISE CHECKS (File I/O Functions)...") # Clarified
    print("="*50)
    main_exercise_success = test_main_file_io_functions() # Renamed

    # Run illustrative integrated tests if main functions are defined
    all_main_funcs_defined = True
    main_funcs_to_check = ['process_user_list', 'process_security_alerts', 'update_security_config', 'archive_old_logs', 'generate_metrics_report']
    for func_name in main_funcs_to_check:
        if func_name not in globals() or not callable(globals()[func_name]):
            all_main_funcs_defined = False
            print(f"Note: Main exercise function {func_name} not defined, skipping illustrative run_integrated_tests.")
            break
    if all_main_funcs_defined:
        run_integrated_tests() # This is illustrative, not strictly part of pass/fail criteria of this test function

    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    if warmup_success and main_exercise_success:
        print("\n✅ All warm-up and main exercise function tests passed!")
        print("You've successfully mastered Python File I/O!")
        print("Ready for Module 9: Error Handling")
    else:
        print("\n📚 Keep practicing! Review the failed tests or messages above.")
        if not warmup_success: print("- Some warm-up exercises have issues.")
        if not main_exercise_success: print("- The main exercise functions have issues or are missing.")

    cleanup_test_files() # Final cleanup

if __name__ == "__main__":
    run_all_tests()

# ============================================================================
# WHAT'S NEXT?
# ============================================================================
"""
Outstanding work completing Module 8! Here's what you learned:

✅ Reading files safely with proper file handling
✅ Writing and appending data to files
✅ Processing structured data (CSV, configuration files)
✅ Error handling for file operations
✅ Parsing and analyzing security log files
✅ Working with different file formats and structures
✅ Building comprehensive file management systems

CYBERSECURITY SKILLS GAINED:
- Configuration file management and updates
- Security log analysis and processing
- Alert management and filtering systems
- User account data processing
- Security metrics and reporting
- File archiving and data preservation
- Automated file processing workflows

FINAL MODULE: 09_error_handling.py
In the final module, you'll learn error handling - how to make your
cybersecurity scripts robust, reliable, and capable of handling unexpected
situations gracefully. This is crucial for production security tools!

You're almost ready to build professional cybersecurity automation! 🚀📊
"""
