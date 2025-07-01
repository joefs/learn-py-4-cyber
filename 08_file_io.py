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
# HELPER FUNCTIONS (These might be used by your main exercise functions)
# ============================================================================
def analyze_security_log(log_filename):
    """
    Analyze a security log file and extract statistics.
    (This is a helper, can be adapted or used by your main exercise functions)
    """
    stats = {
        "total_entries": 0,
        "by_severity": {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0},
        "failed_logins": 0,
        "suspicious_ips": set(),
        "critical_events": []
    }
    if not os.path.exists(log_filename):
        return stats # Return default stats if log file doesn't exist

    try:
        with open(log_filename, "r") as log_file:
            for line in log_file:
                line = line.strip()
                if not line: continue
                stats["total_entries"] += 1
                for severity in stats["by_severity"].keys():
                    if severity in line:
                        stats["by_severity"][severity] += 1
                        break
                if "failed login" in line.lower(): stats["failed_logins"] += 1
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = re.findall(ip_pattern, line)
                if ips and ("failed" in line.lower() or "suspicious" in line.lower()):
                    stats["suspicious_ips"].update(ips)
                if "CRITICAL" in line: stats["critical_events"].append(line)
    except Exception: # Basic error handling for helper
        pass # In a real scenario, log this error
    stats["suspicious_ips"] = list(stats["suspicious_ips"])
    return stats

# ============================================================================
# WARM-UP EXERCISES: Practice File Operations
# ============================================================================

# Exercise 1: Write a simple file
"""
PRACTICE: Basic File Writing

Write a function `write_status_to_file(filename, status_message)` that
creates a file named `filename` and writes the `status_message` into it.
The function should return True if successful, False otherwise.
"""
# TODO: Implement write_status_to_file
def write_status_to_file(filename, status_message):
    pass

# Exercise 2: Read a simple file
"""
PRACTICE: Basic File Reading

Write a function `read_status_from_file(filename)` that reads and
returns the entire content of the specified `filename`.
If the file doesn't exist, it should return None.
"""
# TODO: Implement read_status_from_file
def read_status_from_file(filename):
    pass

# Exercise 3: Append to a file
"""
PRACTICE: Appending to Files

Write a function `append_log_to_file(filename, log_message)` that
appends the `log_message` (prefixed with a newline character if the
file is not empty) to the specified `filename`.
Returns True if successful, False otherwise.
"""
# TODO: Implement append_log_to_file
def append_log_to_file(filename, log_message):
    pass

# Exercise 4: Process file line by line
"""
PRACTICE: Line-by-Line Processing

Write a function `get_servers_from_file(filename)` that reads `filename`
line by line. Each line is expected to be a server name.
The function should return a list of strings, where each string is
"Checking: [server_name]". Skip empty lines.
If the file doesn't exist, return an empty list.
"""
# TODO: Implement get_servers_from_file
def get_servers_from_file(filename):
    pass

# ============================================================================
# YOUR MAIN EXERCISE: Build a Security File Management System
# ============================================================================
"""
USER ACCOUNT DATA PROCESSOR:
`process_user_list(csv_filepath)`:
  Input: Path to a CSV file (e.g., "users.csv").
  CSV Format: username,role,email,last_login_date,status (active/inactive)
  Output: A dictionary with:
    "total_users": count
    "active_users": list of usernames
    "inactive_users": list of usernames
    "admin_users": list of usernames (role is "admin" or "administrator")

SECURITY ALERT FILTERING SYSTEM:
`process_security_alerts(alerts_filepath, output_report_filepath)`:
  Input: Path to an alerts file, path for the output report.
  Alerts File Format: Each line is "timestamp|severity|source_system|description"
  Task: Filter for "HIGH" or "CRITICAL" severity alerts.
        Write these filtered alerts to `output_report_filepath`, one alert per line,
        formatted as: "ALERT: [timestamp] - [severity] - [source] - [description]".
  Output: Count of high-priority alerts processed.

CONFIGURATION MANAGEMENT TOOL:
`update_security_config(config_filepath, updates_dict)`:
  Input: Path to a config file, dictionary of updates `{"key_to_update": "new_value"}`.
  Config File Format: "key=value" per line. Lines starting with "#" are comments.
  Task: Update values for keys present in `updates_dict`. Add new key-value pairs
        if a key in `updates_dict` is not in the file. Preserve comments and structure.
  Output: True if successful, False on error.

LOG ARCHIVE SYSTEM:
`archive_old_logs(source_directory, archive_filepath)`:
  Input: Directory path, path for the output archive file.
  Task: Find all ".log" and ".txt" files in `source_directory` (excluding the
        `archive_filepath` itself). Append their content to `archive_filepath`.
        Each appended file's content should be preceded by a header like:
        "--- Start of [filename] (Archived: YYYY-MM-DD HH:MM:SS) ---"
        and followed by "--- End of [filename] ---".
  Output: List of filenames successfully archived.

SECURITY METRICS ANALYZER:
`generate_metrics_report(user_csv_filepath, alerts_filepath, output_metrics_filepath)`:
  Input: Paths to user CSV, alerts file, and path for output metrics report.
  Task: Use `process_user_list` and `process_security_alerts` (or similar logic for alerts).
        Calculate metrics:
          - User metrics: total_users, active_user_percentage, admin_user_count.
          - Alert metrics: total_alerts_in_file, high_priority_alert_count,
                           critical_alert_count (from alerts_filepath).
        Write these metrics to `output_metrics_filepath` in a readable format.
  Output: A dictionary containing the calculated metrics.
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
def generate_metrics_report(user_csv_filepath, alerts_filepath, output_metrics_filepath):
    pass


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================
# Setup for tests - Create dummy files
def setup_test_files():
    # Warmup files
    with open("warmup_test.txt", "w") as f: f.write("Initial content.")
    with open("warmup_servers.txt", "w") as f: f.write("serverA\nserverB\n\nserverC")

    # Main exercise files
    user_data_csv = "username,role,email,last_login,status\nadmin_user,admin,a@e.com,2023-01-01,active\nnormal_user,user,n@e.com,2023-01-02,active\ninactive_user,user,i@e.com,2022-01-01,inactive"
    with open("users.csv", "w") as f: f.write(user_data_csv)

    alerts_data = "2023-01-01T10:00:00Z|CRITICAL|app01|System breach\n2023-01-01T11:00:00Z|LOW|db01|Low disk space\n2023-01-01T12:00:00Z|HIGH|net01|DDoS attempt"
    with open("alerts.txt", "w") as f: f.write(alerts_data)

    config_data = "# System Config\nkey1=value1\nkey2=old_value"
    with open("config.ini", "w") as f: f.write(config_data)

    with open("log1.log", "w") as f: f.write("Log entry 1")
    with open("log2.txt", "w") as f: f.write("Text entry 2")
    if os.path.exists("archive.zip"): os.remove("archive.zip") # Ensure no old archive for test

def cleanup_test_files():
    files_to_delete = [
        "warmup_test.txt", "warmup_servers.txt", "users.csv", "alerts.txt",
        "config.ini", "log1.log", "log2.txt", "archive.zip",
        "filtered_alerts.txt", "metrics_report.txt", "test_archive.txt" # Files created by functions
    ]
    for f_name in files_to_delete:
        if os.path.exists(f_name):
            try:
                os.remove(f_name)
            except OSError:
                pass # Ignore if deletion fails (e.g. file still open on Windows)

def test_warmup_file_io():
    warmup_passed = 0
    total_warmup_tests = 4
    setup_test_files()

    # Test 1
    try:
        assert write_status_to_file("warmup_test.txt", "Security System Active") is True
        with open("warmup_test.txt", "r") as f: assert f.read() == "Security System Active"
        print("✅ Warm-up Exercise 1 PASSED")
        warmup_passed += 1
    except Exception as e: print(f"❌ Warm-up Exercise 1 FAILED: {e}")

    # Test 2
    try:
        assert read_status_from_file("warmup_test.txt") == "Security System Active"
        assert read_status_from_file("non_existent.txt") is None
        print("✅ Warm-up Exercise 2 PASSED")
        warmup_passed += 1
    except Exception as e: print(f"❌ Warm-up Exercise 2 FAILED: {e}")

    # Test 3
    try:
        write_status_to_file("warmup_test.txt", "First line.") # Reset file
        assert append_log_to_file("warmup_test.txt", "Second line.") is True
        with open("warmup_test.txt", "r") as f: assert f.read() == "First line.\nSecond line."
        print("✅ Warm-up Exercise 3 PASSED")
        warmup_passed += 1
    except Exception as e: print(f"❌ Warm-up Exercise 3 FAILED: {e}")

    # Test 4
    try:
        expected_lines = ["Checking: serverA", "Checking: serverB", "Checking: serverC"]
        assert get_servers_from_file("warmup_servers.txt") == expected_lines
        assert get_servers_from_file("non_existent_servers.txt") == []
        print("✅ Warm-up Exercise 4 PASSED")
        warmup_passed += 1
    except Exception as e: print(f"❌ Warm-up Exercise 4 FAILED: {e}")

    print(f"\nWarm-up Score: {warmup_passed}/{total_warmup_tests} exercises completed correctly.")
    # cleanup_test_files() # Keep files for main tests if they rely on them
    return warmup_passed == total_warmup_tests

def test_main_file_management_system():
    main_passed = True
    # setup_test_files() is called by the outer test runner now

    # Test process_user_list
    try:
        user_stats = process_user_list("users.csv")
        assert user_stats["total_users"] == 3
        assert "admin_user" in user_stats["active_users"]
        assert "inactive_user" in user_stats["inactive_users"]
        assert "admin_user" in user_stats["admin_users"]
        print("✅ Main Test 1 PASSED: process_user_list")
    except Exception as e:
        print(f"❌ Main Test 1 FAILED: process_user_list - {e}")
        main_passed = False

    # Test process_security_alerts
    try:
        count = process_security_alerts("alerts.txt", "filtered_alerts.txt")
        assert count == 2 # CRITICAL and HIGH
        with open("filtered_alerts.txt", "r") as f:
            content = f.read()
            assert "CRITICAL" in content and "HIGH" in content and "LOW" not in content
        print("✅ Main Test 2 PASSED: process_security_alerts")
    except Exception as e:
        print(f"❌ Main Test 2 FAILED: process_security_alerts - {e}")
        main_passed = False

    # Test update_security_config
    try:
        updates = {"key2": "new_value", "key3": "value3"}
        assert update_security_config("config.ini", updates) is True
        with open("config.ini", "r") as f:
            content = f.read()
            assert "key1=value1" in content
            assert "key2=new_value" in content
            assert "key3=value3" in content
            assert "# System Config" in content
        print("✅ Main Test 3 PASSED: update_security_config")
    except Exception as e:
        print(f"❌ Main Test 3 FAILED: update_security_config - {e}")
        main_passed = False

    # Test archive_old_logs
    try:
        archived = archive_old_logs(".", "test_archive.txt")
        assert "log1.log" in archived and "log2.txt" in archived
        with open("test_archive.txt", "r") as f:
            content = f.read()
            assert "Log entry 1" in content and "Text entry 2" in content
            assert "--- Start of log1.log" in content
        print("✅ Main Test 4 PASSED: archive_old_logs")
    except Exception as e:
        print(f"❌ Main Test 4 FAILED: archive_old_logs - {e}")
        main_passed = False

    # Test generate_metrics_report
    try:
        metrics = generate_metrics_report("users.csv", "alerts.txt", "metrics_report.txt")
        assert metrics["total_users"] == 3
        assert metrics["admin_user_count"] == 1
        assert metrics["high_priority_alert_count"] == 2 # Assuming CRITICAL and HIGH
        assert metrics["critical_alert_count"] == 1
        assert os.path.exists("metrics_report.txt")
        print("✅ Main Test 5 PASSED: generate_metrics_report")
    except Exception as e:
        print(f"❌ Main Test 5 FAILED: generate_metrics_report - {e}")
        main_passed = False

    if main_passed: print("\n🎉 ALL MAIN EXERCISE TESTS PASSED (basic functionality)!")
    else: print("\n❌ SOME MAIN EXERCISE TESTS FAILED.")
    # cleanup_test_files() # Cleanup after all tests
    return main_passed

def run_all_tests():
    """Run all tests for Module 8."""
    setup_test_files() # Setup files once for all tests in this run
    
    print("="*50)
    print("RUNNING WARM-UP TESTS...")
    print("="*50)
    warmup_success = test_warmup_file_io()

    print("\n" + "="*50)
    print("RUNNING MAIN EXERCISE CHECKS...")
    print("="*50)
    main_exercise_success = test_main_file_management_system()

    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    if warmup_success and main_exercise_success:
        print("\n✅ All warm-up and main exercise tests passed!")
        print("You've successfully mastered Python File I/O!")
        print("Ready for Module 9: Error Handling")
    else:
        print("\n📚 Keep practicing! Review the failed tests or checks above.")
        if not warmup_success: print("- Some warm-up exercises have issues.")
        if not main_exercise_success: print("- The main exercise has issues or missing functions.")

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
