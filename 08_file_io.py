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

# ============================================================================
# CONCEPT EXPLANATION: Basic File Reading
# ============================================================================

print("=== BASIC FILE READING ===")
print()

# First, let's create some sample files to work with
# Creating a sample configuration file
config_content = """# Security Configuration File
firewall_enabled=true
intrusion_detection=true
log_level=INFO
max_login_attempts=5
session_timeout=30
encryption_enabled=true
backup_frequency=daily
"""

# Write the config file
with open("security_config.txt", "w") as config_file:
    config_file.write(config_content)

print("Created sample security_config.txt file")

# Reading entire file content
print("\nReading entire file:")
with open("security_config.txt", "r") as file:
    content = file.read()
    print(content)

# Reading file line by line
print("Reading file line by line:")
with open("security_config.txt", "r") as file:
    for line_number, line in enumerate(file, 1):
        line = line.strip()  # Remove newline characters
        if line and not line.startswith("#"):  # Skip empty lines and comments
            print(f"Line {line_number}: {line}")

print()

# ============================================================================
# CONCEPT EXPLANATION: File Writing and Appending
# ============================================================================

print("=== FILE WRITING AND APPENDING ===")
print()

# Creating a security log file
print("Creating security incident log:")
incident_log = [
    "2023-10-01 09:15:23 WARNING: Multiple failed login attempts from 203.0.113.42",
    "2023-10-01 09:20:15 INFO: User alice_admin logged in successfully",
    "2023-10-01 09:25:33 ERROR: Database connection timeout",
    "2023-10-01 09:30:44 CRITICAL: Suspicious file detected in quarantine"
]

# Write initial log entries
with open("security_incidents.log", "w") as log_file:
    for entry in incident_log:
        log_file.write(entry + "\n")

print("Initial log file created with 4 entries")

# Append new entries to existing log
new_incidents = [
    "2023-10-01 09:35:12 WARNING: High CPU usage detected on web-server-01",
    "2023-10-01 09:40:28 INFO: Backup completed successfully"
]

with open("security_incidents.log", "a") as log_file:  # "a" for append mode
    for entry in new_incidents:
        log_file.write(entry + "\n")

print("Appended 2 new entries to log file")

# Read and display the complete log
print("\nComplete security incident log:")
with open("security_incidents.log", "r") as log_file:
    for line_num, line in enumerate(log_file, 1):
        print(f"{line_num:2d}: {line.strip()}")

print()

# ============================================================================
# CONCEPT EXPLANATION: Processing Structured Data
# ============================================================================

print("=== PROCESSING STRUCTURED DATA ===")
print()

# Create a CSV-like user access file
user_access_data = """username,role,last_login,failed_attempts,status
alice_admin,administrator,2023-10-01,0,active
bob_analyst,analyst,2023-09-30,2,active
charlie_guest,guest,2023-09-25,5,locked
david_manager,manager,2023-10-01,1,active
eve_intern,intern,2023-09-28,0,inactive
"""

with open("user_access.csv", "w") as csv_file:
    csv_file.write(user_access_data)

print("Created user access CSV file")

# Read and parse CSV data
print("\nUser Access Report:")
print("-" * 60)
with open("user_access.csv", "r") as csv_file:
    lines = csv_file.readlines()
    
    # Parse header
    header = lines[0].strip().split(",")
    print(f"{'Username':<15} {'Role':<12} {'Status':<8} {'Failed':<6}")
    print("-" * 60)
    
    # Parse data rows
    for line in lines[1:]:
        if line.strip():  # Skip empty lines
            fields = line.strip().split(",")
            username, role, last_login, failed_attempts, status = fields
            
            # Format output with status indicators
            status_icon = "✅" if status == "active" else "⚠️" if status == "locked" else "❌"
            failed_icon = "🔴" if int(failed_attempts) > 3 else "🟡" if int(failed_attempts) > 0 else "🟢"
            
            print(f"{username:<15} {role:<12} {status:<8} {failed_attempts:<6} {status_icon} {failed_icon}")

print()

# ============================================================================
# CONCEPT EXPLANATION: Error Handling with Files
# ============================================================================

print("=== ERROR HANDLING WITH FILES ===")
print()

def safe_read_file(filename):
    """Safely read a file with proper error handling."""
    try:
        with open(filename, "r") as file:
            return file.read()
    except FileNotFoundError:
        print(f"❌ Error: File '{filename}' not found")
        return None
    except PermissionError:
        print(f"❌ Error: Permission denied accessing '{filename}'")
        return None
    except Exception as e:
        print(f"❌ Error reading '{filename}': {e}")
        return None

def safe_write_file(filename, content):
    """Safely write to a file with proper error handling."""
    try:
        with open(filename, "w") as file:
            file.write(content)
        print(f"✅ Successfully wrote to '{filename}'")
        return True
    except PermissionError:
        print(f"❌ Error: Permission denied writing to '{filename}'")
        return False
    except Exception as e:
        print(f"❌ Error writing to '{filename}': {e}")
        return False

# Test safe file operations
print("Testing safe file operations:")
content = safe_read_file("security_config.txt")
if content:
    print("✅ Successfully read configuration file")

content = safe_read_file("nonexistent_file.txt")  # This will fail gracefully

result = safe_write_file("test_output.txt", "Test security data")
print()

# ============================================================================
# CONCEPT EXPLANATION: Processing Log Files
# ============================================================================

print("=== PROCESSING LOG FILES ===")
print()

def analyze_security_log(log_filename):
    """
    Analyze a security log file and extract statistics.
    
    Args:
        log_filename (str): Path to the log file
        
    Returns:
        dict: Analysis results
    """
    stats = {
        "total_entries": 0,
        "by_severity": {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0},
        "failed_logins": 0,
        "suspicious_ips": set(),
        "critical_events": []
    }
    
    try:
        with open(log_filename, "r") as log_file:
            for line in log_file:
                line = line.strip()
                if not line:
                    continue
                
                stats["total_entries"] += 1
                
                # Extract severity level
                for severity in stats["by_severity"].keys():
                    if severity in line:
                        stats["by_severity"][severity] += 1
                        break
                
                # Look for failed login attempts
                if "failed login" in line.lower():
                    stats["failed_logins"] += 1
                
                # Extract IP addresses from suspicious activities
                import re
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = re.findall(ip_pattern, line)
                if ips and ("failed" in line.lower() or "suspicious" in line.lower()):
                    stats["suspicious_ips"].update(ips)
                
                # Collect critical events
                if "CRITICAL" in line:
                    stats["critical_events"].append(line)
    
    except Exception as e:
        print(f"Error analyzing log file: {e}")
        return None
    
    # Convert set to list for JSON serialization
    stats["suspicious_ips"] = list(stats["suspicious_ips"])
    return stats

# Analyze our security log
print("Security Log Analysis:")
log_stats = analyze_security_log("security_incidents.log")

if log_stats:
    print(f"Total log entries: {log_stats['total_entries']}")
    print("\nEntries by severity:")
    for severity, count in log_stats['by_severity'].items():
        if count > 0:
            icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "ERROR" else "🟡" if severity == "WARNING" else "🟢"
            print(f"  {icon} {severity}: {count}")
    
    print(f"\nFailed login attempts: {log_stats['failed_logins']}")
    
    if log_stats['suspicious_ips']:
        print(f"Suspicious IP addresses: {', '.join(log_stats['suspicious_ips'])}")
    
    if log_stats['critical_events']:
        print(f"\nCritical events found:")
        for event in log_stats['critical_events']:
            print(f"  🚨 {event}")

print()

# ============================================================================
# HOW THIS APPLIES TO CYBERSECURITY ADMINISTRATION:
# ============================================================================
"""
CYBERSECURITY APPLICATIONS OF FILE I/O:

1. CONFIGURATION MANAGEMENT:
   - Read security policy files and system configurations
   - Parse firewall rules, access control lists, and security settings
   - Update configuration files based on security requirements
   - Backup and restore security configurations

2. LOG ANALYSIS AND MONITORING:
   - Process system logs, security logs, and application logs
   - Parse web server access logs for security patterns
   - Analyze firewall logs for intrusion attempts
   - Extract indicators of compromise (IOCs) from log files

3. INCIDENT RESPONSE AND FORENSICS:
   - Read memory dumps and disk images for evidence
   - Parse network packet captures (with appropriate libraries)
   - Process timeline data and system artifacts
   - Generate incident reports and documentation

4. THREAT INTELLIGENCE:
   - Read threat feed files (IOCs, malware signatures)
   - Process vulnerability databases and CVE lists
   - Import blacklists and reputation data
   - Export security findings and intelligence reports

5. COMPLIANCE AND REPORTING:
   - Generate security compliance reports
   - Process audit logs and compliance data
   - Create security metrics and dashboard data
   - Archive security documentation and evidence

6. AUTOMATION AND ORCHESTRATION:
   - Read input files for security automation scripts
   - Process batch security operations from files
   - Generate automated security reports
   - Store and retrieve security automation results
"""

print("=== CYBERSECURITY FILE PROCESSING EXAMPLES ===")

def parse_firewall_rules(rules_file):
    """Parse a firewall rules configuration file."""
    rules = []
    try:
        with open(rules_file, "r") as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if line and not line.startswith("#"):
                    # Simple rule format: ACTION SOURCE DEST PORT PROTOCOL
                    parts = line.split()
                    if len(parts) >= 4:
                        rule = {
                            "line": line_num,
                            "action": parts[0],
                            "source": parts[1],
                            "destination": parts[2],
                            "port": parts[3],
                            "protocol": parts[4] if len(parts) > 4 else "tcp"
                        }
                        rules.append(rule)
    except Exception as e:
        print(f"Error parsing firewall rules: {e}")
    
    return rules

def generate_security_report(log_stats, output_file):
    """Generate a comprehensive security report."""
    try:
        with open(output_file, "w") as report:
            report.write("SECURITY ANALYSIS REPORT\n")
            report.write("=" * 50 + "\n\n")
            
            report.write(f"Report Generated: 2023-10-01 16:30:00\n")
            report.write(f"Analysis Period: Last 24 hours\n\n")
            
            report.write("LOG ANALYSIS SUMMARY:\n")
            report.write("-" * 25 + "\n")
            report.write(f"Total Events: {log_stats['total_entries']}\n")
            
            for severity, count in log_stats['by_severity'].items():
                if count > 0:
                    report.write(f"{severity} Events: {count}\n")
            
            report.write(f"\nSECURITY INCIDENTS:\n")
            report.write("-" * 20 + "\n")
            report.write(f"Failed Login Attempts: {log_stats['failed_logins']}\n")
            
            if log_stats['suspicious_ips']:
                report.write(f"Suspicious IP Addresses:\n")
                for ip in log_stats['suspicious_ips']:
                    report.write(f"  - {ip}\n")
            
            if log_stats['critical_events']:
                report.write(f"\nCRITICAL EVENTS:\n")
                for event in log_stats['critical_events']:
                    report.write(f"  - {event}\n")
            
            report.write("\nRECOMMENDATIONS:\n")
            report.write("-" * 15 + "\n")
            if log_stats['failed_logins'] > 3:
                report.write("- Review and strengthen authentication policies\n")
            if log_stats['suspicious_ips']:
                report.write("- Consider blocking suspicious IP addresses\n")
            if log_stats['by_severity']['CRITICAL'] > 0:
                report.write("- Investigate critical events immediately\n")
            
            report.write("\nEND OF REPORT\n")
        
        print(f"✅ Security report generated: {output_file}")
        return True
    
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        return False

# Create sample firewall rules file
firewall_rules_content = """# Firewall Rules Configuration
# Format: ACTION SOURCE DEST PORT PROTOCOL

ALLOW 192.168.1.0/24 ANY 80 tcp
ALLOW 192.168.1.0/24 ANY 443 tcp
DENY ANY ANY 23 tcp
ALLOW 10.0.0.0/8 192.168.1.100 22 tcp
DENY 203.0.113.0/24 ANY ANY ANY
ALLOW ANY ANY 53 udp
"""

with open("firewall_rules.txt", "w") as fw_file:
    fw_file.write(firewall_rules_content)

print("Firewall Rules Analysis:")
fw_rules = parse_firewall_rules("firewall_rules.txt")
for rule in fw_rules:
    action_icon = "✅" if rule["action"] == "ALLOW" else "🚫"
    print(f"{action_icon} Line {rule['line']}: {rule['action']} {rule['source']} -> {rule['destination']}:{rule['port']}")

print()

# Generate comprehensive security report
if log_stats:
    generate_security_report(log_stats, "security_report.txt")
    
    # Display the generated report
    print("Generated Security Report:")
    print("-" * 30)
    with open("security_report.txt", "r") as report:
        print(report.read())

print()

# ============================================================================
# WARM-UP EXERCISES: Practice File Operations
# ============================================================================

# Exercise 1: Write a simple file
"""
PRACTICE: Basic File Writing

Your security monitoring system needs to create status log files.
Create a file called "test.txt" containing the status message "Security System Active".
Use the file writing function with "w" mode for creating new security logs.
This demonstrates basic security event logging for audit trails.
"""
# TODO: Create file "test.txt" with content "Security System Active"


# Exercise 2: Read a simple file
"""
PRACTICE: Basic File Reading

Your security operations center needs to read system status from log files.
Read the content from "test.txt" that contains the security system status.
Display the retrieved status information for operational awareness.
This shows how to access stored security information for monitoring.
"""
# TODO: Read and display content from "test.txt"


# Exercise 3: Append to a file
"""
PRACTICE: Appending to Files

Your security logging system needs to add new events to existing log files.
Append the status update "\nBackup completed" to the existing "test.txt" file.
Read and display the entire updated file content to verify the logging process.
This demonstrates continuous security event logging without overwriting existing data.
"""
# TODO: Append "\nBackup completed" to "test.txt" and display full content


# Exercise 4: Process file line by line
"""
PRACTICE: Line-by-Line Processing

Your infrastructure monitoring system needs to process server lists systematically.
Create a file called "servers.txt" containing three server entries:
web-server
mail-server  
file-server

Read the file line by line and display each server with "Checking: " prefix.
This shows automated server health verification from configuration files.
"""
# TODO: Create "servers.txt" with server list and process each line


print("\n" + "="*50)
print("WARM-UP COMPLETE - NOW THE MAIN EXERCISE")
print("="*50 + "\n")

# ============================================================================
# YOUR MAIN EXERCISE: Build a Security File Management System
# ============================================================================
"""
SECURITY FILE MANAGEMENT SYSTEM

You are developing a comprehensive file management system for security operations that 
handles user data, security alerts, configuration management, log archiving, and metrics 
reporting. The system must process various file formats and generate actionable security 
intelligence.

USER ACCOUNT DATA PROCESSOR:
Create a function named process_user_list that analyzes user account data from CSV files. 
The system receives user data in CSV format with columns for username, role, email, last 
login date, and account status. Process this data to categorize users as active or inactive, 
identify administrative accounts (users with "admin" or "administrator" roles), and provide 
user statistics for security auditing.

SECURITY ALERT FILTERING SYSTEM:
Create a function named process_security_alerts that processes security incident data. 
The system receives alert data where each line contains timestamp, severity level, source 
system, and description separated by pipe characters. Filter and extract only high-priority 
alerts (those marked as "HIGH" or "CRITICAL" severity) and format them into a readable 
report for incident response teams.

CONFIGURATION MANAGEMENT TOOL:
Create a function named update_security_config that manages security configuration files. 
The system works with configuration files using "key=value" format and must update specific 
settings while preserving existing configurations and comments (lines starting with #). 
The function should safely modify configuration values and maintain file integrity.

LOG ARCHIVE SYSTEM:
Create a function named archive_old_logs that consolidates security logs for long-term 
storage. The system should locate all log files (.log and .txt extensions) in the current 
directory, combine them into a single archive file with proper timestamps and source 
identification, and return a list of successfully archived files.

SECURITY METRICS ANALYZER:
Create a function named generate_metrics_report that produces comprehensive security 
analytics by combining data from multiple sources. Calculate key security metrics including 
user account health ratios, alert volume and severity distributions, and system activity 
levels. Generate a detailed metrics report file and return summary statistics for 
management dashboards.

INTEGRATED TESTING FRAMEWORK:
Implement a complete testing system that creates sample data files representing realistic 
security scenarios: a user database with mixed account types and statuses, security alerts 
with various severity levels, and system configuration files. Test all functions with this 
data and demonstrate the complete file processing workflow.
"""

# YOUR CODE GOES HERE
# ============================================================================

print("=== SECURITY FILE MANAGEMENT SYSTEM ===")
print()

# PART 1: User Management File Operations
# TODO: Create process_user_list function
# TODO: Create your process_user_list function here

# PART 2: Security Alert File Processing
# TODO: Create process_security_alerts function
# TODO: Create your process_security_alerts function here

# PART 3: Configuration File Management
# TODO: Create update_security_config function
def update_security_config(config_file, updates):
    """
    Update security configuration file with new values.
    
    Args:
        config_file (str): Path to configuration file
        updates (dict): Dictionary of key-value pairs to update
        
    Returns:
        bool: True if successful, False if error
    """
    try:
        # Read current configuration
        with open(config_file, "r") as file:
            lines = file.readlines()
        
        # Process and update lines
        updated_lines = []
        updated_keys = set()
        
        for line in lines:
            stripped_line = line.strip()
            
            # Preserve comments and empty lines
            if not stripped_line or stripped_line.startswith("#"):
                updated_lines.append(line)
                continue
            
            # Process key=value lines
            if "=" in stripped_line:
                key, value = stripped_line.split("=", 1)
                key = key.strip()
                
                if key in updates:
                    updated_lines.append(f"{key}={updates[key]}\n")
                    updated_keys.add(key)
                else:
                    updated_lines.append(line)
            else:
                updated_lines.append(line)
        
        # Add any new keys that weren't in the original file
        for key, value in updates.items():
            if key not in updated_keys:
                updated_lines.append(f"{key}={value}\n")
        
        # Write updated configuration
        with open(config_file, "w") as file:
            file.writelines(updated_lines)
        
        return True
    
    except Exception as e:
        print(f"Error updating configuration: {e}")
        return False

# PART 4: Log File Archiving
# TODO: Create archive_old_logs function
def archive_old_logs(source_dir, archive_file):
    """
    Archive log files into a single file.
    
    Args:
        source_dir (str): Directory to scan (use "." for current)
        archive_file (str): Output archive file
        
    Returns:
        list: List of files that were archived
    """
    import os
    from datetime import datetime
    
    archived_files = []
    
    try:
        with open(archive_file, "w") as archive:
            archive.write("SECURITY LOG ARCHIVE\n")
            archive.write("=" * 30 + "\n")
            archive.write(f"Archive created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Get all .log and .txt files in current directory
            for filename in os.listdir("."):
                if filename.endswith((".log", ".txt")) and filename != archive_file:
                    try:
                        with open(filename, "r") as logfile:
                            content = logfile.read()
                            
                            archive.write(f"[{filename}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                            archive.write("-" * 50 + "\n")
                            archive.write(content)
                            archive.write("\n" + "=" * 50 + "\n\n")
                            
                            archived_files.append(filename)
                    
                    except Exception as e:
                        archive.write(f"[{filename}] ERROR: Could not read file - {e}\n\n")
        
        return archived_files
    
    except Exception as e:
        print(f"Error creating archive: {e}")
        return []

# PART 5: Security Metrics Report
# TODO: Create generate_metrics_report function
def generate_metrics_report(user_file, alert_file, log_file):
    """
    Generate comprehensive security metrics report.
    
    Args:
        user_file (str): User data CSV file
        alert_file (str): Security alerts file
        log_file (str): System log file
        
    Returns:
        dict: Summary of key metrics
    """
    metrics = {}
    
    try:
        # Process user data
        user_data = process_user_list(user_file)
        active_ratio = len(user_data["active_users"]) / max(user_data["total_users"], 1) * 100
        admin_ratio = len(user_data["admin_users"]) / max(user_data["total_users"], 1) * 100
        
        # Process log data (simple analysis)
        log_analysis = analyze_security_log(log_file)
        
        # Calculate metrics
        metrics = {
            "total_users": user_data["total_users"],
            "active_user_ratio": round(active_ratio, 1),
            "admin_user_ratio": round(admin_ratio, 1),
            "total_log_events": log_analysis["total_entries"] if log_analysis else 0,
            "critical_events": len(log_analysis["critical_events"]) if log_analysis else 0,
            "suspicious_ips": len(log_analysis["suspicious_ips"]) if log_analysis else 0
        }
        
        # Generate report
        with open("security_metrics.txt", "w") as report:
            report.write("SECURITY METRICS DASHBOARD\n")
            report.write("=" * 35 + "\n\n")
            
            report.write("USER ACCOUNT METRICS:\n")
            report.write("-" * 20 + "\n")
            report.write(f"Total User Accounts: {metrics['total_users']}\n")
            report.write(f"Active Users: {len(user_data['active_users'])} ({metrics['active_user_ratio']}%)\n")
            report.write(f"Inactive Users: {len(user_data['inactive_users'])}\n")
            report.write(f"Administrative Users: {len(user_data['admin_users'])} ({metrics['admin_user_ratio']}%)\n\n")
            
            report.write("SECURITY EVENT METRICS:\n")
            report.write("-" * 23 + "\n")
            report.write(f"Total Log Events: {metrics['total_log_events']}\n")
            report.write(f"Critical Events: {metrics['critical_events']}\n")
            report.write(f"Suspicious IP Addresses: {metrics['suspicious_ips']}\n\n")
            
            # Security health assessment
            health_score = 100
            if metrics['active_user_ratio'] < 80:
                health_score -= 20
            if metrics['critical_events'] > 0:
                health_score -= 30
            if metrics['suspicious_ips'] > 2:
                health_score -= 25
            
            report.write("SECURITY HEALTH ASSESSMENT:\n")
            report.write("-" * 27 + "\n")
            report.write(f"Overall Security Score: {health_score}/100\n")
            
            if health_score >= 90:
                report.write("Status: EXCELLENT - Security posture is strong\n")
            elif health_score >= 70:
                report.write("Status: GOOD - Minor improvements recommended\n")
            elif health_score >= 50:
                report.write("Status: FAIR - Several security concerns need attention\n")
            else:
                report.write("Status: POOR - Immediate security improvements required\n")
        
        return metrics
    
    except Exception as e:
        print(f"Error generating metrics report: {e}")
        return {}

# PART 6: Integration and Testing
# TODO: Create sample data files and test all functions
print("6. CREATING SAMPLE DATA AND TESTING FUNCTIONS:")
print("-" * 50)

# Create sample users CSV
sample_users_csv = """username,role,email,last_login,status
alice_admin,administrator,alice@company.com,2023-10-01,active
bob_analyst,analyst,bob@company.com,2023-09-30,active
charlie_guest,guest,charlie@company.com,2023-09-25,inactive
david_manager,manager,david@company.com,2023-10-01,active
eve_user,user,eve@company.com,2023-09-28,inactive
"""

with open("sample_users.csv", "w") as f:
    f.write(sample_users_csv)

# Create sample alerts file
sample_alerts = """2023-10-01 09:15:23|LOW|firewall|Regular traffic pattern detected
2023-10-01 09:20:15|HIGH|ids|Multiple failed login attempts detected
2023-10-01 09:25:33|MEDIUM|antivirus|Suspicious file quarantined
2023-10-01 09:30:44|CRITICAL|system|Unauthorized root access detected
2023-10-01 09:35:12|LOW|backup|Scheduled backup completed
2023-10-01 09:40:28|HIGH|network|Unusual outbound traffic detected
"""

with open("sample_alerts.txt", "w") as f:
    f.write(sample_alerts)

# Create sample configuration file
sample_config = """# Security Configuration Settings
firewall_enabled=true
max_login_attempts=5
session_timeout=30
logging_level=INFO
"""

with open("sample_config.txt", "w") as f:
    f.write(sample_config)

# Test all functions
print("Testing process_user_list:")
user_results = process_user_list("sample_users.csv")
print(f"  Total users: {user_results['total_users']}")
print(f"  Active users: {len(user_results['active_users'])}")
print(f"  Admin users: {user_results['admin_users']}")
print()

print("Testing process_security_alerts:")
alert_count = process_security_alerts("sample_alerts.txt", "high_priority_alerts.txt")
print(f"  High-priority alerts processed: {alert_count}")
print()

print("Testing update_security_config:")
config_updates = {"max_login_attempts": "3", "encryption_enabled": "true"}
config_success = update_security_config("sample_config.txt", config_updates)
print(f"  Configuration update successful: {config_success}")
print()

print("Testing archive_old_logs:")
archived_files = archive_old_logs(".", "logs_archive.txt")
print(f"  Files archived: {len(archived_files)}")
print(f"  Archived files: {', '.join(archived_files[:3])}...")  # Show first 3
print()

print("Testing generate_metrics_report:")
metrics = generate_metrics_report("sample_users.csv", "sample_alerts.txt", "security_incidents.log")
if metrics:
    print(f"  Security score calculated: {100 - (metrics['critical_events'] * 30)}/100")
    print(f"  Total events analyzed: {metrics['total_log_events']}")

print("\n✅ All file management functions tested successfully!")

# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_file_io():
    """Test function to verify your file I/O implementations are correct."""
    
    try:
        # Test Part 1: User list processing
        user_result = process_user_list("sample_users.csv")
        assert "active_users" in user_result, "process_user_list should return dictionary with 'active_users' key"
        assert "total_users" in user_result, "process_user_list should return dictionary with 'total_users' key"
        assert user_result["total_users"] == 5, f"Should process 5 users, got {user_result['total_users']}"
        print("✅ Test 1 PASSED: process_user_list function works correctly")
        
        # Test Part 2: Security alerts processing
        alert_count = process_security_alerts("sample_alerts.txt", "test_alerts_output.txt")
        assert alert_count > 0, "Should process some high-priority alerts"
        assert isinstance(alert_count, int), "Should return integer count"
        print("✅ Test 2 PASSED: process_security_alerts function works correctly")
        
        # Test Part 3: Configuration update
        test_updates = {"test_key": "test_value"}
        config_result = update_security_config("sample_config.txt", test_updates)
        assert isinstance(config_result, bool), "update_security_config should return boolean"
        print("✅ Test 3 PASSED: update_security_config function works correctly")
        
        # Test Part 4: Log archiving
        archived = archive_old_logs(".", "test_archive.txt")
        assert isinstance(archived, list), "archive_old_logs should return list of files"
        print("✅ Test 4 PASSED: archive_old_logs function works correctly")
        
        # Test Part 5: Metrics report generation
        metrics_result = generate_metrics_report("sample_users.csv", "sample_alerts.txt", "security_incidents.log")
        assert isinstance(metrics_result, dict), "generate_metrics_report should return dictionary"
        assert "total_users" in metrics_result, "Metrics should include total_users"
        print("✅ Test 5 PASSED: generate_metrics_report function works correctly")
        
        print("\n🎉 CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python File I/O!")
        print("Ready for Module 9: Error Handling")
        
    except NameError as e:
        print(f"❌ ERROR: Function not found - {e}")
        print("Make sure you've defined all required functions.")
    except AssertionError as e:
        print(f"❌ TEST FAILED: {e}")
        print("Check your function implementations and try again.")
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")

# Run the tests
test_file_io()

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
