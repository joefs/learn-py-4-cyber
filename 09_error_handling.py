"""
====================================================================
MODULE 9: ERROR HANDLING - Building Robust Security Tools 🛡️
====================================================================

Welcome to the final module! You've learned all the core Python concepts.
Now you'll master error handling - the critical skill that makes your
cybersecurity tools robust, reliable, and ready for real-world deployment.

WHAT IS ERROR HANDLING?
Error handling lets your programs gracefully manage unexpected situations:
network failures, missing files, invalid data, or system errors. In
cybersecurity, robust error handling is essential because your tools must
work reliably even when systems are under attack or compromised.

ERROR HANDLING CONCEPTS WE'LL COVER:
- Understanding different types of errors
- try/except blocks for catching errors
- Multiple exception types and specific handling
- finally blocks for cleanup operations
- Custom exceptions for security scenarios
- Best practices for robust cybersecurity tools
"""

# ============================================================================
# CONCEPT EXPLANATION: Types of Errors and Basic try/except
# ============================================================================

print("=== UNDERSTANDING ERRORS AND BASIC ERROR HANDLING ===")
print()

# First, let's see what happens without error handling
print("Examples of common errors (handled safely):")

# NameError example
try:
    print(undefined_variable)
except NameError as e:
    print(f"NameError caught: {e}")

# TypeError example  
try:
    result = "text" + 5
except TypeError as e:
    print(f"TypeError caught: {e}")

# ValueError example
try:
    number = int("not_a_number")
except ValueError as e:
    print(f"ValueError caught: {e}")

# ZeroDivisionError example
try:
    result = 10 / 0
except ZeroDivisionError as e:
    print(f"ZeroDivisionError caught: {e}")

print()

# Basic try/except structure
def safe_division(a, b):
    """Safely divide two numbers with error handling."""
    try:
        result = a / b
        print(f"Division successful: {a} / {b} = {result}")
        return result
    except ZeroDivisionError:
        print("❌ Error: Cannot divide by zero!")
        return None
    except TypeError:
        print("❌ Error: Both arguments must be numbers!")
        return None

print("Safe division examples:")
safe_division(10, 2)    # Normal case
safe_division(10, 0)    # Division by zero
safe_division(10, "a")  # Type error
print()

# ============================================================================
# CONCEPT EXPLANATION: Multiple Exception Types
# ============================================================================

print("=== HANDLING MULTIPLE EXCEPTION TYPES ===")
print()

def process_security_data(data_list, index):
    """Process security data with comprehensive error handling."""
    try:
        # This might raise IndexError if index is out of range
        item = data_list[index]
        
        # This might raise ValueError if item can't be converted to int
        numeric_value = int(item)
        
        # This might raise ZeroDivisionError
        result = 100 / numeric_value
        
        print(f"✅ Processing successful: 100 / {numeric_value} = {result}")
        return result
        
    except IndexError:
        print(f"❌ IndexError: Index {index} is out of range for list of length {len(data_list)}")
        return None
    except ValueError:
        print(f"❌ ValueError: '{item}' cannot be converted to a number")
        return None
    except ZeroDivisionError:
        print(f"❌ ZeroDivisionError: Cannot divide by zero (value was {item})")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

# Test with different error scenarios
security_data = ["5", "10", "0", "invalid", "2"]

print("Testing multiple exception handling:")
process_security_data(security_data, 0)  # Normal case
process_security_data(security_data, 2)  # Division by zero
process_security_data(security_data, 3)  # Value error
process_security_data(security_data, 10) # Index error
print()

# ============================================================================
# CONCEPT EXPLANATION: finally Block and Resource Management
# ============================================================================

print("=== FINALLY BLOCKS AND RESOURCE CLEANUP ===")
print()

def secure_file_processing(filename):
    """Process a file with proper resource cleanup."""
    file_handle = None
    try:
        print(f"Opening file: {filename}")
        file_handle = open(filename, "r")
        
        print("Processing file content...")
        content = file_handle.read()
        
        # Simulate some processing that might fail
        if "ERROR" in content:
            raise ValueError("Error content detected in file")
        
        print(f"✅ File processed successfully, {len(content)} characters read")
        return content
        
    except FileNotFoundError:
        print(f"❌ Error: File '{filename}' not found")
        return None
    except PermissionError:
        print(f"❌ Error: Permission denied accessing '{filename}'")
        return None
    except ValueError as e:
        print(f"❌ Processing error: {e}")
        return None
    finally:
        # This block ALWAYS executes, even if an error occurs
        if file_handle:
            print("Closing file handle...")
            file_handle.close()
        print("Cleanup completed")

# Create a test file for demonstration
with open("test_security_log.txt", "w") as f:
    f.write("2023-10-01 INFO: System startup\n2023-10-01 WARNING: High CPU usage")

print("Testing file processing with cleanup:")
secure_file_processing("test_security_log.txt")  # Normal case
print()
secure_file_processing("nonexistent_file.txt")   # File not found
print()

# ============================================================================
# CONCEPT EXPLANATION: Custom Exceptions
# ============================================================================

print("=== CUSTOM EXCEPTIONS FOR SECURITY SCENARIOS ===")
print()

# Define custom exception classes for cybersecurity scenarios
class SecurityException(Exception):
    """Base exception for security-related errors."""
    pass

class AuthenticationError(SecurityException):
    """Raised when authentication fails."""
    pass

class AuthorizationError(SecurityException):
    """Raised when user lacks required permissions."""
    pass

class SecurityPolicyViolation(SecurityException):
    """Raised when a security policy is violated."""
    pass

class ThreatDetected(SecurityException):
    """Raised when a security threat is detected."""
    pass

def authenticate_user(username, password, ip_address):
    """Authenticate a user with security checks."""
    try:
        # Simulate authentication logic
        valid_users = {"admin": "secure123", "analyst": "password456"}
        blocked_ips = ["203.0.113.42", "198.51.100.1"]
        
        # Check for blocked IP
        if ip_address in blocked_ips:
            raise ThreatDetected(f"Login attempt from blocked IP: {ip_address}")
        
        # Check credentials
        if username not in valid_users:
            raise AuthenticationError(f"Unknown user: {username}")
        
        if valid_users[username] != password:
            raise AuthenticationError(f"Invalid password for user: {username}")
        
        # Check for admin access from external IP
        if username == "admin" and not ip_address.startswith("192.168."):
            raise AuthorizationError("Admin access only allowed from internal network")
        
        print(f"✅ Authentication successful for {username} from {ip_address}")
        return True
        
    except ThreatDetected as e:
        print(f"🚨 THREAT ALERT: {e}")
        return False
    except AuthenticationError as e:
        print(f"🔐 AUTH FAILED: {e}")
        return False
    except AuthorizationError as e:
        print(f"⛔ ACCESS DENIED: {e}")
        return False
    except Exception as e:
        print(f"❌ SYSTEM ERROR: {e}")
        return False

print("Testing custom exception handling:")
authenticate_user("admin", "secure123", "192.168.1.100")    # Success
authenticate_user("admin", "wrong_password", "192.168.1.100") # Auth error
authenticate_user("admin", "secure123", "203.0.113.42")     # Threat detected
authenticate_user("unknown", "password", "192.168.1.100")   # Unknown user
print()

# ============================================================================
# CONCEPT EXPLANATION: Error Logging and Monitoring
# ============================================================================

print("=== ERROR LOGGING AND MONITORING ===")
print()

import datetime

def log_security_event(event_type, message, severity="INFO"):
    """Log security events with timestamp and severity."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{severity}] [{event_type}] {message}"
    
    try:
        with open("security_events.log", "a") as log_file:
            log_file.write(log_entry + "\n")
    except Exception as e:
        print(f"Failed to write to log file: {e}")

def robust_network_scan(ip_address, port):
    """Perform network scan with comprehensive error handling and logging."""
    try:
        log_security_event("NETWORK_SCAN", f"Starting scan of {ip_address}:{port}")
        
        # Validate IP address format
        ip_parts = ip_address.split(".")
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address format")
        
        for part in ip_parts:
            if not (0 <= int(part) <= 255):
                raise ValueError("IP address octets must be 0-255")
        
        # Validate port number
        if not (1 <= port <= 65535):
            raise ValueError("Port number must be 1-65535")
        
        # Simulate network scan (random result for demo)
        import random
        if random.choice([True, False]):
            result = "OPEN"
            log_security_event("NETWORK_SCAN", f"Port {port} OPEN on {ip_address}", "INFO")
        else:
            result = "CLOSED"
            log_security_event("NETWORK_SCAN", f"Port {port} CLOSED on {ip_address}", "INFO")
        
        print(f"✅ Scan complete: {ip_address}:{port} is {result}")
        return result
        
    except ValueError as e:
        error_msg = f"Invalid input for scan: {e}"
        print(f"❌ {error_msg}")
        log_security_event("NETWORK_SCAN", error_msg, "ERROR")
        return None
    except Exception as e:
        error_msg = f"Unexpected error during scan: {e}"
        print(f"❌ {error_msg}")
        log_security_event("NETWORK_SCAN", error_msg, "ERROR")
        return None

print("Testing robust network scanning:")
robust_network_scan("192.168.1.1", 80)     # Valid scan
robust_network_scan("999.999.999.999", 80) # Invalid IP
robust_network_scan("192.168.1.1", 99999)  # Invalid port
print()

# ============================================================================
# HOW THIS APPLIES TO CYBERSECURITY ADMINISTRATION:
# ============================================================================
"""
CYBERSECURITY APPLICATIONS OF ERROR HANDLING:

1. NETWORK SECURITY TOOLS:
   - Handle network timeouts and connection failures gracefully
   - Manage scanning errors without crashing entire security sweeps
   - Log failed connections for security analysis
   - Retry mechanisms for temporary network issues

2. LOG ANALYSIS AND MONITORING:
   - Process malformed log entries without stopping analysis
   - Handle missing or corrupted log files
   - Manage large log files that might cause memory issues
   - Continue monitoring even when individual log sources fail

3. INCIDENT RESPONSE AUTOMATION:
   - Ensure incident response scripts run even if some systems are down
   - Handle API failures when integrating with security tools
   - Manage database connection issues during incident data collection
   - Provide fallback mechanisms when primary response tools fail

4. VULNERABILITY MANAGEMENT:
   - Handle scanner errors and incomplete vulnerability data
   - Manage authentication failures to target systems
   - Process partial scan results when some systems are unreachable
   - Continue vulnerability assessments despite individual system failures

5. COMPLIANCE AND REPORTING:
   - Generate partial reports when some data sources are unavailable
   - Handle data format inconsistencies across different systems
   - Manage authentication failures to compliance data sources
   - Ensure reporting continues even with incomplete data

6. SECURITY AUTOMATION:
   - Robust automation that doesn't break due to individual failures
   - Graceful degradation when security tools are unavailable
   - Error recovery mechanisms for long-running security processes
   - Comprehensive logging of automation errors for troubleshooting
"""

print("=== CYBERSECURITY ERROR HANDLING EXAMPLES ===")

class SecurityTool:
    """A comprehensive security tool with robust error handling."""
    
    def __init__(self, tool_name):
        self.tool_name = tool_name
        self.errors_encountered = []
        self.operations_completed = 0
    
    def log_error(self, operation, error_message):
        """Log errors for later analysis."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_entry = {
            "timestamp": timestamp,
            "operation": operation,
            "error": error_message
        }
        self.errors_encountered.append(error_entry)
        print(f"⚠️  [{self.tool_name}] {operation}: {error_message}")
    
    def check_system_health(self, systems):
        """Check health of multiple systems with error resilience."""
        healthy_systems = []
        failed_systems = []
        
        for system in systems:
            try:
                # Simulate system health check
                import random
                if system == "compromised_system":
                    raise ConnectionError("System appears to be compromised")
                elif system == "offline_system":
                    raise TimeoutError("System is not responding")
                elif random.choice([True, False, True]):  # 2/3 chance of success
                    print(f"✅ {system}: Healthy")
                    healthy_systems.append(system)
                    self.operations_completed += 1
                else:
                    raise Exception("Unknown system error")
                    
            except ConnectionError as e:
                self.log_error(f"Health check ({system})", f"Connection failed: {e}")
                failed_systems.append(system)
            except TimeoutError as e:
                self.log_error(f"Health check ({system})", f"Timeout: {e}")
                failed_systems.append(system)
            except Exception as e:
                self.log_error(f"Health check ({system})", f"Unexpected error: {e}")
                failed_systems.append(system)
        
        return {
            "healthy": healthy_systems,
            "failed": failed_systems,
            "total_checked": len(systems)
        }
    
    def scan_for_vulnerabilities(self, targets):
        """Scan targets for vulnerabilities with error handling."""
        vulnerabilities_found = []
        scan_failures = []
        
        for target in targets:
            try:
                # Simulate vulnerability scanning
                if target == "protected_system":
                    raise PermissionError("Access denied - system is protected")
                elif target == "unreachable_system":
                    raise ConnectionError("Target unreachable")
                else:
                    # Simulate finding vulnerabilities
                    import random
                    vuln_count = random.randint(0, 3)
                    if vuln_count > 0:
                        vulns = [f"CVE-2023-{1000 + i}" for i in range(vuln_count)]
                        vulnerabilities_found.extend([(target, vuln) for vuln in vulns])
                        print(f"⚠️  {target}: Found {vuln_count} vulnerabilities")
                    else:
                        print(f"✅ {target}: No vulnerabilities found")
                    
                    self.operations_completed += 1
                    
            except PermissionError as e:
                self.log_error(f"Vulnerability scan ({target})", f"Permission denied: {e}")
                scan_failures.append(target)
            except ConnectionError as e:
                self.log_error(f"Vulnerability scan ({target})", f"Connection failed: {e}")
                scan_failures.append(target)
            except Exception as e:
                self.log_error(f"Vulnerability scan ({target})", f"Scan error: {e}")
                scan_failures.append(target)
        
        return {
            "vulnerabilities": vulnerabilities_found,
            "failed_scans": scan_failures,
            "targets_scanned": len(targets) - len(scan_failures)
        }
    
    def generate_summary_report(self):
        """Generate a summary report of operations and errors."""
        print(f"\n=== {self.tool_name.upper()} SUMMARY REPORT ===")
        print(f"Operations completed successfully: {self.operations_completed}")
        print(f"Errors encountered: {len(self.errors_encountered)}")
        
        if self.errors_encountered:
            print("\nError Summary:")
            error_types = {}
            for error in self.errors_encountered:
                error_type = error["operation"]
                error_types[error_type] = error_types.get(error_type, 0) + 1
            
            for error_type, count in error_types.items():
                print(f"  - {error_type}: {count} errors")
        
        success_rate = (self.operations_completed / 
                       (self.operations_completed + len(self.errors_encountered))) * 100
        print(f"\nOverall success rate: {success_rate:.1f}%")

# Demonstrate robust security tool operations
security_scanner = SecurityTool("Advanced Security Scanner")

print("Running comprehensive security assessment:")
print("-" * 45)

# Test system health checking
test_systems = [
    "web_server_01", "database_server", "mail_server", 
    "compromised_system", "offline_system", "backup_server"
]

health_results = security_scanner.check_system_health(test_systems)
print(f"\nHealth Check Results: {len(health_results['healthy'])}/{health_results['total_checked']} systems healthy")

# Test vulnerability scanning
scan_targets = [
    "server_alpha", "server_beta", "protected_system", 
    "unreachable_system", "workstation_01"
]

vuln_results = security_scanner.scan_for_vulnerabilities(scan_targets)
print(f"Vulnerability Scan Results: {len(vuln_results['vulnerabilities'])} vulnerabilities found")

# Generate comprehensive report
security_scanner.generate_summary_report()
print()

# ============================================================================
# WARM-UP EXERCISES: Practice Error Handling
# ============================================================================

# Exercise 1: Basic try-except
"""
PRACTICE: Simple Try-Except

Your security system receives input data that needs validation before processing.
Attempt to convert the invalid string "abc" to an integer for numerical analysis.
Use error handling to catch the conversion failure and display "Invalid number".
This demonstrates basic input validation for security data processing.
"""
# TODO: Use try-except to handle string to integer conversion error


# Exercise 2: Handle file not found
"""
PRACTICE: File Error Handling

Your security monitoring system attempts to access configuration files that may not exist.
Try to open a file called "missing.txt" for reading security configuration data.
Use error handling to catch file access failures and display "File not found".
This shows graceful handling of missing security configuration files.
"""
# TODO: Handle FileNotFoundError when opening "missing.txt"


# Exercise 3: Multiple exception types
"""
PRACTICE: Multiple Exception Handling

Your security calculation system needs robust error handling for mathematical operations.
Create a function safe_divide that accepts parameters a and b for division operations.
Return the division result a/b, but handle ZeroDivisionError with "Cannot divide by zero" 
and TypeError with "Invalid input types" for robust security metric calculations.
Test with safe_divide(10, 2), safe_divide(10, 0), and safe_divide(10, "a").
"""
# TODO: Create function safe_divide with multiple exception handling


# Exercise 4: Try-except-finally
"""
PRACTICE: Finally Block

Your security logging system needs to ensure cleanup operations always execute.
Attempt to open "test.txt" to read security log data and display the content.
Use a finally block to display "File operation completed" regardless of success or failure.
This ensures proper resource cleanup in security operations.
"""
# TODO: Use try-except-finally structure for file operations


print("\n" + "="*50)
print("WARM-UP COMPLETE - NOW THE MAIN EXERCISE")
print("="*50 + "\n")

# ============================================================================
# YOUR MAIN EXERCISE: Build a Robust Security Monitoring System
# ============================================================================
"""
ROBUST SECURITY MONITORING SYSTEM

You are building a production-grade security monitoring system that must operate reliably 
even when individual components fail. The system needs comprehensive error handling to 
ensure continuous security operations and detailed error reporting for troubleshooting.

CUSTOM SECURITY EXCEPTION FRAMEWORK:
Design a specialized exception system for security operations. Create four custom exception 
types: NetworkSecurityError for network-related security issues, DataValidationError for 
invalid security data problems, ConfigurationError for system configuration issues, and 
SecurityPolicyError for security policy violations. These exceptions will provide specific 
error context for different failure scenarios.

SECURE FILE PROCESSING ENGINE:
Create a function named secure_file_processor that safely handles security file operations. 
The function should accept a filename and operation type (read, parse, or validate) and 
implement comprehensive error handling for file access issues, permission problems, and 
data validation errors. Log all operations and errors to "security_operations.log" and 
return detailed results including success status, processed data, and any encountered errors.

NETWORK SECURITY MONITORING SERVICE:
Create a function named monitor_network_security that performs resilient network monitoring. 
The function should accept lists of IP addresses and ports to monitor, handle network 
timeouts and connection failures gracefully, detect suspicious network activity, and 
continue monitoring operations even when individual checks fail. Use custom exceptions 
for security-specific network issues.

SECURITY CONFIGURATION VALIDATOR:
Create a function named validate_security_config that ensures security configurations 
meet organizational standards. The function should verify that required security settings 
exist, validate security policy compliance, and identify weak security configurations. 
Use appropriate custom exceptions for different types of configuration problems and 
provide detailed validation results.

INTEGRATED SECURITY DASHBOARD:
Create a class named SecurityDashboard that provides centralized security monitoring 
capabilities. The dashboard should include methods for processing security logs, checking 
system health, and validating configurations. Implement comprehensive error tracking, 
operation counting, and reporting functionality that demonstrates system resilience 
through proper exception handling.

COMPREHENSIVE SYSTEM TESTING:
Create a function named run_security_monitoring_test that validates the entire system's 
error handling capabilities. Test all functions with both valid data and deliberately 
problematic data to demonstrate that the system continues operating despite individual 
component failures. Show comprehensive error reporting and system resilience in action.
"""

# YOUR CODE GOES HERE
# ============================================================================

print("=== ROBUST SECURITY MONITORING SYSTEM ===")
print()

# PART 1: Create Custom Security Exceptions
# TODO: Define the 4 custom exception classes
# TODO: Define your 4 custom exception classes here

# PART 2: Robust File Processing Function
# TODO: Create secure_file_processor function
def secure_file_processor(filename, operation_type):
    """
    Process security files with comprehensive error handling.
    
    Args:
        filename (str): File to process
        operation_type (str): Type of operation ("read", "parse", "validate")
        
    Returns:
        dict: Processing results with success status, data, and errors
    """
    result = {"success": False, "data": None, "errors": []}
    
    def log_operation(message, level="INFO"):
        """Log operation to security operations log."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open("security_operations.log", "a") as log_file:
                log_file.write(f"[{timestamp}] [{level}] {message}\n")
        except Exception:
            pass  # Don't let logging errors break the main operation
    
    file_handle = None
    
    try:
        log_operation(f"Starting {operation_type} operation on {filename}")
        
        # Open and read file
        file_handle = open(filename, "r")
        content = file_handle.read()
        
        if operation_type == "read":
            result["data"] = content
            result["success"] = True
            log_operation(f"Successfully read {len(content)} characters from {filename}")
            
        elif operation_type == "parse":
            # Simulate parsing logic
            lines = content.split("\n")
            parsed_data = []
            for i, line in enumerate(lines):
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        parsed_data.append({"key": key.strip(), "value": value.strip()})
                    else:
                        raise DataValidationError(f"Invalid format on line {i+1}: {line}")
            
            result["data"] = parsed_data
            result["success"] = True
            log_operation(f"Successfully parsed {len(parsed_data)} entries from {filename}")
            
        elif operation_type == "validate":
            # Simulate validation logic
            if "CRITICAL" in content.upper():
                raise DataValidationError("Critical security issues found in file content")
            if len(content) == 0:
                raise DataValidationError("File is empty")
                
            result["data"] = {"valid": True, "content_length": len(content)}
            result["success"] = True
            log_operation(f"Successfully validated {filename}")
        
        else:
            raise ValueError(f"Unknown operation type: {operation_type}")
    
    except FileNotFoundError as e:
        error_msg = f"File not found: {filename}"
        result["errors"].append(error_msg)
        log_operation(error_msg, "ERROR")
    
    except PermissionError as e:
        error_msg = f"Permission denied accessing: {filename}"
        result["errors"].append(error_msg)
        log_operation(error_msg, "ERROR")
    
    except DataValidationError as e:
        error_msg = f"Data validation failed: {e}"
        result["errors"].append(error_msg)
        log_operation(error_msg, "ERROR")
    
    except Exception as e:
        error_msg = f"Unexpected error during {operation_type}: {e}"
        result["errors"].append(error_msg)
        log_operation(error_msg, "ERROR")
    
    finally:
        if file_handle:
            file_handle.close()
        log_operation(f"Completed {operation_type} operation on {filename}")
    
    return result

# PART 3: Network Security Monitor
# TODO: Create monitor_network_security function
def monitor_network_security(ip_addresses, ports):
    """
    Monitor network security across multiple targets.
    
    Args:
        ip_addresses (list): List of IP addresses to monitor
        ports (list): List of ports to check
        
    Returns:
        dict: Monitoring results and error summary
    """
    results = {
        "successful_checks": 0,
        "failed_checks": 0,
        "suspicious_activity": [],
        "errors": [],
        "monitoring_data": []
    }
    
    import random
    
    for ip in ip_addresses:
        for port in ports:
            try:
                # Validate IP format
                ip_parts = ip.split(".")
                if len(ip_parts) != 4:
                    raise DataValidationError(f"Invalid IP format: {ip}")
                
                for part in ip_parts:
                    if not part.isdigit() or not (0 <= int(part) <= 255):
                        raise DataValidationError(f"Invalid IP octets: {ip}")
                
                # Validate port
                if not (1 <= port <= 65535):
                    raise DataValidationError(f"Invalid port number: {port}")
                
                # Simulate network monitoring
                response_time = random.uniform(0.01, 2.0)
                status = random.choice(["open", "closed", "filtered"])
                
                # Check for suspicious activity
                if response_time > 1.5 and status == "open":
                    suspicious_msg = f"Slow response from {ip}:{port} ({response_time:.2f}s)"
                    results["suspicious_activity"].append(suspicious_msg)
                    raise NetworkSecurityError(suspicious_msg)
                
                # Check for suspicious ports
                if port in [135, 139, 445] and status == "open" and not ip.startswith("192.168."):
                    suspicious_msg = f"Suspicious SMB port {port} open on external IP {ip}"
                    results["suspicious_activity"].append(suspicious_msg)
                    raise NetworkSecurityError(suspicious_msg)
                
                # Record successful check
                results["monitoring_data"].append({
                    "ip": ip,
                    "port": port,
                    "status": status,
                    "response_time": round(response_time, 3)
                })
                results["successful_checks"] += 1
                
            except NetworkSecurityError as e:
                results["errors"].append(f"Security alert for {ip}:{port} - {e}")
                results["failed_checks"] += 1
            
            except DataValidationError as e:
                results["errors"].append(f"Validation error for {ip}:{port} - {e}")
                results["failed_checks"] += 1
            
            except Exception as e:
                results["errors"].append(f"Unexpected error monitoring {ip}:{port} - {e}")
                results["failed_checks"] += 1
    
    return results

# PART 4: Configuration Validator
# TODO: Create validate_security_config function
def validate_security_config(config_dict):
    """
    Validate security configuration settings.
    
    Args:
        config_dict (dict): Configuration to validate
        
    Returns:
        dict: Validation results with error details
    """
    validation_results = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "recommendations": []
    }
    
    try:
        # Required critical settings
        required_settings = [
            "firewall_enabled", "antivirus_enabled", "logging_enabled",
            "max_login_attempts", "session_timeout", "password_policy"
        ]
        
        # Check for missing critical settings
        for setting in required_settings:
            if setting not in config_dict:
                error_msg = f"Missing critical setting: {setting}"
                validation_results["errors"].append(error_msg)
                raise ConfigurationError(error_msg)
        
        # Validate firewall setting
        if not config_dict.get("firewall_enabled", False):
            error_msg = "Firewall must be enabled for security compliance"
            validation_results["errors"].append(error_msg)
            raise SecurityPolicyError(error_msg)
        
        # Validate login attempts
        max_attempts = config_dict.get("max_login_attempts", 0)
        if max_attempts > 10:
            warning_msg = "Max login attempts > 10 may allow brute force attacks"
            validation_results["warnings"].append(warning_msg)
        elif max_attempts < 3:
            error_msg = "Max login attempts < 3 violates security policy"
            validation_results["errors"].append(error_msg)
            raise SecurityPolicyError(error_msg)
        
        # Validate session timeout
        session_timeout = config_dict.get("session_timeout", 0)
        if session_timeout > 480:  # 8 hours
            warning_msg = "Session timeout > 8 hours may pose security risk"
            validation_results["warnings"].append(warning_msg)
        elif session_timeout < 5:
            error_msg = "Session timeout < 5 minutes is impractical"
            validation_results["errors"].append(error_msg)
            raise SecurityPolicyError(error_msg)
        
        # Validate password policy
        password_policy = config_dict.get("password_policy", {})
        if isinstance(password_policy, dict):
            min_length = password_policy.get("min_length", 0)
            if min_length < 8:
                error_msg = "Password minimum length < 8 violates security policy"
                validation_results["errors"].append(error_msg)
                raise SecurityPolicyError(error_msg)
        
        # Add recommendations
        if config_dict.get("encryption_enabled") != True:
            validation_results["recommendations"].append("Enable encryption for enhanced security")
        
        if config_dict.get("audit_logging") != True:
            validation_results["recommendations"].append("Enable audit logging for compliance")
        
        # If we get here, validation passed
        if validation_results["errors"]:
            validation_results["valid"] = False
    
    except ConfigurationError:
        validation_results["valid"] = False
    except SecurityPolicyError:
        validation_results["valid"] = False
    except Exception as e:
        validation_results["errors"].append(f"Unexpected validation error: {e}")
        validation_results["valid"] = False
    
    return validation_results

# PART 5: Comprehensive Security Dashboard
# TODO: Create SecurityDashboard class
class SecurityDashboard:
    """Comprehensive security monitoring dashboard with error resilience."""
    
    def __init__(self, dashboard_name):
        """Initialize the security dashboard."""
        self.dashboard_name = dashboard_name
        self.successful_operations = 0
        self.failed_operations = 0
        self.errors_log = []
        self.operations_log = []
    
    def _log_operation(self, operation, success, details=""):
        """Log dashboard operations."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "operation": operation,
            "success": success,
            "details": details
        }
        self.operations_log.append(log_entry)
        
        if success:
            self.successful_operations += 1
        else:
            self.failed_operations += 1
            self.errors_log.append(log_entry)
    
    def process_logs(self, log_files):
        """Process multiple log files with error handling."""
        processed_logs = []
        
        for log_file in log_files:
            try:
                result = secure_file_processor(log_file, "parse")
                if result["success"]:
                    processed_logs.append({"file": log_file, "data": result["data"]})
                    self._log_operation("process_logs", True, f"Processed {log_file}")
                else:
                    error_details = "; ".join(result["errors"])
                    self._log_operation("process_logs", False, f"Failed to process {log_file}: {error_details}")
                    
            except Exception as e:
                self._log_operation("process_logs", False, f"Exception processing {log_file}: {e}")
        
        return processed_logs
    
    def check_systems(self, systems_config):
        """Check multiple systems with error resilience."""
        system_status = {}
        
        for system_name, system_info in systems_config.items():
            try:
                # Simulate system check
                ip = system_info.get("ip", "unknown")
                ports = system_info.get("ports", [80])
                
                monitor_result = monitor_network_security([ip], ports)
                
                if monitor_result["failed_checks"] == 0:
                    system_status[system_name] = "healthy"
                    self._log_operation("check_systems", True, f"{system_name} is healthy")
                else:
                    system_status[system_name] = "issues_detected"
                    self._log_operation("check_systems", False, f"{system_name} has issues")
                    
            except Exception as e:
                system_status[system_name] = "check_failed"
                self._log_operation("check_systems", False, f"Failed to check {system_name}: {e}")
        
        return system_status
    
    def validate_configs(self, config_files):
        """Validate multiple configuration files."""
        validation_results = {}
        
        for config_name, config_data in config_files.items():
            try:
                validation = validate_security_config(config_data)
                validation_results[config_name] = validation
                
                if validation["valid"]:
                    self._log_operation("validate_configs", True, f"{config_name} configuration is valid")
                else:
                    error_summary = f"{len(validation['errors'])} errors found"
                    self._log_operation("validate_configs", False, f"{config_name} validation failed: {error_summary}")
                    
            except Exception as e:
                validation_results[config_name] = {"valid": False, "errors": [str(e)]}
                self._log_operation("validate_configs", False, f"Exception validating {config_name}: {e}")
        
        return validation_results
    
    def generate_dashboard_report(self):
        """Generate comprehensive dashboard report."""
        print(f"\n{'='*60}")
        print(f"SECURITY DASHBOARD REPORT: {self.dashboard_name}")
        print(f"{'='*60}")
        
        # Operations summary
        total_operations = self.successful_operations + self.failed_operations
        success_rate = (self.successful_operations / max(total_operations, 1)) * 100
        
        print(f"\nOPERATIONS SUMMARY:")
        print(f"Total operations: {total_operations}")
        print(f"Successful: {self.successful_operations}")
        print(f"Failed: {self.failed_operations}")
        print(f"Success rate: {success_rate:.1f}%")
        
        # Error analysis
        if self.errors_log:
            print(f"\nERROR ANALYSIS:")
            error_types = {}
            for error in self.errors_log:
                operation = error["operation"]
                error_types[operation] = error_types.get(operation, 0) + 1
            
            for operation, count in error_types.items():
                print(f"  {operation}: {count} errors")
        
        # Overall health assessment
        print(f"\nOVERALL DASHBOARD HEALTH:")
        if success_rate >= 90:
            print("🟢 EXCELLENT - Dashboard operating optimally")
        elif success_rate >= 75:
            print("🟡 GOOD - Minor issues detected")
        elif success_rate >= 50:
            print("🟠 FAIR - Multiple issues need attention")
        else:
            print("🔴 POOR - Critical issues require immediate attention")
        
        return {
            "total_operations": total_operations,
            "success_rate": success_rate,
            "error_count": len(self.errors_log)
        }

# PART 6: Integration Test
# TODO: Create run_security_monitoring_test function
def run_security_monitoring_test():
    """
    Comprehensive test of the security monitoring system.
    """
    print("🔒 COMPREHENSIVE SECURITY MONITORING TEST")
    print("="*50)
    
    # Initialize dashboard
    dashboard = SecurityDashboard("Production Security Monitor")
    
    # Create test files (some will cause errors)
    test_files = {
        "valid_config.txt": "firewall_enabled=true\nmax_attempts=5\n",
        "invalid_config.txt": "malformed line without equals\n",
        # We'll create a missing file scenario by not creating "missing_config.txt"
    }
    
    for filename, content in test_files.items():
        with open(filename, "w") as f:
            f.write(content)
    
    print("\n1. TESTING FILE PROCESSING:")
    print("-" * 30)
    
    # Test file processing with various scenarios
    test_files_list = ["valid_config.txt", "invalid_config.txt", "missing_config.txt"]
    for filename in test_files_list:
        result = secure_file_processor(filename, "parse")
        status = "✅ SUCCESS" if result["success"] else "❌ FAILED"
        print(f"{status}: {filename}")
        if result["errors"]:
            print(f"   Errors: {'; '.join(result['errors'])}")
    
    print("\n2. TESTING NETWORK MONITORING:")
    print("-" * 30)
    
    # Test network monitoring with various IP/port combinations
    test_ips = ["192.168.1.1", "203.0.113.42", "invalid.ip.address", "10.0.0.1"]
    test_ports = [80, 443, 135, 70000]  # Last port is invalid
    
    network_results = monitor_network_security(test_ips[:2], test_ports[:2])  # Use valid subset
    print(f"Network checks completed: {network_results['successful_checks']} successful, {network_results['failed_checks']} failed")
    if network_results['suspicious_activity']:
        print(f"Suspicious activity detected: {len(network_results['suspicious_activity'])} incidents")
    
    print("\n3. TESTING CONFIGURATION VALIDATION:")
    print("-" * 35)
    
    test_configs = {
        "secure_config": {
            "firewall_enabled": True,
            "antivirus_enabled": True,
            "logging_enabled": True,
            "max_login_attempts": 5,
            "session_timeout": 30,
            "password_policy": {"min_length": 12}
        },
        "weak_config": {
            "firewall_enabled": False,  # This will cause an error
            "max_login_attempts": 2,    # Too low
            "session_timeout": 1000     # Too high
        },
        "incomplete_config": {
            "firewall_enabled": True
            # Missing required settings
        }
    }
    
    config_results = dashboard.validate_configs(test_configs)
    for config_name, result in config_results.items():
        status = "✅ VALID" if result["valid"] else "❌ INVALID"
        print(f"{status}: {config_name}")
        if result.get("errors"):
            print(f"   Errors: {len(result['errors'])}")
    
    print("\n4. TESTING DASHBOARD INTEGRATION:")
    print("-" * 32)
    
    # Test dashboard log processing
    log_files = ["valid_config.txt", "missing_log.txt"]
    processed = dashboard.process_logs(log_files)
    print(f"Processed {len(processed)} log files successfully")
    
    # Test system checking
    systems = {
        "web_server": {"ip": "192.168.1.100", "ports": [80, 443]},
        "db_server": {"ip": "192.168.1.200", "ports": [3306]},
        "invalid_system": {"ip": "999.999.999.999", "ports": [80]}
    }
    
    system_results = dashboard.check_systems(systems)
    healthy_systems = sum(1 for status in system_results.values() if status == "healthy")
    print(f"System health check: {healthy_systems}/{len(systems)} systems healthy")
    
    print("\n5. FINAL DASHBOARD REPORT:")
    print("-" * 25)
    dashboard.generate_dashboard_report()
    
    print(f"\n✅ MONITORING SYSTEM TEST COMPLETED")
    print(f"   The system demonstrated resilience by continuing to operate")
    print(f"   despite {dashboard.failed_operations} failed operations.")

# Run the comprehensive test
run_security_monitoring_test()

# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_error_handling():
    """Test function to verify your error handling implementations are correct."""
    
    try:
        # Test Part 1: Custom exceptions exist
        test_exceptions = [NetworkSecurityError, DataValidationError, ConfigurationError, SecurityPolicyError]
        for exc_class in test_exceptions:
            assert issubclass(exc_class, Exception), f"{exc_class.__name__} should inherit from Exception"
        print("✅ Test 1 PASSED: Custom exception classes defined correctly")
        
        # Test Part 2: File processor function
        # Create a test file
        with open("test_error_file.txt", "w") as f:
            f.write("test_key=test_value\n")
        
        result = secure_file_processor("test_error_file.txt", "read")
        assert isinstance(result, dict), "secure_file_processor should return dictionary"
        assert "success" in result, "Result should contain 'success' key"
        assert "data" in result, "Result should contain 'data' key"
        assert "errors" in result, "Result should contain 'errors' key"
        print("✅ Test 2 PASSED: secure_file_processor function works correctly")
        
        # Test Part 3: Network monitoring function
        network_result = monitor_network_security(["192.168.1.1"], [80])
        assert isinstance(network_result, dict), "monitor_network_security should return dictionary"
        assert "successful_checks" in network_result, "Should contain successful_checks"
        assert "failed_checks" in network_result, "Should contain failed_checks"
        print("✅ Test 3 PASSED: monitor_network_security function works correctly")
        
        # Test Part 4: Configuration validator
        test_config = {
            "firewall_enabled": True,
            "antivirus_enabled": True,
            "logging_enabled": True,
            "max_login_attempts": 5,
            "session_timeout": 30,
            "password_policy": {"min_length": 8}
        }
        
        config_result = validate_security_config(test_config)
        assert isinstance(config_result, dict), "validate_security_config should return dictionary"
        assert "valid" in config_result, "Should contain 'valid' key"
        print("✅ Test 4 PASSED: validate_security_config function works correctly")
        
        # Test Part 5: SecurityDashboard class
        dashboard = SecurityDashboard("Test Dashboard")
        assert hasattr(dashboard, "process_logs"), "SecurityDashboard should have process_logs method"
        assert hasattr(dashboard, "check_systems"), "SecurityDashboard should have check_systems method"
        assert hasattr(dashboard, "validate_configs"), "SecurityDashboard should have validate_configs method"
        assert hasattr(dashboard, "generate_dashboard_report"), "SecurityDashboard should have generate_dashboard_report method"
        print("✅ Test 5 PASSED: SecurityDashboard class implemented correctly")
        
        # Test Part 6: Integration test function exists
        assert callable(run_security_monitoring_test), "run_security_monitoring_test should be callable"
        print("✅ Test 6 PASSED: Integration test function defined")
        
        print("\n🎉 CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python error handling!")
        print("🎓 You have completed the entire Python for Cybersecurity course!")
        
    except NameError as e:
        print(f"❌ ERROR: Function or class not found - {e}")
        print("Make sure you've defined all required components.")
    except AssertionError as e:
        print(f"❌ TEST FAILED: {e}")
        print("Check your implementations and try again.")
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")

# Run the tests
test_error_handling()

# ============================================================================
# COURSE COMPLETION CELEBRATION!
# ============================================================================
"""
🎉 CONGRATULATIONS! YOU'VE COMPLETED THE PYTHON FOR CYBERSECURITY COURSE! 🎉

Here's everything you've mastered in this comprehensive journey:

MODULE 1 - VARIABLES & DATA TYPES ✅
- Storing and managing cybersecurity data
- Working with different data types for security applications

MODULE 2 - OPERATORS ✅  
- Building logical security conditions
- Creating threshold monitoring and comparison logic

MODULE 3 - CONDITIONAL STATEMENTS ✅
- Implementing intelligent security decision-making
- Automated security policy enforcement

MODULE 4 - LOOPS ✅
- Automating repetitive security tasks
- Processing large datasets and log files

MODULE 5 - LISTS ✅
- Managing collections of security data
- Working with IP addresses, user accounts, and security alerts

MODULE 6 - DICTIONARIES ✅
- Organizing complex security information
- Building structured security databases and configurations

MODULE 7 - FUNCTIONS ✅
- Creating reusable security tools and modules
- Building organized, maintainable security code

MODULE 8 - FILE I/O ✅
- Processing security logs, configuration files, and reports
- Implementing data persistence and file management

MODULE 9 - ERROR HANDLING ✅
- Building robust, production-ready security tools
- Implementing comprehensive error resilience

CYBERSECURITY SKILLS YOU'VE GAINED:
🔐 Security monitoring and alerting systems
🔐 Automated threat detection and response
🔐 Log analysis and pattern recognition
🔐 Network scanning and vulnerability assessment
🔐 User management and access control
🔐 Configuration management and compliance
🔐 Incident response automation
🔐 Security reporting and metrics
🔐 Error handling and system resilience

WHAT'S NEXT?
You now have a solid foundation in Python for cybersecurity! Consider exploring:
- Advanced Python libraries (requests, pandas, matplotlib)
- Cybersecurity frameworks (NIST, MITRE ATT&CK)
- Security tools integration (APIs, automation platforms)
- Advanced topics (machine learning for security, threat hunting)

Keep building amazing cybersecurity tools! 🚀🛡️
"""

print("\n" + "🎓" * 20)
print("PYTHON FOR CYBERSECURITY COURSE COMPLETED!")
print("🎓" * 20)
print("\nYou're now ready to build professional cybersecurity automation!")
print("Keep coding, keep securing, and welcome to the world of cybersecurity programming! 🐍🔒")
