"""
====================================================================
MODULE 3: CONDITIONAL STATEMENTS - Making Smart Decisions 🤔
====================================================================

Welcome to Module 3! Now that you can compare and evaluate data with operators,
you'll learn how to make your programs take different actions based on those
comparisons using conditional statements.

WHAT ARE CONDITIONAL STATEMENTS?
Conditional statements let your program make decisions. They work like this:
"IF this condition is true, THEN do this action, OTHERWISE do that action."

CONDITIONAL STATEMENTS WE'LL COVER:
- if: Execute code when a condition is True
- elif: Check additional conditions (else if)
- else: Execute code when all conditions are False
"""

# ============================================================================
# CONCEPT EXPLANATION: Basic IF Statements
# ============================================================================

print("=== BASIC IF STATEMENTS ===")
print()

# Simple if statement
failed_logins = 3
max_attempts = 5

print(f"Failed login attempts: {failed_logins}")
print(f"Maximum allowed attempts: {max_attempts}")

if failed_logins > max_attempts:
    print("🚨 ALERT: Account should be locked!")
print()

# If statement that executes
failed_logins = 6  # Now it exceeds the limit

print(f"Failed login attempts: {failed_logins}")
print(f"Maximum allowed attempts: {max_attempts}")

if failed_logins > max_attempts:
    print("🚨 ALERT: Account should be locked!")
print()

# ============================================================================
# CONCEPT EXPLANATION: IF-ELSE Statements
# ============================================================================

print("=== IF-ELSE STATEMENTS ===")
print()

# If-else provides an alternative action
firewall_status = True

print(f"Firewall enabled: {firewall_status}")

if firewall_status:
    print("✅ Security status: Firewall protection active")
else:
    print("⚠️  Security status: Firewall protection disabled")
print()

# Another if-else example
cpu_usage = 95
cpu_threshold = 90

print(f"Current CPU usage: {cpu_usage}%")
print(f"CPU threshold: {cpu_threshold}%")

if cpu_usage > cpu_threshold:
    print("🔥 WARNING: High CPU usage detected!")
else:
    print("✅ CPU usage is within normal limits")
print()

# ============================================================================
# CONCEPT EXPLANATION: IF-ELIF-ELSE Statements
# ============================================================================

print("=== IF-ELIF-ELSE STATEMENTS ===")
print()

# Multiple conditions with elif
threat_score = 7

print(f"Current threat score: {threat_score}/10")

if threat_score >= 9:
    print("🚨 CRITICAL: Immediate action required!")
elif threat_score >= 7:
    print("⚠️  HIGH: Enhanced monitoring needed")
elif threat_score >= 5:
    print("🟡 MEDIUM: Standard monitoring")
elif threat_score >= 3:
    print("🟢 LOW: Minimal risk")
else:
    print("✅ SAFE: No significant threats")
print()

# ============================================================================
# CONCEPT EXPLANATION: Complex Conditions
# ============================================================================

print("=== COMPLEX CONDITIONS ===")
print()

# Using logical operators in conditions
user_role = "admin"
authenticated = True
vpn_connected = False

print(f"User role: {user_role}")
print(f"Authenticated: {authenticated}")
print(f"VPN connected: {vpn_connected}")

if user_role == "admin" and authenticated:
    print("✅ Admin access granted")
    if not vpn_connected:
        print("⚠️  Warning: Admin not using VPN")
else:
    print("❌ Access denied")
print()

# ============================================================================
# HOW THIS APPLIES TO CYBERSECURITY ADMINISTRATION:
# ============================================================================
"""
CYBERSECURITY APPLICATIONS OF CONDITIONAL STATEMENTS:

1. ACCESS CONTROL DECISIONS:
   - IF user is authenticated AND has proper role THEN grant access
   - IF login attempt from blacklisted IP THEN block immediately
   - IF password strength < minimum THEN require password change

2. INCIDENT RESPONSE AUTOMATION:
   - IF threat level == "CRITICAL" THEN trigger emergency response
   - IF malware detected THEN isolate system AND notify admin
   - IF unusual network activity THEN increase monitoring level

3. SYSTEM MONITORING:
   - IF CPU usage > 90% THEN send alert AND restart service
   - IF disk space < 10% THEN cleanup logs AND notify admin
   - IF service down THEN attempt restart ELSE escalate to admin

4. SECURITY POLICY ENFORCEMENT:
   - IF file extension in dangerous_list THEN quarantine file
   - IF user inactive > 30 days THEN disable account
   - IF unsuccessful logins > 5 THEN lock account for 30 minutes

5. VULNERABILITY MANAGEMENT:
   - IF patch level < required THEN schedule update
   - IF security scan finds high vulnerabilities THEN priority fix
   - IF system unpatched > 30 days THEN flag for immediate attention
"""

print("=== CYBERSECURITY CONDITIONAL EXAMPLES ===")

# Security access control example
user_ip = "203.0.113.42"
blacklisted_ips = ["203.0.113.42", "198.51.100.1"]
user_authenticated = True

print(f"User IP: {user_ip}")
print(f"User authenticated: {user_authenticated}")

if user_ip in blacklisted_ips:
    print("🚨 BLOCKED: IP address is blacklisted")
elif not user_authenticated:
    print("❌ DENIED: User not authenticated")
else:
    print("✅ ACCESS GRANTED: User cleared for entry")
print()

# System health monitoring example
memory_usage = 85
disk_usage = 45
network_errors = 12

print("System Health Check:")
print(f"Memory usage: {memory_usage}%")
print(f"Disk usage: {disk_usage}%")
print(f"Network errors: {network_errors}")

if memory_usage > 90:
    print("🔴 CRITICAL: Memory usage too high")
elif memory_usage > 80:
    print("🟡 WARNING: Memory usage elevated")
else:
    print("🟢 OK: Memory usage normal")

if disk_usage > 90:
    print("🔴 CRITICAL: Disk space critically low")
elif disk_usage > 75:
    print("🟡 WARNING: Disk space running low")
else:
    print("🟢 OK: Disk space sufficient")
print()

# ============================================================================
# WARM-UP EXERCISES: Practice Using Conditionals
# ============================================================================

# Exercise 1: Simple if statement
"""
PRACTICE: Basic If Statement

Create a variable threat_level = 8.
If threat_level is greater than 5, print "High threat detected".
"""
# TODO: Create variable and if statement


# Exercise 2: If-else statement
"""
PRACTICE: If-Else Logic

Create a variable port = 22.
If port equals 22, print "SSH connection".
Otherwise, print "Other connection".
"""
# TODO: Create variable and if-else statement


# Exercise 3: Multiple conditions with elif
"""
PRACTICE: If-Elif-Else Logic

Create a variable security_score = 7.
If score is 9 or above, print "Excellent security".
If score is 7-8, print "Good security".
Otherwise, print "Needs improvement".
"""
# TODO: Create variable and if-elif-else statement


# Exercise 4: Combining conditions with AND
"""
PRACTICE: Conditional with AND

Create variables admin_logged_in = True and system_healthy = True.
If BOTH are True, print "System ready for operations".
Otherwise, print "System not ready".
"""
# TODO: Create variables and conditional with AND


print("\n" + "="*50)
print("WARM-UP COMPLETE - NOW THE MAIN EXERCISE")
print("="*50 + "\n")

# ============================================================================
# YOUR MAIN EXERCISE: Build a Security Assessment System
# ============================================================================
"""
AUTOMATED SECURITY ASSESSMENT SYSTEM

You are developing an automated security assessment tool that evaluates a computer 
system's security posture and provides recommendations.

The system being assessed has the following characteristics:
- Current password length: 6 characters
- Days since last security update: 45 days
- Firewall status: Enabled
- Antivirus status: Not active
- Administrator account status: Active
- Recent failed login attempts: 8 attempts

Your assessment tool needs to evaluate four critical security areas:

PASSWORD SECURITY ASSESSMENT:
Evaluate password strength and provide appropriate feedback:
- Passwords with 12 or more characters are considered strong
- Passwords with 8-11 characters are adequate  
- Passwords with less than 8 characters are weak and require immediate change

SYSTEM UPDATE STATUS:
Assess how current the system updates are:
- Systems updated within 7 days are current
- Systems updated within 30 days are acceptable
- Systems not updated for over 30 days are critically outdated

SECURITY SOFTWARE PROTECTION:
Determine the level of security software protection:
- Systems with both firewall and antivirus active are fully protected
- Systems with only one protection active are partially protected
- Systems with neither protection are unprotected

ACCOUNT SECURITY MONITORING:
Analyze login attempt patterns for security threats:
- If admin account is active and failed attempts exceed 5: admin account under attack
- If failed attempts exceed 10: possible brute force attack
- If failed attempts exceed 3: multiple failed attempts warning
- Otherwise: normal login activity

Create variables named password_length, last_update_days, firewall_enabled, 
antivirus_active, admin_account_active, and failed_login_attempts to store the 
system data, then implement the assessment logic.
"""

# YOUR CODE GOES HERE
# ============================================================================

print("=== AUTOMATED SECURITY ASSESSMENT SYSTEM ===")
print()

# PART 1: Create the assessment variables
# TODO: Create the 6 variables listed above
# Create password_length variable here

# Create last_update_days variable here

# Create firewall_enabled variable here

# Create antivirus_active variable here

# Create admin_account_active variable here

# Create failed_login_attempts variable here


# TODO: Print system information
print("System Information:")
# Add your print statements here

print()

print("Security Assessment Results:")
print("-" * 40)

# PART 2: Write the conditional statements

# TODO: Password Security Assessment
# Write your if/elif/else statements for password security here

# TODO: System Updates Assessment
# Write your if/elif/else statements for system updates here

# TODO: Security Software Assessment
# Write your if/elif/else statements for security software here

# TODO: Account Security Assessment
# Write your if/elif/else statements for account security here

print()

# PART 3: Overall Security Recommendation
print("Overall Security Recommendation:")
print("-" * 40)

# TODO: Write overall security recommendation logic here

# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

print("\n" + "="*50)
print("RUNNING TESTS...")
print("="*50)

def test_warmup_exercises():
    """Test the warm-up exercises."""
    print("=== TESTING WARM-UP EXERCISES ===")
    warmup_passed = 0
    
    # Test Exercise 1: Basic if statement
    try:
        assert threat_level == 8, f"Variable 'threat_level' should be 8, got: {threat_level}"
        print("✅ Exercise 1 PASSED: threat_level variable created correctly")
        warmup_passed += 1
    except NameError as e:
        print(f"❌ Exercise 1 FAILED: Missing variable - {e}")
        print("Create variable: threat_level=8 and add if statement to print when > 5")
    except AssertionError as e:
        print(f"❌ Exercise 1 FAILED: {e}")
    
    # Test Exercise 2: If-else logic
    try:
        assert port == 22, f"Variable 'port' should be 22, got: {port}"
        print("✅ Exercise 2 PASSED: port variable and if-else logic correct")
        warmup_passed += 1
    except NameError as e:
        print(f"❌ Exercise 2 FAILED: Missing variable - {e}")
        print("Create variable: port=22 and add if-else to check port type")
    except AssertionError as e:
        print(f"❌ Exercise 2 FAILED: {e}")
    
    # Test Exercise 3: If-elif-else logic
    try:
        assert security_score == 7, f"Variable 'security_score' should be 7, got: {security_score}"
        print("✅ Exercise 3 PASSED: security_score variable and if-elif-else logic correct")
        warmup_passed += 1
    except NameError as e:
        print(f"❌ Exercise 3 FAILED: Missing variable - {e}")
        print("Create variable: security_score=7 and add if-elif-else for score ranges")
    except AssertionError as e:
        print(f"❌ Exercise 3 FAILED: {e}")
    
    # Test Exercise 4: Conditional with AND
    try:
        assert admin_logged_in == True, f"Variable 'admin_logged_in' should be True, got: {admin_logged_in}"
        assert system_healthy == True, f"Variable 'system_healthy' should be True, got: {system_healthy}"
        print("✅ Exercise 4 PASSED: admin_logged_in and system_healthy variables correct")
        warmup_passed += 1
    except NameError as e:
        print(f"❌ Exercise 4 FAILED: Missing variable - {e}")
        print("Create variables: admin_logged_in=True, system_healthy=True and add AND conditional")
    except AssertionError as e:
        print(f"❌ Exercise 4 FAILED: {e}")
    
    print(f"Warm-up Score: {warmup_passed}/4 exercises completed")
    return warmup_passed == 4

def test_main_exercise():
    """Test the main exercise conditional logic."""
    print("\n=== TESTING MAIN EXERCISE ===")
    
    try:
        # Test data variables
        assert password_length == 6, f"Variable 'password_length' should be 6, got: {password_length}"
        print("✅ password_length: Correct")
        
        assert last_update_days == 45, f"Variable 'last_update_days' should be 45, got: {last_update_days}"
        print("✅ last_update_days: Correct")
        
        assert firewall_enabled == True, f"Variable 'firewall_enabled' should be True, got: {firewall_enabled}"
        print("✅ firewall_enabled: Correct")
        
        assert antivirus_active == False, f"Variable 'antivirus_active' should be False, got: {antivirus_active}"
        print("✅ antivirus_active: Correct")
        
        assert admin_account_active == True, f"Variable 'admin_account_active' should be True, got: {admin_account_active}"
        print("✅ admin_account_active: Correct")
        
        assert failed_login_attempts == 8, f"Variable 'failed_login_attempts' should be 8, got: {failed_login_attempts}"
        print("✅ failed_login_attempts: Correct")
        
        print("\n✅ MAIN EXERCISE COMPLETED! Security assessment logic implemented!")
        return True
        
    except NameError as e:
        print(f"❌ ERROR: Variable not found - {e}")
        print("Make sure you've created all required variables and implemented the conditional logic.")
        return False
    except AssertionError as e:
        print(f"❌ ERROR: {e}")
        print("Check your variable values and conditional logic.")
        return False
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")
        return False

def test_conditionals():
    """Run all tests for Module 3."""
    warmup_success = test_warmup_exercises()
    main_success = test_main_exercise()
    
    if warmup_success and main_success:
        print("\n✅ CONGRATULATIONS! All tests passed!")
        print("You've successfully mastered Python conditional statements!")
        print("Ready for Module 4: Loops")
    else:
        print("\n📚 Keep practicing! Complete all exercises to proceed.")
        if not warmup_success:
            print("- Finish the warm-up exercises first")
        if not main_success:
            print("- Complete the main security assessment exercise")

# Run the tests
test_conditionals()

# ============================================================================
# WHAT'S NEXT?
# ============================================================================
"""
Outstanding work completing Module 3! Here's what you learned:

✅ Basic if statements for simple decisions
✅ If-else statements for two-option decisions
✅ If-elif-else for multiple condition checking
✅ Complex conditions using logical operators
✅ How to build automated security assessment logic

CYBERSECURITY SKILLS GAINED:
- Automated security policy enforcement
- Intelligent threat response decisions
- System health monitoring with smart alerts
- Access control logic implementation
- Incident response automation basics

NEXT MODULE: 04_loops.py
In the next module, you'll learn about loops - the powerful feature that
lets you automate repetitive tasks like scanning multiple IP addresses,
processing log files, or checking system status across many servers!

You're building serious cybersecurity automation skills! 🛡️
"""
