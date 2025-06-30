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

# ============================================================================
# WARM-UP EXERCISES: Practice Using Conditionals
# ============================================================================

# Exercise 1: Simple if statement
"""
PRACTICE: Basic If Statement

Write a function `check_threat_level(threat_level)` that takes an integer.
If `threat_level` is greater than 5, it should return "High threat detected".
Otherwise, it should return "Low threat".
"""
# TODO: Implement the function check_threat_level
def check_threat_level(threat_level):
    # Your code here
    pass


# Exercise 2: If-else statement
"""
PRACTICE: If-Else Logic

Write a function `check_port(port)` that takes an integer.
If `port` equals 22, it should return "SSH connection".
Otherwise, it should return "Other connection".
"""
# TODO: Implement the function check_port
def check_port(port):
    # Your code here
    pass


# Exercise 3: Multiple conditions with elif
"""
PRACTICE: If-Elif-Else Logic

Write a function `evaluate_security_score(score)` that takes an integer.
If `score` is 9 or above, return "Excellent security".
If `score` is 7-8, return "Good security".
Otherwise, return "Needs improvement".
"""
# TODO: Implement the function evaluate_security_score
def evaluate_security_score(score):
    # Your code here
    pass


# Exercise 4: Combining conditions with AND
"""
PRACTICE: Conditional with AND

Write a function `check_system_status(admin_logged_in, system_healthy)`
that takes two boolean values.
If BOTH `admin_logged_in` AND `system_healthy` are True, return "System ready for operations".
Otherwise, return "System not ready".
"""
# TODO: Implement the function check_system_status
def check_system_status(admin_logged_in, system_healthy):
    # Your code here
    pass


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

# PART 1: Create the assessment variables
# TODO: Create the 6 variables listed above
# Create password_length variable here

# Create last_update_days variable here

# Create firewall_enabled variable here

# Create antivirus_active variable here

# Create admin_account_active variable here

# Create failed_login_attempts variable here


# TODO: Print system information (Optional, for your own debugging)


# PART 2: Write the conditional statements for the main exercise
# You will need to use the variables created in Part 1 to make decisions.
# For each assessment area, determine the appropriate message based on the rules.
# You can store these messages in variables or print them directly.

# TODO: Password Security Assessment
# Store or print the result of password security assessment

# TODO: System Updates Assessment
# Store or print the result of system updates assessment

# TODO: Security Software Assessment
# Store or print the result of security software assessment

# TODO: Account Security Assessment
# Store or print the result of account security assessment


# PART 3: Overall Security Recommendation (Optional Challenge)
# Based on the individual assessments, provide an overall recommendation.
# For example, if multiple areas are weak, recommend urgent action.


# ============================================================================
# BUILT-IN TESTS - Check Your Work!
# ============================================================================

def test_warmup_exercises():
    """Test the warm-up exercises."""
    warmup_passed = 0
    total_warmup_tests = 4

    # Test Exercise 1: Basic if statement
    try:
        assert check_threat_level(8) == "High threat detected", "Test 1.1 Failed: threat_level = 8"
        assert check_threat_level(4) == "Low threat", "Test 1.2 Failed: threat_level = 4"
        assert check_threat_level(5) == "Low threat", "Test 1.3 Failed: threat_level = 5"
        print("✅ Exercise 1 PASSED")
        warmup_passed += 1
    except NameError as e:
        print("❌ Exercise 1 FAILED: Function 'check_threat_level' not defined.")
    except AssertionError as e:
        print(f"❌ Exercise 1 FAILED: {e}")
    except Exception as e:
        print(f"❌ Exercise 1 FAILED: Unexpected error - {e}")

    # Test Exercise 2: If-else logic
    try:
        assert check_port(22) == "SSH connection", "Test 2.1 Failed: port = 22"
        assert check_port(80) == "Other connection", "Test 2.2 Failed: port = 80"
        assert check_port(443) == "Other connection", "Test 2.3 Failed: port = 443"
        print("✅ Exercise 2 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Exercise 2 FAILED: Function 'check_port' not defined.")
    except AssertionError as e:
        print(f"❌ Exercise 2 FAILED: {e}")
    except Exception as e:
        print(f"❌ Exercise 2 FAILED: Unexpected error - {e}")

    # Test Exercise 3: If-elif-else logic
    try:
        assert evaluate_security_score(10) == "Excellent security", "Test 3.1 Failed: score = 10"
        assert evaluate_security_score(9) == "Excellent security", "Test 3.2 Failed: score = 9"
        assert evaluate_security_score(8) == "Good security", "Test 3.3 Failed: score = 8"
        assert evaluate_security_score(7) == "Good security", "Test 3.4 Failed: score = 7"
        assert evaluate_security_score(6) == "Needs improvement", "Test 3.5 Failed: score = 6"
        assert evaluate_security_score(0) == "Needs improvement", "Test 3.6 Failed: score = 0"
        print("✅ Exercise 3 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Exercise 3 FAILED: Function 'evaluate_security_score' not defined.")
    except AssertionError as e:
        print(f"❌ Exercise 3 FAILED: {e}")
    except Exception as e:
        print(f"❌ Exercise 3 FAILED: Unexpected error - {e}")

    # Test Exercise 4: Conditional with AND
    try:
        assert check_system_status(True, True) == "System ready for operations", "Test 4.1 Failed: True, True"
        assert check_system_status(True, False) == "System not ready", "Test 4.2 Failed: True, False"
        assert check_system_status(False, True) == "System not ready", "Test 4.3 Failed: False, True"
        assert check_system_status(False, False) == "System not ready", "Test 4.4 Failed: False, False"
        print("✅ Exercise 4 PASSED")
        warmup_passed += 1
    except NameError:
        print("❌ Exercise 4 FAILED: Function 'check_system_status' not defined.")
    except AssertionError as e:
        print(f"❌ Exercise 4 FAILED: {e}")
    except Exception as e:
        print(f"❌ Exercise 4 FAILED: Unexpected error - {e}")

    print(f"\nWarm-up Score: {warmup_passed}/{total_warmup_tests} exercises completed correctly.")
    return warmup_passed == total_warmup_tests

def test_main_exercise():
    """Test the main exercise conditional logic."""
    # These tests primarily check if the variables are defined.
    # The actual logic of the main exercise (printing messages) is for the user to verify visually.
    # For a more robust test, you'd capture print output or have functions return results.
    main_passed = True
    try:
        # Test data variables (check if they exist and have the initial values)
        # These are defined by the user in their code section.
        # We assume the user is meant to define these based on the problem description.
        # For example:
        # password_length = 6
        # last_update_days = 45
        # firewall_enabled = True
        # antivirus_active = False
        # admin_account_active = True
        # failed_login_attempts = 8

        # We can't directly test the print statements of the main exercise without
        # more complex redirection of stdout or refactoring the exercise to return strings.
        # For now, we'll assume if the variables are present, the user is working on it.
        # A full check would require specific output strings.

        # Example of how you might check if variables are defined by the user:
        if 'password_length' not in globals() or password_length != 6:
            print("❌ Main Exercise Check: 'password_length' not correctly defined or missing.")
            main_passed = False
        if 'last_update_days' not in globals() or last_update_days != 45:
            print("❌ Main Exercise Check: 'last_update_days' not correctly defined or missing.")
            main_passed = False
        if 'firewall_enabled' not in globals() or firewall_enabled != True:
            print("❌ Main Exercise Check: 'firewall_enabled' not correctly defined or missing.")
            main_passed = False
        if 'antivirus_active' not in globals() or antivirus_active != False:
            print("❌ Main Exercise Check: 'antivirus_active' not correctly defined or missing.")
            main_passed = False
        if 'admin_account_active' not in globals() or admin_account_active != True:
            print("❌ Main Exercise Check: 'admin_account_active' not correctly defined or missing.")
            main_passed = False
        if 'failed_login_attempts' not in globals() or failed_login_attempts != 8:
            print("❌ Main Exercise Check: 'failed_login_attempts' not correctly defined or missing.")
            main_passed = False

        if main_passed:
            print("\n✅ MAIN EXERCISE: Variables seem to be defined. Ensure your conditional logic produces the correct outputs based on the problem description.")
        else:
            print("\n❌ MAIN EXERCISE: Some initial variables are not defined correctly. Please check the problem description.")

    except NameError as e:
        print(f"❌ ERROR in Main Exercise: Variable not found - {e}. Make sure you've created all required variables.")
        return False # Return False on NameError, as variables are crucial.
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR in Main Exercise: {e}")
        return False # Return False on other unexpected errors.

    # Since we are not testing output directly, we return True if variables are okay.
    # The user is responsible for verifying the printed output of their logic.
    return main_passed


def run_all_tests():
    """Run all tests for Module 3."""
    print("="*50)
    print("RUNNING WARM-UP TESTS...")
    print("="*50)
    warmup_success = test_warmup_exercises()

    print("\n" + "="*50)
    print("RUNNING MAIN EXERCISE CHECKS...")
    print("="*50)
    # The main exercise for this module involves print statements.
    # We will call the function to check variable setup, but the user must verify their print logic.
    main_exercise_variables_ok = test_main_exercise()
    if main_exercise_variables_ok:
        print("Reminder: For the main exercise, manually verify your printed outputs against the problem description.")


    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    if warmup_success and main_exercise_variables_ok:
        print("\n✅ All warm-up tests passed and main exercise variables are set up.")
        print("Please ensure your main exercise conditional logic prints the correct messages.")
        print("You've successfully practiced Python conditional statements!")
        print("Ready for Module 4: Loops")
    else:
        print("\n📚 Keep practicing! Review the failed tests or checks above.")
        if not warmup_success:
            print("- Some warm-up exercises have issues.")
        if not main_exercise_variables_ok:
            print("- The main exercise variable setup has issues.")

# Run the tests
run_all_tests()

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
