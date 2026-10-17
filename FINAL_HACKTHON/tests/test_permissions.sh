#!/usr/bin/env bash
# ==============================================================================
# Project: Linux File Permission Analyzer
# File:    tests/test_permissions.sh
# Authors: Abhishek Yadav K (2520090208)
#          S Venu Gopal (2520090185)
#          R ROHIT (2520080037)
# Hackathon: 17 October 2026
#
# Description:
# Automated regression and security validation test suite covering the 12
# mandatory test scenarios specified in the Hackathon project guidelines.
# ==============================================================================

set -u

# Colors
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_GREEN="\033[32m"
C_RED="\033[31m"
C_YELLOW="\033[33m"
C_CYAN="\033[36m"

BINARY="./bin/permission_analyzer"

if [ ! -x "$BINARY" ]; then
    echo -e "${C_YELLOW}[*] Binary not found. Compiling first...${C_RESET}"
    make all > /dev/null 2>&1
    if [ ! -x "$BINARY" ]; then
        echo -e "${C_RED}[-] Failed to build binary. Aborting tests.${C_RESET}"
        exit 1
    fi
fi

# Create dedicated sandbox directory on native ext4 filesystem (/tmp)
TEST_DIR="/tmp/analyzer_test_sandbox_$$"
mkdir -p "$TEST_DIR"

cleanup() {
    # Restore permissions in case an inaccessible dir was created
    chmod -R 777 "$TEST_DIR" > /dev/null 2>&1 || true
    rm -rf "$TEST_DIR" > /dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo -e "${C_CYAN}${C_BOLD}=====================================================================${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}       LINUX FILE PERMISSION ANALYZER - AUTOMATED TEST SUITE        ${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}=====================================================================${C_RESET}"
echo -e "Sandbox Directory: ${TEST_DIR}\n"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_TESTS=12

run_test() {
    local test_num="$1"
    local test_name="$2"
    local test_cmd="$3"
    local expected_pattern="$4"

    echo -ne "[Test ${test_num}/${TOTAL_TESTS}] ${test_name}... "

    local output
    output=$(eval "$test_cmd" 2>&1)
    local status=$?

    if [ -n "$expected_pattern" ]; then
        if echo "$output" | grep -E -q "$expected_pattern"; then
            echo -e "${C_GREEN}${C_BOLD}PASS${C_RESET}"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo -e "${C_RED}${C_BOLD}FAIL${C_RESET} (Pattern '$expected_pattern' not found)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    else
        if [ $status -eq 0 ]; then
            echo -e "${C_GREEN}${C_BOLD}PASS${C_RESET}"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo -e "${C_RED}${C_BOLD}FAIL${C_RESET} (Exited with code $status)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi
}

# ------------------------------------------------------------------------------
# Test 1: File with permission 644 (Standard read-only for others)
# ------------------------------------------------------------------------------
touch "${TEST_DIR}/file_644.txt"
chmod 644 "${TEST_DIR}/file_644.txt"
run_test "01" "File with permission 644" \
    "$BINARY -f '${TEST_DIR}/file_644.txt'" \
    "644|Standard Permissions Baseline"

# ------------------------------------------------------------------------------
# Test 2: File with permission 600 (Strict private owner access)
# ------------------------------------------------------------------------------
touch "${TEST_DIR}/file_600.key"
chmod 600 "${TEST_DIR}/file_600.key"
run_test "02" "File with permission 600" \
    "$BINARY -f '${TEST_DIR}/file_600.key'" \
    "600|Standard Permissions Baseline"

# ------------------------------------------------------------------------------
# Test 3: Executable file with permission 755
# ------------------------------------------------------------------------------
touch "${TEST_DIR}/run_755.sh"
chmod 755 "${TEST_DIR}/run_755.sh"
run_test "03" "Executable file with permission 755" \
    "$BINARY -f '${TEST_DIR}/run_755.sh'" \
    "755|Standard Permissions Baseline"

# ------------------------------------------------------------------------------
# Test 4: File with permission 777 (High security risk)
# ------------------------------------------------------------------------------
touch "${TEST_DIR}/danger_777.txt"
chmod 777 "${TEST_DIR}/danger_777.txt"
run_test "04" "File with permission 777 (Risk Flagging)" \
    "$BINARY -f '${TEST_DIR}/danger_777.txt'" \
    "HIGH.*777|RULE-02"

# ------------------------------------------------------------------------------
# Test 5: World-writable directory without sticky bit
# ------------------------------------------------------------------------------
mkdir -p "${TEST_DIR}/shared_world_dir"
chmod 777 "${TEST_DIR}/shared_world_dir"
run_test "05" "World-writable directory without sticky bit" \
    "$BINARY -d '${TEST_DIR}/shared_world_dir'" \
    "HIGH.*World-Writable Directory Without Sticky Bit|RULE-03"

# ------------------------------------------------------------------------------
# Test 6: Directory with permission 700 (Private owner directory)
# ------------------------------------------------------------------------------
mkdir -p "${TEST_DIR}/private_dir"
chmod 700 "${TEST_DIR}/private_dir"
run_test "06" "Directory with permission 700" \
    "$BINARY -d '${TEST_DIR}/private_dir'" \
    "700|Standard Permissions Baseline"

# ------------------------------------------------------------------------------
# Test 7: Symbolic Link handling (Must not follow blindly)
# ------------------------------------------------------------------------------
ln -s "${TEST_DIR}/file_644.txt" "${TEST_DIR}/symlink_to_file"
run_test "07" "Symbolic link handling" \
    "$BINARY -f '${TEST_DIR}/symlink_to_file'" \
    "Symbolic Link|RULE-00"

# ------------------------------------------------------------------------------
# Test 8: Missing file (Graceful error handling)
# ------------------------------------------------------------------------------
run_test "08" "Missing file error handling" \
    "$BINARY -f '${TEST_DIR}/nonexistent_file_xyz.txt'" \
    "Error: Cannot inspect|No such file"

# ------------------------------------------------------------------------------
# Test 9: Empty directory
# ------------------------------------------------------------------------------
mkdir -p "${TEST_DIR}/empty_dir"
run_test "09" "Empty directory analysis" \
    "$BINARY -d '${TEST_DIR}/empty_dir'" \
    "DIRECTORY PERMISSION ANALYSIS"

# ------------------------------------------------------------------------------
# Test 10: Nested directory containing multiple files
# ------------------------------------------------------------------------------
mkdir -p "${TEST_DIR}/nested_root/sub1/sub2"
touch "${TEST_DIR}/nested_root/root_f.txt"
touch "${TEST_DIR}/nested_root/sub1/sub1_f.txt"
touch "${TEST_DIR}/nested_root/sub1/sub2/sub2_f.txt"
chmod 644 "${TEST_DIR}/nested_root/root_f.txt"
chmod 644 "${TEST_DIR}/nested_root/sub1/sub1_f.txt"
chmod 777 "${TEST_DIR}/nested_root/sub1/sub2/sub2_f.txt"
run_test "10" "Recursive nested directory scan" \
    "$BINARY -r '${TEST_DIR}/nested_root'" \
    "Files scanned:.*3|Directories scanned:.*3"

# ------------------------------------------------------------------------------
# Test 11: Inaccessible directory (permission 000)
# ------------------------------------------------------------------------------
mkdir -p "${TEST_DIR}/inaccessible_dir"
chmod 000 "${TEST_DIR}/inaccessible_dir"
run_test "11" "Inaccessible directory (Permission Denied)" \
    "$BINARY -r '${TEST_DIR}/inaccessible_dir'" \
    "Cannot Inspect Directory Metadata|Directory Unreadable|ERR-"
chmod 755 "${TEST_DIR}/inaccessible_dir"

# ------------------------------------------------------------------------------
# Test 12: Invalid command-line user input
# ------------------------------------------------------------------------------
run_test "12" "Invalid user argument handling" \
    "$BINARY --invalid-flag-12345" \
    "Unknown option"

# ------------------------------------------------------------------------------
# Test Summary
# ------------------------------------------------------------------------------
echo -e "\n${C_CYAN}${C_BOLD}=====================================================================${C_RESET}"
echo -e "${C_BOLD}TEST RESULTS SUMMARY:${C_RESET}"
echo -e "Total Tests Executed:  ${TOTAL_TESTS}"
echo -e "Passed:                ${C_GREEN}${PASS_COUNT}${C_RESET}"
echo -e "Failed:                ${C_RED}${FAIL_COUNT}${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}=====================================================================${C_RESET}\n"

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${C_GREEN}${C_BOLD}[+] ALL 12 TEST CASES PASSED SUCCESSFULLY!${C_RESET}\n"
    exit 0
else
    echo -e "${C_RED}${C_BOLD}[-] Some test cases failed.${C_RESET}\n"
    exit 1
fi
