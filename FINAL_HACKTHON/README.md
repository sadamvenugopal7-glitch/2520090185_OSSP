# Linux File Permission Analyzer

[![Language: C](https://img.shields.io/badge/Language-C99%20%2F%20POSIX-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Compiler: GCC](https://img.shields.io/badge/Compiler-GCC%2015.2%2B-orange.svg)](https://gcc.gnu.org/)
[![Platform: Linux / WSL](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20WSL2-green.svg)](https://ubuntu.com/)
[![Tests: 12/12 Passing](https://img.shields.io/badge/Tests-12%2F12%20Passed-brightgreen.svg)](#testing-instructions)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Hackathon: 2026](https://img.shields.io/badge/Hackathon-17%20October%202026-red.svg)](#team-members)

> An educational, high-performance Linux cybersecurity utility written in native C to audit file and directory permissions, detect insecure configurations, explain risks, and recommend actionable `chmod` remediations.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Abstract](#abstract)
3. [Problem Statement](#problem-statement)
4. [Objectives](#objectives)
5. [Key Features](#key-features)
6. [Technologies Used](#technologies-used)
7. [System Requirements](#system-requirements)
8. [Project Structure](#project-structure)
9. [Installation & Compilation](#installation--compilation)
10. [Usage Guide](#usage-guide)
11. [Live Demonstration Script (3-5 Minutes)](#live-demonstration-script-3-5-minutes)
12. [Testing Instructions](#testing-instructions)
13. [Example Terminal Output](#example-terminal-output)
14. [Report Generation](#report-generation)
15. [Security & Safety Considerations](#security--safety-considerations)
16. [Limitations](#limitations)
17. [Future Enhancements](#future-enhancements)
18. [Team Members](#team-members)
19. [Git & GitHub Submission Instructions](#git--github-submission-instructions)
20. [License](#license)

---

## Project Overview

The **Linux File Permission Analyzer** is an open-source, read-only system security tool developed in modular C for GNU/Linux operating systems and Windows Subsystem for Linux (WSL). It uses native POSIX system calls to inspect file mode bits, resolves file ownership, checks for high-risk permissions such as `777`, world-writable files, exposed `.env` secrets, and SUID binaries, and generates formatted text logs and modern HTML cybersecurity dashboards.

---

## Abstract

In Linux systems, the Discretionary Access Control (DAC) model governs which users can read, write, or execute files. However, novice users and developers frequently bypass permission restrictions by applying broad permissions such as `chmod 777`, unintentionally leaving critical files open to unauthorized tampering, data corruption, and local privilege escalation.

This tool solves this challenge by automating permission auditing. Without modifying system files, it analyzes actual file metadata, calculates octal and symbolic permissions, evaluates configurations against 10 documented security rules, and outputs plain-language explanations along with recommended corrective `chmod` commands.

---

## Problem Statement

1. **The "chmod 777" Anti-Pattern:** Developers often blindly run `chmod 777` when facing permission-denied errors, exposing entire directory trees to tampering.
2. **Exposed Credentials:** Secrets stored in `.env`, `.pem`, and `.key` files are frequently left world-readable (`644` or `666`).
3. **Privilege Escalation:** Executables or scripts with world-write permissions allow an unprivileged attacker to inject malicious shell commands.
4. **Lack of Educational Tools:** Built-in commands like `ls -l` display raw strings like `-rwxrwxrwx` without explaining *why* the configuration is dangerous.

---

## Objectives

- Provide real-time analysis of file metadata using POSIX `lstat()`, `realpath()`, `opendir()`, and `readdir()`.
- Accurately convert permission bits to symbolic (`-rwxr-xr-x`) and octal (`0755`) notations.
- Traverse deep directory trees recursively while avoiding symlink loops and handling inaccessible folders gracefully.
- Classify findings into four severity tiers: **HIGH**, **MEDIUM**, **LOW**, and **INFORMATIONAL**.
- Generate executive-grade HTML dashboards and plaintext audit logs.
- Enforce strict read-only execution: never modify files or permissions automatically.

---

## Key Features

- **Single File Analysis:** Detailed inspection of file path, type, symbolic/octal permissions, UID/GID, owner/group names, size, and last modification time.
- **Single & Recursive Directory Scanning:** Deep directory traversal with loop detection based on device and inode tracking (`dev_t`, `ino_t`).
- **Symlink Boundary Protection:** Inspects symbolic links without following them recursively, preventing infinite loops.
- **Security Rule Engine:** Evaluates 10 documented rules covering world-writable files, world-writable directories, SUID/SGID bits, exposed credentials, and least-privilege baselines.
- **Dual Reporting:**
  - Standardized plain-text reports (`.txt`).
  - Standalone dark-themed HTML5/CSS3 cybersecurity dashboard (`.html`) featuring search and real-time severity filtering.
- **Interactive TUI & Scriptable CLI:** Run via a menu or automate through CLI flags (`-f`, `-d`, `-r`, `-H`, `-t`).

---

## Technologies Used

- **Primary Language:** C (C99 Standard / POSIX.1-2008 Compliance)
- **Compiler:** GCC (GNU Compiler Collection) with `-Wall -Wextra -Wpedantic`
- **Build System:** GNU Make
- **Target OS:** Ubuntu Linux (20.04 / 22.04 / 24.04 LTS), Ubuntu under WSL2
- **Version Control:** Git & GitHub

---

## System Requirements

- **Operating System:** Ubuntu Linux or Ubuntu under WSL on Windows 10/11
- **Tools:** GCC, GNU Make, Bash shell
- **Memory:** Less than 15 MB RAM utilized during scan
- **Disk Space:** ~5 MB for project files and compiled binary

---

## Project Structure

```
linux-file-permission-analyzer/
|-- src/
|   |-- main.c               # Terminal menu, CLI argument dispatcher & session loop
|   |-- analyzer.c           # File metadata collector & security rule engine
|   |-- analyzer.h           # Data structures, prototypes & rule definitions
|   |-- scanner.c            # POSIX single-level & recursive directory scanner
|   |-- scanner.h            # Scanner prototypes & loop protection types
|   |-- report.c             # Text audit report & HTML dashboard generator
|   |-- report.h             # Reporting prototypes & HTML escaping utility
|
|-- tests/
|   |-- test_cases.md        # Detailed test matrix and observed behaviors
|   |-- test_permissions.sh  # Automated 12-test validation script
|
|-- demo_files/
|   |-- README.md            # Live demonstration instructions
|   |-- normal.txt           # Standard compliant file (644)
|   |-- private.txt          # Owner-only confidential file (600)
|   |-- risky.txt            # Insecure world-writable file (777)
|   |-- script.sh            # Standard executable script (755)
|   |-- .env                 # Sensitive credentials demonstration file
|   |-- nested/
|       |-- subfile.txt      # Multi-level recursive test file
|
|-- reports/
|   |-- .gitkeep             # Directory for outputted reports
|
|-- docs/
|   |-- architecture.md      # Detailed system architecture & Mermaid diagrams
|   |-- project_report.md    # 19-section academic project report
|   |-- viva_questions.md    # 25 viva questions with concise answers
|   |-- presentation.md      # 8-slide PowerPoint script with speaker notes
|
|-- Makefile                 # Make targets: all, clean, run, test, debug
|-- README.md                # Project documentation
|-- .gitignore               # Git exclusions for binaries, logs, and temp files
|-- LICENSE                  # MIT License
```

---

## Installation & Compilation

### Step 1: Open Terminal / WSL
Ensure you are in the project root directory.

### Step 2: Compile with Make
```bash
make
```
This runs GCC with strict warning flags:
```bash
gcc -Wall -Wextra -Wpedantic -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -O2 ...
```
The binary will be compiled to `bin/permission_analyzer`.

### Other Make Targets
```bash
make run    # Compile and launch the interactive terminal menu
make test   # Compile and run the 12-point automated test suite
make clean  # Remove compiled object files and binaries
make debug  # Build with debug symbols (-g -DDEBUG)
```

---

## Usage Guide

### 1. Interactive Terminal Mode
Run without arguments to launch the menu:
```bash
./bin/permission_analyzer
```
```
===============================================
       LINUX FILE PERMISSION ANALYZER          
===============================================
1. Analyze a single file
2. Analyze a directory
3. Recursively scan a directory
4. View security findings
5. Generate a text security report
6. Generate an HTML security report
7. View project information
0. Exit

Enter your choice:
```

### 2. Command-Line Options (CLI)
```bash
# Analyze a single file
./bin/permission_analyzer -f demo_files/risky.txt

# Non-recursive directory analysis
./bin/permission_analyzer -d demo_files/

# Recursive scan with text report export
./bin/permission_analyzer -r demo_files/ -t reports/audit.txt

# Recursive scan with HTML dashboard export
./bin/permission_analyzer -r demo_files/ -H reports/dashboard.html

# View help
./bin/permission_analyzer --help
```

---

## Live Demonstration Script (3-5 Minutes)

Follow these exact steps for the hackathon demonstration:

### Step 1: Show the Application Menu
```bash
./bin/permission_analyzer
```
*Speaking Script:* "Respected judges, we begin by launching our interactive terminal interface. It offers options for single-file analysis, directory scans, recursive audits, and reporting." (Press `0` to exit to command line).

### Step 2: Set Up Demo Files
Set up permissions on the demo files:
```bash
chmod 644 demo_files/normal.txt
chmod 600 demo_files/private.txt
chmod 777 demo_files/risky.txt
chmod 755 demo_files/script.sh
chmod 644 demo_files/.env
```
*(Note: If demonstrating under WSL on a Windows mount `/mnt/c`, run in `/tmp/demo_suite` where Linux POSIX permissions are natively active).*

### Step 3: Run Single File Analysis on a Risky File
```bash
./bin/permission_analyzer -f demo_files/risky.txt
```
*Speaking Script:* "Here, we analyze `risky.txt`. Notice our tool reads real kernel metadata via `lstat()`. It identifies the octal mode `777`, flags it as a HIGH severity risk under `RULE-02`, and provides an actionable recommendation: `chmod 644 demo_files/risky.txt`."

### Step 4: Run Recursive Scan and Generate HTML Report
```bash
./bin/permission_analyzer -r demo_files/ -H reports/demo_report.html
```
*Speaking Script:* "Next, we run a recursive scan on the entire directory tree. Notice how it traverses nested subdirectories, counts scanned entries, and aggregates statistics into a clean summary table."

### Step 5: Open the HTML Security Dashboard
```bash
# On Linux:
xdg-open reports/demo_report.html

# On WSL / Windows:
explorer.exe reports/demo_report.html
```
*Speaking Script:* "Our application generates a standalone cybersecurity dashboard with dark navy aesthetics. Judges can filter findings by High, Medium, Low, or Informational severity with zero external internet dependencies."

### Step 6: Conclude with Limitations & Future Scope
*Speaking Script:* "Our tool operates in 100% read-only mode to prevent unintended system breakage. In the future, we plan to package this as a GitHub Action and add support for POSIX Access Control Lists (ACLs)."

---

## Testing Instructions

An automated test suite validates all 12 required test scenarios:
```bash
make test
# OR
./tests/test_permissions.sh
```

### Test Results Summary
```
=====================================================================
       LINUX FILE PERMISSION ANALYZER - AUTOMATED TEST SUITE        
=====================================================================
[Test 01/12] File with permission 644... PASS
[Test 02/12] File with permission 600... PASS
[Test 03/12] Executable file with permission 755... PASS
[Test 04/12] File with permission 777 (Risk Flagging)... PASS
[Test 05/12] World-writable directory without sticky bit... PASS
[Test 06/12] Directory with permission 700... PASS
[Test 07/12] Symbolic link handling... PASS
[Test 08/12] Missing file error handling... PASS
[Test 09/12] Empty directory analysis... PASS
[Test 10/12] Recursive nested directory scan... PASS
[Test 11/12] Inaccessible directory (Permission Denied)... PASS
[Test 12/12] Invalid user argument handling... PASS
=====================================================================
[+] ALL 12 TEST CASES PASSED SUCCESSFULLY!
```
Detailed test documentation is in [`tests/test_cases.md`](tests/test_cases.md).

---

## Example Terminal Output

```
=======================================================
              FILE PERMISSION ANALYSIS
=======================================================
File Name:         risky.txt
Input Path:        demo_files/risky.txt
Resolved Path:     /home/user/project/demo_files/risky.txt
File Type:         Regular File
Permissions:       -rwxrwxrwx (Bits: rwxrwxrwx)
Octal Notation:    777 (Full: 0777)
Owner:             venu (UID: 1000)
Group:             venu (GID: 1000)
File Size:         214 B (214 bytes)
Last Modified:     2026-10-17 05:01:23
-------------------------------------------------------
SECURITY FINDINGS AND RECOMMENDATIONS:

  [Finding #1] [HIGH] Unrestricted Permissions (777)
  Rule ID:         RULE-02
  Target:          demo_files/risky.txt
  Permissions:     -rwxrwxrwx (Octal: 777)
  Explanation:     The file grants full Read, Write, and Execute access to Owner, Group, and Everyone (world). Any local user can overwrite, truncate, or inject malicious content.
  Recommendation:  Restrict access to the owner and necessary group. Regular files rarely need 777.
  Suggested Cmd:   chmod 644 "demo_files/risky.txt"
=======================================================
```

---

## Report Generation

### Plain-Text Audit Report (`reports/scan_report.txt`)
Contains structured ASCII tables with scan metadata, executive statistics, detailed findings, and full inventory tables suitable for piping to `grep`, `less`, or log aggregators.

### Cyber Dark HTML Report (`reports/scan_report.html`)
- **Theme:** Cybersecurity dark navy (`#0b1120`, `#151e32`, `#38bdf8`)
- **Interactive Controls:** Instant JavaScript buttons to filter by High, Medium, Low, or Informational severity.
- **Search Bar:** Real-time path and rule filtering.
- **Copyable Fixes:** Displays exact recommended commands (e.g. `chmod 600 .env`).
- **XSS Protection:** All file paths are sanitized via `escape_html()`.

---

## Security & Safety Considerations

1. **Strict Read-Only Execution:** The analyzer will **never** automatically alter file modes, delete files, or overwrite directories.
2. **Reviewable Recommendations:** Chmod commands are provided as suggestions for the user to review.
3. **Loop Prevention:** Uses device and inode tracking (`dev_t`, `ino_t`) to prevent infinite recursion.
4. **Symlink Boundary:** Uses `lstat()` to inspect symlink attributes without dereferencing, preventing link-following loops.
5. **No Root Requirement:** Operates completely under unprivileged user accounts.

---

## Limitations

1. **POSIX DAC Only:** Focuses on standard Unix permission bits; does not currently parse POSIX Access Control Lists (`getfacl`) or SELinux contexts.
2. **WSL Windows Mounts:** In WSL, files mounted on `/mnt/c` inherit synthetic `777` permissions unless the `metadata` option is enabled in `/etc/wsl.conf`. Testing on native Linux ext4 directories (`/tmp`, `/home`) reflects true POSIX behavior.

---

## Future Enhancements

- **CI/CD Integration:** Package as a GitHub Action to audit repositories on pull requests.
- **Remediation Script Export:** Generate a reviewable `fix_permissions.sh` script.
- **Extended Attributes:** Support for POSIX ACLs (`libacl`) and SELinux/AppArmor security contexts.

---

## Team Members

| Name | Roll Number | Primary Responsibilities |
| :--- | :--- | :--- |
| **Abhishek Yadav K** | `2520090208` | File metadata collection, POSIX system calls, symbolic/octal representation |
| **S Venu Gopal** | `2520090185` | Security rule engine, severity classification, system integration |
| **R ROHIT** | `2520080037` | Directory scanning engine, dual report generation, test suite |

---

## Git & GitHub Submission Instructions

To push this project to GitHub:

```bash
# 1. Initialize local repository
git init

# 2. Add all project files
git add .

# 3. Create initial commit
git commit -m "Initial commit: Complete Linux File Permission Analyzer project"

# 4. Set main branch
git branch -M main

# 5. Add your remote GitHub repository URL (replace with your repository link)
# git remote add origin https://github.com/<your-username>/linux-file-permission-analyzer.git

# 6. Push code to GitHub
# git push -u origin main
```

---

## License

This project is licensed under the **MIT License** — see the [`LICENSE`](LICENSE) file for details.
