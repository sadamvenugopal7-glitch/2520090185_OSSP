# Hackathon Presentation Slide Deck

**Project Title:** Linux File Permission Analyzer  
**Event:** College Hackathon — 17 October 2026  
**Category:** Linux System Programming / Cybersecurity  

**Presenting Team:**
1. **Abhishek Yadav K** — `2520090208`
2. **S Venu Gopal** — `2520090185`
3. **R ROHIT** — `2520080037`

---

## Slide 1: Project Title and Team

### Visual Layout
- **Header:** Linux File Permission Analyzer
- **Subtitle:** Automated POSIX Permission Auditing & Least-Privilege Risk Engine
- **Event:** College Innovation Hackathon (17 October 2026)
- **Team Members & Roles:**
  - **Abhishek Yadav K** (2520090208) — *File Metadata Collection & Octal/Symbolic Translation*
  - **S Venu Gopal** (2520090185) — *Security Rule Engine, Risk Classification & Integration*
  - **R ROHIT** (2520080037) — *Recursive Traversal Engine, HTML Reporting & Testing*

### Speaker Notes (Speaker: Abhishek Yadav K)
> "Good morning, respected judges and faculty members. Today, our team—comprising myself Abhishek, Venu Gopal, and Rohit—presents the **Linux File Permission Analyzer**. 
> As first-year CSIT students exploring Linux system programming, we frequently observed students and developers assigning overly broad permissions like `chmod 777` just to bypass access denied errors. Our project addresses this vulnerability by delivering a native C-based cybersecurity auditing tool that analyzes file permissions, explains the associated risks in plain language, and provides actionable remediation guidance."

---

## Slide 2: Problem Statement

### Slide Content
- **The "chmod 777" Epidemic:** Developers frequently grant global read, write, and execute permissions without understanding the consequences.
- **Silent Security Exposures:**
  - World-writable regular files allow local users to tamper with or corrupt critical data.
  - World-writable executables invite local privilege escalation (code injection).
  - Configuration files (`.env`, private keys) left world-readable expose credentials and API secrets.
- **Limitations of Native Tools:**
  - Standard commands like `ls -la` display raw bit patterns (e.g. `drwxrwxrwx`) but provide no security risk assessment.
  - Manual inspection across hundreds of nested directories is tedious and prone to human error.

### Speaker Notes (Speaker: Abhishek Yadav K)
> "In Unix-like operating systems, security relies on Discretionary Access Control. However, when a developer encounters a 'permission denied' error, the most common bad habit is running `chmod 777`. This immediately grants read, write, and execute permissions to every user on the system.
> The danger is silent: attackers do not need root access if configuration files or binaries are already world-writable. Current built-in commands like `ls -l` show permission strings, but they don't warn you if a file is dangerous. We built this tool to automate this discovery and cultivate a security-first mindset."

---

## Slide 3: Objectives & Proposed Solution

### Slide Content
- **Core Objectives:**
  - Build a native Linux utility in C to audit file and directory permissions using real POSIX kernel metadata.
  - Translate raw octal and bitmask permissions into intuitive symbolic and human-readable forms.
  - Implement recursive directory traversal with loop prevention and symlink boundaries.
  - Classify risks into 4 severity levels: **HIGH**, **MEDIUM**, **LOW**, and **INFORMATIONAL**.
  - Generate dual reporting outputs: Terminal diagnostics, plain-text audit logs, and an executive-grade HTML dashboard.
- **Safety Guarantee:**
  - **100% Read-Only Mode:** The analyzer never modifies, deletes, or executes files on the host system.
  - Generates recommended, reviewable `chmod` commands for administrator authorization.

### Speaker Notes (Speaker: S Venu Gopal)
> "Our solution is the **Linux File Permission Analyzer**. Our goal was not to simulate results or display mock data, but to interact directly with the Linux kernel using POSIX system calls.
> We designed the tool around five core pillars: accurate metadata collection, deep recursive scanning, a multi-tier security rule engine, pedagogical explanations, and comprehensive reporting. Crucially, our tool guarantees safety: it operates in read-only mode, providing suggested `chmod` commands without blindly modifying system state."

---

## Slide 4: System Architecture

### Slide Content
```
[User / Terminal Menu]
          |
          v
[Path Validation & Traversal Engine (scanner.c)]
   --> opendir(), readdir(), loop prevention (dev_t, ino_t)
          |
          v
[POSIX Metadata Extraction Engine (analyzer.c)]
   --> lstat(), realpath(), getpwuid(), getgrgid()
          |
          v
[Security Rule & Severity Engine (analyzer.c)]
   --> RULES 01-10: 777 checks, world-write, SUID, sensitive files
          |
          v
[Dual Report Generator (report.c)]
   --> Plain-text Audit Logs (.txt)
   --> Modern Cyber Dark HTML5 Dashboard (.html)
```

### Speaker Notes (Speaker: S Venu Gopal)
> "Here we see our decoupled modular architecture. The entry point handles user interaction via an intuitive terminal menu or command-line flags. 
> The path validator passes requests to the directory scanner, which leverages `opendir` and `readdir` alongside device-and-inode loop tracking to prevent circular traversals.
> Next, the metadata engine queries the kernel via `lstat` to capture file attributes without dereferencing symlinks. The security rule engine then categorizes findings by severity, and the report engine serializes the data into ANSI terminal summaries, text logs, and modern HTML dashboards."

---

## Slide 5: Implementation & Technologies

### Slide Content
- **Programming Language:** C (C99 Standard / POSIX.1-2008 Compliance).
- **Core POSIX System Calls:**
  - `lstat()` — Link-safe file status query.
  - `realpath()` — Canonical path resolution.
  - `opendir()`, `readdir()`, `closedir()` — Directory stream processing.
  - `getpwuid()`, `getgrgid()` — User and group identity resolution.
- **Compiler & Toolchain:**
  - GCC with strict flags: `-Wall -Wextra -Wpedantic -std=c99 -O2`.
  - Compiled with **0 errors and 0 warnings**.
  - Automated building via GNU `Makefile` (`make`, `make run`, `make test`, `make clean`).
- **Security Engineering:**
  - Safe bounded buffer copy routines (`safe_copy`).
  - Strict HTML character escaping (`escape_html`) to prevent XSS.

### Speaker Notes (Speaker: R ROHIT)
> "We chose C and standard POSIX APIs because they provide raw, unmediated communication with the Linux kernel without bloated external runtimes.
> Our codebase compiles cleanly with zero warnings under GCC's strictest flags: `-Wall -Wextra -Wpedantic`. We implemented custom safe buffer routines to guarantee immunity against buffer overflows. 
> Furthermore, when generating HTML dashboards, all filenames and paths are rigorously sanitized through our `escape_html` function, ensuring complete resilience against stored script injection."

---

## Slide 6: Live Demonstration & Testing

### Slide Content
- **12 Automated Test Scenarios Validated (`tests/test_permissions.sh`):**
  1. Standard file (`644`) — Baseline OK
  2. Strict private key (`600`) — Baseline OK
  3. Executable binary (`755`) — Baseline OK
  4. World-writable file (`777`) — **HIGH Risk** flagged
  5. World-writable directory (no sticky bit) — **HIGH Risk** flagged
  6. Private directory (`700`) — Baseline OK
  7. Symbolic link — Boundary isolation verified
  8. Missing path — Graceful error handling
  9. Empty directory — Clean traversal
  10. Multi-level nested subdirectories — Full depth traversal
  11. Inaccessible directory (`0000`) — `EACCES` recovery without crashing
  12. Invalid CLI options — Helpful error message
- **Results:** **12 / 12 PASS (100% Success Rate)**.

### Speaker Notes (Speaker: R ROHIT)
> "To verify our application, we created a comprehensive automated test suite covering 12 distinct edge cases, from normal 644 and 755 files to insecure 777 files, world-writable directories, inaccessible folders, and symbolic links.
> As shown on the slide, all 12 tests passed with a 100% success rate. The application handles permission-denied errors gracefully, tracks nested directory depths, and flags security risks accurately."

---

## Slide 7: Results, Security Impact & Limitations

### Slide Content
- **Demonstrated Results:**
  - Accurately identified world-writable `.env` credentials and `risky.txt` files in live tests.
  - Automatically suggested least-privilege remedies: `chmod 644` for files, `chmod 600` for keys, `chmod 755` for scripts.
  - Generated fully functional, responsive HTML dashboards featuring real-time client-side severity filtering.
- **Security Impact:**
  - Prevents accidental local privilege escalation and data tampering.
  - Teaches developers the exact rationale behind least-privilege security.
- **Current Limitations:**
  - Evaluates standard POSIX DAC permissions; does not yet inspect POSIX ACLs (`getfacl`) or SELinux contexts.
  - Windows WSL default mounts (`/mnt/c/...`) require metadata configuration for POSIX `chmod` persistence.

### Speaker Notes (Speaker: S Venu Gopal)
> "The security impact of this tool is immediate: in our test suite, the analyzer caught exposed credentials in a `.env` file and an insecure 777 file within milliseconds, recommending exact corrective commands.
> In terms of limitations, our tool currently targets standard POSIX Discretionary Access Control. It does not inspect Access Control Lists or SELinux policies, and WSL users must ensure filesystem metadata is enabled when working on Windows drives. These limitations provide clear directions for future expansion."

---

## Slide 8: Conclusion & Future Scope

### Slide Content
- **Conclusion:**
  - Successfully built a professional, robust Linux security auditing tool in native C.
  - Promotes the Principle of Least Privilege across academic and developer environments.
  - Fast, modular, safe, and zero-dependency.
- **Future Scope:**
  - **CI/CD Integration:** Package as a GitHub Action to prevent insecure file permissions from being merged into production repositories.
  - **Automated Fix Script:** Option to generate a reviewable `fix_permissions.sh` script for batch remediation.
  - **Advanced Access Controls:** Integration with POSIX ACLs (`libacl`) and SELinux/AppArmor security labels.

### Speaker Notes (Speaker: Abhishek Yadav K)
> "To conclude, the Linux File Permission Analyzer demonstrates that system security can be both mathematically rigorous and beginner-friendly. By combining low-level C programming with clear explanations and modern dashboard reporting, we have created a tool that protects systems while educating users.
> In the future, we plan to package this as a GitHub Action for continuous security auditing and integrate POSIX ACL inspection. Thank you for your time, and we now welcome any questions!"
