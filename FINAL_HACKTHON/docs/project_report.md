# Comprehensive Academic Project Report

---

# LINUX FILE PERMISSION ANALYZER
### A Modular C & POSIX-Based Cybersecurity Audit Application for GNU/Linux Systems

**Course:** B.Tech — Computer Science and Information Technology (CSIT)  
**Hackathon Event:** College Innovation Hackathon 2026  
**Date of Submission:** 17 October 2026  

**Project Developed By:**
1. **Abhishek Yadav K** — Roll Number: `2520090208`
2. **S Venu Gopal** — Roll Number: `2520090185`
3. **R ROHIT** — Roll Number: `2520080037`

**Academic Mentorship & Evaluation Board:**  
Department of Computer Science & Engineering / Information Technology  

---

## 1. Title Page Details

- **Project Title:** Linux File Permission Analyzer
- **Category:** Linux System Programming & System Security / Cybersecurity
- **Implementation Language:** C (C99 Standard / POSIX.1-2008 Compliance)
- **Target Environments:** Ubuntu Linux 22.04 / 24.04 LTS, Ubuntu under Windows Subsystem for Linux (WSL2), Debian, Red Hat Enterprise Linux
- **Development Toolchain:** GNU Compiler Collection (GCC 15.2 / 11+), GNU Make 4.4+, Git Version Control System

---

## 2. Abstract

File permission misconfigurations represent one of the most pervasive yet preventable security vulnerabilities across Unix-like and Linux operating systems. Novice users, junior developers, and system administrators frequently assign overly broad access rights—such as `chmod 777`—to resolve immediate permission-denied errors, unintentionally exposing confidential data to local privilege escalation, unauthorized tampering, and arbitrary code injection.

This project presents the **Linux File Permission Analyzer**, an open-source, read-only cybersecurity auditing tool implemented in modular C using native POSIX system calls (`lstat`, `realpath`, `opendir`, `readdir`). The application recursively inspects single files or directory trees, parses raw octal and symbolic permission bits, resolves user and group identities via `/etc/passwd` and `/etc/group`, and evaluates file metadata against ten defined security rules. Findings are classified across four severity tiers (High, Medium, Low, Informational) alongside actionable, non-destructive `chmod` remediation commands. The tool outputs formatted ANSI terminal diagnostics, plaintext audit logs, and an interactive cybersecurity HTML dashboard with zero third-party dependencies.

---

## 3. Introduction

The GNU/Linux operating system relies fundamentally on the Discretionary Access Control (DAC) model introduced in early Unix systems. In Linux, every file and directory is associated with an owner (User), an assigned Group, and Others (the rest of the local system users). Access permissions are governed by three primary bits:
- **Read (`r`, 4):** Grants permission to read file contents or list directory entries.
- **Write (`w`, 2):** Grants permission to modify or truncate file contents, or create/delete entries within a directory.
- **Execute (`x`, 1):** Grants permission to execute a binary/script, or traverse/enter a directory.

Special mode bits—namely Setuid (`S_ISUID`), Setgid (`S_ISGID`), and the Sticky bit (`S_ISVTX`)—provide elevated execution privileges or deletion protections. While this design provides remarkable flexibility, manual inspection of nested file permissions across thousands of filesystem entries is tedious, error-prone, and overwhelming for beginners.

The **Linux File Permission Analyzer** bridges this gap by automating the detection and plain-language explanation of permission risks, helping college students, developers, and administrators cultivate secure system programming habits.

---

## 4. Problem Statement

In modern computing environments, file permission vulnerabilities manifest due to:
1. **The "chmod 777" Anti-Pattern:** Users experiencing access denied errors often blindly run `chmod -R 777 .`, granting global read, write, and execute permissions to all users.
2. **Exposed Secrets in Configuration Files:** Web applications frequently store API keys and database credentials in `.env`, `.pem`, or configuration files with default world-readable permissions (`644` or `666`).
3. **Privilege Escalation Risks:** Executables that are world-writable can be modified by an unprivileged local attacker. When an administrator or cron job runs the binary, attacker-injected code executes with root privileges.
4. **Lack of Educational Feedback:** Standard Linux utilities such as `ls -l` display raw symbolic strings (e.g. `drwxrwxrwx`) but provide zero contextual guidance regarding whether that permission is safe or why it poses a threat.

---

## 5. Existing System

Traditional approaches to permission analysis in Linux rely on:
- **Manual Commands (`ls -la`, `stat`):** Displays file metadata one entry at a time without risk assessment.
- **Generic Find Scripts (`find / -perm -777`):** Generates long, unfiltered lists of paths that overwhelm users without providing severity ratings or remediation guidance.
- **Heavyweight Enterprise Scanners (e.g., Lynis, OpenSCAP):** Powerful but complex to configure, requiring root privileges, high memory overhead, and steep learning curves unsuitable for quick classroom or hackathon demonstrations.

### Limitations of Existing Systems:
- No interactive beginner-friendly terminal interface.
- Lack of clear, educational risk explanations tailored to CSIT students.
- Risk of accidental filesystem damage if using automated fix scripts.
- Absence of lightweight, self-contained HTML reports generated without bulky runtimes.

---

## 6. Proposed System

The proposed **Linux File Permission Analyzer** introduces:
1. **Interactive Terminal User Interface:** A clear, numbered menu guiding users through single-file inspections, shallow directory checks, and deep recursive scans.
2. **Context-Aware Security Rule Engine:** A deterministic rule engine that differentiates between dangerous world-writable files and legitimate public resources, evaluating special bits like SUID and the sticky bit.
3. **Strict Read-Only Safety Architecture:** The program operates in passive audit mode; it never modifies, deletes, or executes files on the host machine.
4. **Dual Reporting Pipeline:** Instant generation of standardized plaintext audit files and modern, dark-themed HTML cybersecurity dashboards with interactive client-side filtering.
5. **Zero External Dependencies:** Built entirely with standard C (C99) and POSIX libraries, ensuring native execution on any Linux distribution or WSL setup without needing Python, Node.js, or package managers.

---

## 7. Objectives

1. Develop a high-performance C application using POSIX system APIs (`lstat`, `opendir`, `readdir`).
2. Provide precise translation between raw file mode bits, symbolic representations (`-rw-r--r--`), and octal notation (`0644`).
3. Implement recursive traversal algorithms that safely bypass symlink loops and handle permission-denied errors gracefully.
4. Detect high-risk permission anomalies, including 777 files, world-writable scripts, exposed `.env` credentials, and SUID binaries.
5. Provide actionable remediation advice with copy-pasteable `chmod` commands.
6. Generate production-ready HTML security dashboards formatted for executive and technical review.

---

## 8. Hardware and Software Requirements

### Hardware Requirements
- **Processor:** x86_64 or ARM64 multi-core processor (Intel Core i3/i5/i7, AMD Ryzen, or Apple Silicon via Linux VM).
- **RAM:** Minimum 512 MB (less than 15 MB utilized by the analyzer process).
- **Storage:** Minimum 10 MB free disk space for source code and compiled binaries.

### Software Requirements
- **Operating System:** Ubuntu Linux 20.04 / 22.04 / 24.04 LTS, Debian 11/12, or Windows 10/11 with WSL2 (Ubuntu).
- **Compiler:** GCC (GNU Compiler Collection) version 9.0 or higher.
- **Build System:** GNU Make 4.0+.
- **Standard Libraries:** `glibc` with POSIX.1-2008 support (`<sys/stat.h>`, `<dirent.h>`, `<pwd.h>`, `<grp.h>`).
- **Web Browser:** Any modern web browser (Google Chrome, Mozilla Firefox, Microsoft Edge) to view generated HTML dashboards.

---

## 9. System Architecture

The application implements a layered pipeline:

```
[User Input] --> [Terminal Interface] --> [Path Validation] --> [Directory Scanner]
                                                                        |
                                                                        v
[Report Generator] <-- [Severity Classifier] <-- [Security Rules] <-- [POSIX Metadata Engine]
```

Please refer to `docs/architecture.md` for comprehensive architectural diagrams and Mermaid flowcharts.

---

## 10. Module Descriptions

### Module A: File Metadata & Permission Analysis (`src/analyzer.c`)
- **Developer:** Abhishek Yadav K
- **Role:** Extracts file size, ownership UID/GID, last modified timestamp, and mode bits. Implements bitwise operations to construct symbolic strings (`-rwxr-xr-x`) and octal values (`0755`). Resolves usernames from `/etc/passwd`.

### Module B: Security Rule Engine & Severity Classifier (`src/analyzer.c`)
- **Developer:** S Venu Gopal
- **Role:** Evaluates extracted metadata against security rules (`RULE-00` to `RULE-10`). Assigns severity levels (`HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) and formulates pedagogical explanations and corrective `chmod` suggestions.

### Module C: Recursive Directory Traversal (`src/scanner.c`)
- **Developer:** R ROHIT
- **Role:** Traverses hierarchical directory structures using `opendir()` and `readdir()`. Maintains loop prevention structures using `dev_t` and `ino_t`, ensures symbolic links are never recursively traversed, and handles inaccessible folders gracefully.

### Module D: Dual Report Generator (`src/report.c`)
- **Developers:** R ROHIT & S Venu Gopal
- **Role:** Serializes scan state into monospaced text logs and standalone HTML5/CSS3 cybersecurity dashboards with interactive client-side JavaScript filtering and XSS-safe character escaping.

---

## 11. Algorithms and Workflow

### Algorithm 1: Recursive Traversal with Loop Detection
```
FUNCTION ScanDirectory(path, depth, max_depth, context):
    IF depth > max_depth THEN RETURN
    stat_result = lstat(path)
    IF stat_result FAILS THEN
        Record "ERR-ACCESS" Finding
        RETURN
        
    IF IsSymlink(stat_result) THEN
        EvaluateRules(path)
        RETURN  // Do not traverse into symlink targets
        
    IF (stat_result.device, stat_result.inode) IN VisitedList THEN
        RETURN  // Loop prevented
        
    Add (stat_result.device, stat_result.inode) TO VisitedList
    EvaluateRules(path)
    
    dir_handle = opendir(path)
    IF dir_handle IS NULL THEN
        Record "ERR-UNREAD" Finding
        RETURN
        
    WHILE (entry = readdir(dir_handle)) IS NOT NULL:
        IF entry.name == "." OR entry.name == ".." THEN CONTINUE
        child_path = Concatenate(path, entry.name)
        child_stat = lstat(child_path)
        
        IF child_stat is Directory AND RecursiveEnabled THEN
            ScanDirectory(child_path, depth + 1, max_depth, context)
        ELSE
            EvaluateRules(child_path)
            RecordEntry(child_path)
            
    closedir(dir_handle)
END FUNCTION
```

### Algorithm 2: Security Rule Classification
```
FUNCTION EvaluateSecurityRules(file_info):
    IF IsSymlink(file_info) THEN
        CreateFinding(RULE_00, INFO, "Symbolic Link Encountered")
        RETURN
        
    IF IsRegularFile(file_info) THEN
        IF file_info.octal == 0777 THEN
            CreateFinding(RULE_02, HIGH, "Unrestricted Permissions (777)", "chmod 644")
        ELSE IF (file_info.mode & S_IWOTH) THEN
            CreateFinding(RULE_01, HIGH, "World-Writable Regular File", "chmod 644")
            
    IF IsDirectory(file_info) THEN
        IF (file_info.mode & S_IWOTH) AND NOT (file_info.mode & S_ISVTX) THEN
            CreateFinding(RULE_03, HIGH, "World-Writable Directory Without Sticky Bit", "chmod 755")
        ELSE IF (file_info.mode & S_IWOTH) AND (file_info.mode & S_ISVTX) THEN
            CreateFinding(RULE_06, INFO, "World-Writable Directory With Sticky Bit (e.g. /tmp)")
            
    IF IsSensitiveFilename(file_info.name) AND HasBroadPermissions(file_info) THEN
        CreateFinding(RULE_04, HIGH, "Sensitive Credential Exposed", "chmod 600")
        
    IF (file_info.mode & S_ISUID) THEN
        CreateFinding(RULE_05A, HIGH_OR_MEDIUM, "Setuid Bit Active", "chmod u-s")
        
    IF (file_info.mode & S_IWGRP) AND NOT (file_info.mode & S_IWOTH) THEN
        CreateFinding(RULE_07, LOW, "Group-Writable File", "chmod g-w")
        
    IF NoRisksFound THEN
        CreateFinding(RULE_10, INFO, "Standard Permissions Baseline", "None (Compliant)")
END FUNCTION
```

---

## 12. Implementation Details

The implementation strictly adheres to standard C (C99) with `-Wall -Wextra -Wpedantic` flags. Memory management is rigorously controlled:
- Dynamic arrays expand geometrically (factor of 2) to maintain amortized $O(1)$ insertions.
- All allocated memory for findings, visited inode lists, and scanned entries is freed via explicit teardown functions (`scan_context_free()`).
- All string copies use bounded `safe_copy` functions that eliminate buffer overruns.

---

## 13. Testing Methodology

Testing was conducted using a dedicated bash automation suite (`tests/test_permissions.sh`) executed on an isolated temporary sandbox (`/tmp/analyzer_test_sandbox_$$`). The suite validates 12 mandatory scenarios:
1. Standard user file (`644`)
2. Private key file (`600`)
3. Executable script (`755`)
4. High-risk 777 file
5. World-writable directory without sticky bit
6. Private directory (`700`)
7. Symbolic link boundary isolation
8. Non-existent file error handling
9. Empty directory traversal
10. Deeply nested directory structure
11. Inaccessible directory (`0000`) error recovery
12. Invalid CLI argument rejection

---

## 14. Actual Test Results

```
=====================================================================
       LINUX FILE PERMISSION ANALYZER - AUTOMATED TEST SUITE        
=====================================================================
Sandbox Directory: /tmp/analyzer_test_sandbox_625

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
TEST RESULTS SUMMARY:
Total Tests Executed:  12
Passed:                12
Failed:                0
=====================================================================
[+] ALL 12 TEST CASES PASSED SUCCESSFULLY!
```

---

## 15. Advantages

1. **Lightweight & Fast:** Executes thousands of file evaluations in milliseconds with minimal CPU and memory footprints.
2. **Zero Dependencies:** Compiles into a single binary requiring only standard POSIX C libraries.
3. **Safe by Design:** Strictly read-only; impossible for the tool to corrupt or delete system files.
4. **Educational Value:** Explains *why* a configuration is insecure instead of merely showing raw bits.
5. **Modern Visualization:** Generates responsive, executive-ready HTML cybersecurity dashboards.

---

## 16. Limitations

1. **Local Discretionary Access Control Only:** The current release audits traditional POSIX permission bits. It does not inspect Access Control Lists (POSIX ACLs via `getfacl`) or SELinux / AppArmor security contexts.
2. **WSL Default Mount Nuances:** On Windows Subsystem for Linux (WSL), files residing on the default Windows DrvFs mount (`/mnt/c/...`) inherit synthetic `0777` permissions unless the `metadata` mount option is enabled in `/etc/wsl.conf`.
3. **Network Filesystem Restrictions:** Files residing on NFS or CIFS shares may exhibit non-standard permission semantics governed by remote servers.

---

## 17. Future Scope

1. **POSIX ACL Integration:** Add support for extended attributes and access control lists (`libacl`).
2. **SELinux & AppArmor Auditing:** Inspect mandatory access control labels on security-hardened Linux distributions.
3. **Automated Remediation Script Generation:** Export a shell script containing verified `chmod` commands that the administrator can review and execute with a single command.
4. **JSON / CSV Output Support:** Enable integration into CI/CD pipelines (e.g. GitHub Actions) to fail builds if world-writable credentials are committed.

---

## 18. Conclusion

The **Linux File Permission Analyzer** successfully fulfills all design and functional requirements established for the 2026 Hackathon. Implemented in modular, warning-free C, the software provides an indispensable bridge between theoretical operating system concepts and real-world system security administration. By automating permission auditing and visualizing security risks through interactive dashboards, this project equips developers and administrators with the insights needed to enforce the principle of least privilege across Linux environments.

---

## 19. References

1. Kernighan, B. W., & Ritchie, D. M. (1988). *The C Programming Language* (2nd ed.). Prentice Hall.
2. Love, R. (2013). *Linux System Programming: Talking Directly to the Kernel and C Library* (2nd ed.). O'Reilly Media.
3. Stevens, W. R., & Rago, S. A. (2013). *Advanced Programming in the UNIX Environment* (3rd ed.). Addison-Wesley Professional.
4. IEEE and The Open Group. (2018). *The Open Group Base Specifications Issue 7 / IEEE Std 1003.1-2017 (POSIX.1)*.
5. Kerrisk, M. (2010). *The Linux Programming Interface: A Linux and UNIX System Programming Handbook*. No Starch Press.
