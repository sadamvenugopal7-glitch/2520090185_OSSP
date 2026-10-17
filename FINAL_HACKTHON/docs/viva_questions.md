# Viva & Oral Defense Preparation Guide

**Project Title:** Linux File Permission Analyzer  
**Hackathon Date:** 17 October 2026  
**Team Members:**  
1. Abhishek Yadav K — 2520090208  
2. S Venu Gopal — 2520090185  
3. R ROHIT — 2520080037  

---

## 25 Essential Viva Questions & Concise Answers

### Q1: What are Linux file permissions?
**Answer:** Linux file permissions are security attributes that control which users on the system can read (`r`), write (`w`), or execute (`x`) a file or directory. They enforce Discretionary Access Control (DAC).

---

### Q2: What do read, write, and execute mean for files vs directories?
**Answer:**
- **For files:**
  - `Read (r)`: View file contents.
  - `Write (w)`: Modify, overwrite, or truncate file contents.
  - `Execute (x)`: Run the file as a compiled program or script.
- **For directories:**
  - `Read (r)`: List the filenames inside the directory.
  - `Write (w)`: Create, delete, or rename files within the directory.
  - `Execute (x)`: Traverse or `cd` into the directory and access metadata of files inside.

---

### Q3: What is the difference between permission 644 and 755?
**Answer:**
- **`644` (`-rw-r--r--`):** The owner can read and write; group and others can only read. This is standard for documents, text files, and images.
- **`755` (`-rwxr-xr-x`):** The owner has full access (read, write, execute); group and others can read and execute (traverse). This is standard for directories and executable programs/scripts.

---

### Q4: What does permission 777 mean?
**Answer:** `777` (`-rwxrwxrwx`) grants full read, write, and execute permissions to **everyone** on the system (Owner, Group, and Others). Any local user or process can overwrite, truncate, or inject malicious code into the file.

---

### Q5: What are owner, group, and others in Linux?
**Answer:**
- **Owner (User, `u`):** The individual user account that created or owns the file.
- **Group (`g`):** A collection of users sharing collaborative access permissions.
- **Others (World, `o`):** Every other user account on the Linux system.

---

### Q6: What is an octal permission representation?
**Answer:** Octal is a base-8 numeric representation where each 3-bit permission triplet (`rwx`) is represented by a single digit from 0 to 7:
- `r = 4`
- `w = 2`
- `x = 1`
- Sum: `r + w = 6`, `r + x = 5`, `r + w + x = 7`.
- Example: Owner=7, Group=5, Others=5 yields octal `755`.

---

### Q7: What is the purpose of the `stat()` system call?
**Answer:** `stat()` is a POSIX system call that queries the Linux kernel for a file's inode metadata, returning information such as size, device ID, inode number, mode/permissions, owner UID, group GID, and timestamps.

---

### Q8: What is the purpose of the `lstat()` system call?
**Answer:** `lstat()` is identical to `stat()`, except when the target is a symbolic link. `lstat()` returns metadata about the **symbolic link itself**, rather than the target file it points to.

---

### Q9: What is the key difference between `stat()` and `lstat()`?
**Answer:** If passed a symbolic link, `stat()` dereferences the link and returns the target file's metadata, whereas `lstat()` returns the attributes of the symlink itself. Using `lstat()` prevents infinite recursion loops during directory scanning.

---

### Q10: What is a symbolic link?
**Answer:** A symbolic link (symlink) is a special pointer file containing the pathname string of another file or directory. On Linux, permissions on the symlink itself are ignored by the kernel; the permissions of the target file govern access.

---

### Q11: Why is recursive directory scanning needed in this project?
**Answer:** Real-world file trees contain multiple nested folders and subdirectories. Recursive scanning systematically navigates down through child directories to audit every file in the tree, ensuring no hidden insecure permissions escape detection.

---

### Q12: What is a world-writable file, and why is it dangerous?
**Answer:** A world-writable file has the `others` write bit enabled (`o+w` or `xx2`/`xx6`/`xx7`). It is dangerous because any unprivileged local user, rogue daemon, or compromised service can alter the file, corrupt data, or inject malicious instructions.

---

### Q13: Why is `chmod 777` generally discouraged in cybersecurity?
**Answer:** It completely violates the **Principle of Least Privilege**. Granting write and execute access to the world allows unauthorized tampering, privilege escalation, and unintended file deletion. Secure systems only grant the minimum permissions required for functionality.

---

### Q14: What is the purpose of GCC?
**Answer:** GCC (GNU Compiler Collection) is the standard open-source compiler used in Linux to translate C source code (`.c` files) into machine code executables.

---

### Q15: Why is this project implemented in C instead of Python or Java?
**Answer:**
1. C provides direct, native access to POSIX kernel system calls (`lstat`, `opendir`, `readdir`) without abstraction layers.
2. It compiles into a standalone native binary with zero runtime dependencies.
3. It demonstrates core Linux system programming and memory management principles essential for CSIT students.

---

### Q16: How does this application identify security risks?
**Answer:** The tool extracts the exact `mode_t` bitmask from the kernel via `lstat()`, checks special bits (SUID, SGID, Sticky), and evaluates them against 10 documented security rules (e.g. world-write, 777, exposed `.env` files, SUID binaries).

---

### Q17: How are findings classified into severity levels?
**Answer:**
- **HIGH:** Imminent risk of unauthorized modification, arbitrary code execution, or credential compromise (e.g. `777` files, world-writable files, exposed `.env`/`.key`).
- **MEDIUM:** Potential exposure or unreadable directories requiring review (e.g. readable config files, SUID binaries).
- **LOW:** Minor non-standard access (e.g. group-writable shared files).
- **INFORMATIONAL:** Standard secure configurations adhering to baseline least privilege (e.g. `644`, `755`, `600`, `700`, `/tmp` with sticky bit).

---

### Q18: Why is read-only analysis safer for security auditing?
**Answer:** Automatic permission modification can break operational services, lock out authorized daemons, or alter proprietary software configurations. Operating in read-only mode allows administrators to review findings and make deliberate, informed remediation decisions.

---

### Q19: How does the application handle inaccessible directories (Permission Denied)?
**Answer:** The program inspects return codes from `opendir()` and `lstat()`. When an error like `EACCES` occurs, it captures `strerror(errno)`, logs an `ERR-UNREAD` or `ERR-ACCESS` finding, increments counters, and gracefully continues scanning other directories without crashing.

---

### Q20: What are the project's current limitations?
**Answer:**
1. It inspects standard POSIX Discretionary Access Control (DAC) bits, but does not yet evaluate POSIX Access Control Lists (ACLs) or SELinux/AppArmor labels.
2. In WSL default mounts (`/mnt/c/...`), Windows mounts files with synthetic permissions unless the WSL `metadata` option is enabled.

---

### Q21: What is POSIX?
**Answer:** POSIX (Portable Operating System Interface) is an IEEE standard defining the API, shell, and utility interfaces for software compatibility across Unix-like operating systems (Linux, macOS, BSD).

---

### Q22: Why do we use a Makefile?
**Answer:** A `Makefile` automates the compilation process. It tracks source file dependencies, compiles only modified files, applies consistent compiler warning flags (`-Wall -Wextra -Wpedantic`), and simplifies testing with clean commands (`make`, `make run`, `make test`, `make clean`).

---

### Q23: What role does Git and GitHub play in this project?
**Answer:** Git provides distributed version control to track code changes and collaborate among team members. GitHub acts as the remote repository host for source code review, issue tracking, and project showcase.

---

### Q24: How does the tool prevent circular symlink loops?
**Answer:**
1. It uses `lstat()` instead of `stat()`, so symlinks are recognized as links rather than followed as folders.
2. It tracks visited device and inode pairs (`dev_t`, `ino_t`) to detect and abort circular directory loops.

---

### Q25: What is the future scope of this project?
**Answer:**
1. Support for POSIX ACLs (`getfacl`) and SELinux contexts.
2. Automated export of a reviewable remediation shell script (`fix_permissions.sh`).
3. Integration as a pre-commit hook or GitHub Actions CI/CD security scanner to prevent insecure file permissions from reaching production.
