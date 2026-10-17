# Test Cases & Validation Log

**Project Title:** Linux File Permission Analyzer  
**Hackathon Date:** 17 October 2026  
**Team Members:**  
1. Abhishek Yadav K — 2520090208  
2. S Venu Gopal — 2520090185  
3. R ROHIT — 2520080037  

---

## 1. Overview

This document provides complete, verifiable documentation for the **12 mandatory test cases** executed against the `permission_analyzer` application. All tests were executed in an isolated temporary test sandbox on Ubuntu Linux (under WSL2) using real POSIX filesystem metadata.

---

## 2. Test Execution Matrix

| Test ID | Test Scenario | Input Path | Current Mode | Expected Behavior | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Regular file with permission 644 | `file_644.txt` | `0644` (`-rw-r--r--`) | Identified as compliant baseline | Reported `RULE-10` Informational; no risk | **PASS** |
| **TC-02** | Private file with permission 600 | `file_600.key` | `0600` (`-rw-------`) | Identified as strict owner-only | Reported `RULE-10` Informational; least-privilege compliant | **PASS** |
| **TC-03** | Executable script with 755 | `run_755.sh` | `0755` (`-rwxr-xr-x`) | Recognized as compliant binary/script | Reported `RULE-10` Informational; standard binary permissions | **PASS** |
| **TC-04** | File with 777 permissions | `danger_777.txt` | `0777` (`-rwxrwxrwx`) | Flagged as HIGH security risk | Reported `RULE-02` (HIGH); suggested `chmod 644` | **PASS** |
| **TC-05** | World-writable directory (no sticky bit) | `shared_world_dir/` | `0777` (`drwxrwxrwx`) | Flagged as HIGH vulnerability | Reported `RULE-03` (HIGH); suggested `chmod 755` or `+t` | **PASS** |
| **TC-06** | Directory with permission 700 | `private_dir/` | `0700` (`drwx------`) | Identified as secure private directory | Reported `RULE-10` Informational baseline | **PASS** |
| **TC-07** | Symbolic link to target | `symlink_to_file` | `0777` (`lrwxrwxrwx`) | Inspected via `lstat()`; link preserved | Reported `RULE-00` Informational; showed target path | **PASS** |
| **TC-08** | Non-existent / missing file | `nonexistent_file_xyz.txt` | N/A | Graceful error without crash | Output: `Cannot inspect: No such file or directory` | **PASS** |
| **TC-09** | Empty directory | `empty_dir/` | `0755` (`drwxr-xr-x`) | Successful traversal; 0 children | Scanned 0 files, 1 dir; no errors | **PASS** |
| **TC-10** | Nested subdirectories (multi-level) | `nested_root/` | Mixed (`644`, `777`, `755`) | Recursively traversed all depths | Scanned 3 files, 3 dirs; flagged nested `777` | **PASS** |
| **TC-11** | Inaccessible directory (`0000`) | `inaccessible_dir/` | `0000` (`d---------`) | Caught `EACCES` gracefully | Reported `ERR-ACCESS` / `ERR-UNREAD` Medium finding; no crash | **PASS** |
| **TC-12** | Invalid CLI arguments | `--invalid-flag-12345` | N/A | Displayed helpful error and usage | Returned exit code 1 with usage instruction | **PASS** |

---

## 3. Detailed Test Case Specifications

### Test Case 1: Standard File (644)
- **Setup Command:** `touch file_644.txt && chmod 644 file_644.txt`
- **Execution:** `./bin/permission_analyzer -f file_644.txt`
- **Expected Behavior:** Application reads mode `0644`, displays `-rw-r--r--`, classifies as `RULE-10` (Standard Permissions Baseline, Informational).
- **Observed Behavior:** Correctly identified as standard Unix permission adhering to least privilege. No corrective chmod suggested.

### Test Case 2: Strict Owner File (600)
- **Setup Command:** `touch file_600.key && chmod 600 file_600.key`
- **Execution:** `./bin/permission_analyzer -f file_600.key`
- **Expected Behavior:** Mode `0600` recognized with zero group and world permissions (`-rw-------`).
- **Observed Behavior:** Identified as secure private file configuration.

### Test Case 3: Executable Binary/Script (755)
- **Setup Command:** `touch run_755.sh && chmod 755 run_755.sh`
- **Execution:** `./bin/permission_analyzer -f run_755.sh`
- **Expected Behavior:** Mode `0755` recognized (`-rwxr-xr-x`), owner has write/exec, others have read/exec only.
- **Observed Behavior:** Reported standard baseline for executable files.

### Test Case 4: High-Risk World-Writable File (777)
- **Setup Command:** `touch danger_777.txt && chmod 777 danger_777.txt`
- **Execution:** `./bin/permission_analyzer -f danger_777.txt`
- **Expected Behavior:** Mode `0777` flagged as `HIGH` severity (`RULE-02`). Suggested command: `chmod 644 danger_777.txt`.
- **Observed Behavior:** Flagged immediately with high severity alert, clear explanation of unauthorized modification risk, and precise corrective chmod command.

### Test Case 5: World-Writable Directory Without Sticky Bit
- **Setup Command:** `mkdir shared_world_dir && chmod 777 shared_world_dir`
- **Execution:** `./bin/permission_analyzer -d shared_world_dir`
- **Expected Behavior:** Mode `0777` without `S_ISVTX` flagged as `HIGH` severity (`RULE-03`).
- **Observed Behavior:** Flagged with explanation that arbitrary users can delete or rename other users' files without sticky bit protection. Suggested `chmod 755` or `chmod +t`.

### Test Case 6: Private Directory (700)
- **Setup Command:** `mkdir private_dir && chmod 700 private_dir`
- **Execution:** `./bin/permission_analyzer -d private_dir`
- **Expected Behavior:** Mode `0700` (`drwx------`) recognized as secure owner-only folder.
- **Observed Behavior:** Correctly classified as secure baseline.

### Test Case 7: Symbolic Link Handling
- **Setup Command:** `ln -s file_644.txt symlink_to_file`
- **Execution:** `./bin/permission_analyzer -f symlink_to_file`
- **Expected Behavior:** Tool uses `lstat()` to inspect link without following it into infinite loops.
- **Observed Behavior:** Entry recognized as `Symbolic Link (l)`, resolved target displayed as `file_644.txt`, noted that target governs actual access.

### Test Case 8: Missing File Handling
- **Setup Command:** Ensure `nonexistent_file_xyz.txt` does not exist.
- **Execution:** `./bin/permission_analyzer -f nonexistent_file_xyz.txt`
- **Expected Behavior:** Error message returned cleanly without crashing or segmentation fault.
- **Observed Behavior:** Graceful message: `Error: Cannot inspect '...': No such file or directory`. Exit code handled properly.

### Test Case 9: Empty Directory Handling
- **Setup Command:** `mkdir empty_dir`
- **Execution:** `./bin/permission_analyzer -d empty_dir`
- **Expected Behavior:** Successfully scans directory without error, reports 0 contained files.
- **Observed Behavior:** Traversed cleanly with 0 files, 1 directory recorded.

### Test Case 10: Multi-Level Nested Directory Scanning
- **Setup Command:** `mkdir -p nested_root/sub1/sub2 && touch nested_root/root_f.txt nested_root/sub1/sub1_f.txt nested_root/sub1/sub2/sub2_f.txt && chmod 777 nested_root/sub1/sub2/sub2_f.txt`
- **Execution:** `./bin/permission_analyzer -r nested_root`
- **Expected Behavior:** Recurses through `nested_root`, `sub1`, and `sub2`, detecting all 3 files and 3 directories, flagging the deeply nested `777` file.
- **Observed Behavior:** Recursive traversal captured all levels accurately; total counts: 3 files, 3 directories; correctly flagged `sub2_f.txt` with `RULE-02` HIGH finding.

### Test Case 11: Inaccessible Directory (Permission Denied)
- **Setup Command:** `mkdir inaccessible_dir && chmod 000 inaccessible_dir`
- **Execution:** `./bin/permission_analyzer -r inaccessible_dir`
- **Expected Behavior:** Tool catches `EACCES` or permission error, logs finding `ERR-ACCESS` or `ERR-UNREAD`, continues without aborting.
- **Observed Behavior:** Logged as MEDIUM severity finding: `Cannot Inspect Directory Metadata: Permission denied`. Application completed cleanly without crash.

### Test Case 12: Invalid User Input / Unknown Options
- **Execution:** `./bin/permission_analyzer --invalid-flag-12345`
- **Expected Behavior:** Graceful error message directing user to `--help` or interactive menu.
- **Observed Behavior:** Output: `Unknown option: --invalid-flag-12345. Use -h for help.` Exit code 1.

---

## 4. Verification Conclusion

All 12 automated test cases passed with 100% success rate on GCC 15.2 / Ubuntu Linux. The application demonstrated robust memory handling, zero memory leaks during traversals, zero compiler warnings under `-Wall -Wextra -Wpedantic`, and complete adherence to read-only security safety requirements.
