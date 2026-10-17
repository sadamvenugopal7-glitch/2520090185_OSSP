# Linux File Permission Analyzer - Demonstration Directory

This directory contains pre-configured test files for the 3-5 minute live Hackathon demonstration.

## Demo Files Overview

| Filename | Intended Permission | Description | Security Expectation |
| :--- | :--- | :--- | :--- |
| `normal.txt` | `644` (`-rw-r--r--`) | Standard public documentation | Compliant baseline (`RULE-10`) |
| `private.txt` | `600` (`-rw-------`) | Private administrator notes | Compliant private file (`RULE-10`) |
| `risky.txt` | `777` (`-rwxrwxrwx`) | Insecure world-writable file | **HIGH** risk finding (`RULE-02`) |
| `script.sh` | `755` (`-rwxr-xr-x`) | Executable deployment script | Compliant executable baseline |
| `.env` | `644` (`-rw-r--r--`) | Sensitive environment credentials | **HIGH** risk: exposed secret (`RULE-04`) |
| `nested/subfile.txt` | `644` (`-rw-r--r--`) | Nested file in subdirectory | Demonstrates recursive traversal |

## Quick Setup Command for Live Demo

On Ubuntu Linux or WSL:

```bash
# Set intended demo permissions
chmod 644 demo_files/normal.txt
chmod 600 demo_files/private.txt
chmod 777 demo_files/risky.txt
chmod 755 demo_files/script.sh
chmod 644 demo_files/.env
chmod 644 demo_files/nested/subfile.txt
```

> **Note on Windows WSL:**
> If running directly on a Windows mount (`/mnt/c/...`) without WSL metadata automount enabled, run the demonstration in `/tmp/demo_files` using the provided test scripts or ensure WSL metadata is enabled.
