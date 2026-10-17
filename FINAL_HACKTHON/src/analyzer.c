/**
 * ============================================================================
 * Project: Linux File Permission Analyzer
 * File:    analyzer.c
 * Authors: Abhishek Yadav K (2520090208) - Metadata & Permission Representation
 *          S Venu Gopal (2520090185)     - Security Rule Engine & Severity
 *          R ROHIT (2520080037)          - Testing & Formatting
 * Date:    17 October 2026
 *
 * Description:
 * Implements file metadata retrieval via POSIX system calls (lstat, realpath),
 * permission translation into symbolic and octal forms, and the core
 * security risk classification engine.
 * ============================================================================
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include "analyzer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>

/* ANSI Terminal Color Escape Codes */
#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_RED        "\033[31m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_BLUE       "\033[34m"
#define ANSI_MAGENTA    "\033[35m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_WHITE      "\033[37m"
#define ANSI_BG_RED     "\033[41m\033[37m"

/* Safe string copy helper preventing buffer overflow and compiler truncation warnings */
static void safe_copy(char *dest, const char *src, size_t dest_size) {
    if (!dest || dest_size == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    size_t i = 0;
    while (i + 1 < dest_size && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

void findings_list_init(FindingsList *list) {
    if (!list) return;
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

bool findings_list_add(FindingsList *list, const SecurityFinding *finding) {
    if (!list || !finding) return false;

    if (list->count >= list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 16 : list->capacity * 2;
        SecurityFinding *new_items = (SecurityFinding *)realloc(list->items, new_cap * sizeof(SecurityFinding));
        if (!new_items) {
            return false;
        }
        list->items = new_items;
        list->capacity = new_cap;
    }

    list->items[list->count] = *finding;
    list->count++;
    return true;
}

void findings_list_free(FindingsList *list) {
    if (!list) return;
    if (list->items) {
        free(list->items);
        list->items = NULL;
    }
    list->count = 0;
    list->capacity = 0;
}

const char* severity_to_string(SeverityLevel sev) {
    switch (sev) {
        case SEV_HIGH:   return "HIGH";
        case SEV_MEDIUM: return "MEDIUM";
        case SEV_LOW:    return "LOW";
        case SEV_INFO:   return "INFORMATIONAL";
        default:         return "UNKNOWN";
    }
}

const char* severity_to_color(SeverityLevel sev) {
    switch (sev) {
        case SEV_HIGH:   return ANSI_RED;
        case SEV_MEDIUM: return ANSI_YELLOW;
        case SEV_LOW:    return ANSI_CYAN;
        case SEV_INFO:   return ANSI_GREEN;
        default:         return ANSI_RESET;
    }
}

void format_file_size(off_t size, char *output, size_t max_len) {
    if (!output || max_len == 0) return;

    if (size < 1024) {
        snprintf(output, max_len, "%ld B", (long)size);
    } else if (size < 1024 * 1024) {
        snprintf(output, max_len, "%.1f KB", (double)size / 1024.0);
    } else if (size < 1024 * 1024 * 1024) {
        snprintf(output, max_len, "%.1f MB", (double)size / (1024.0 * 1024.0));
    } else {
        snprintf(output, max_len, "%.2f GB", (double)size / (1024.0 * 1024.0 * 1024.0));
    }
}

void mode_to_symbolic(mode_t mode, char *output, size_t size) {
    if (!output || size < 11) return;

    /* Index 0: File type */
    if (S_ISREG(mode))       output[0] = '-';
    else if (S_ISDIR(mode))  output[0] = 'd';
    else if (S_ISLNK(mode))  output[0] = 'l';
    else if (S_ISCHR(mode))  output[0] = 'c';
    else if (S_ISBLK(mode))  output[0] = 'b';
    else if (S_ISFIFO(mode)) output[0] = 'p';
    else if (S_ISSOCK(mode)) output[0] = 's';
    else                     output[0] = '?';

    /* User permissions */
    output[1] = (mode & S_IRUSR) ? 'r' : '-';
    output[2] = (mode & S_IWUSR) ? 'w' : '-';
    if (mode & S_ISUID) {
        output[3] = (mode & S_IXUSR) ? 's' : 'S';
    } else {
        output[3] = (mode & S_IXUSR) ? 'x' : '-';
    }

    /* Group permissions */
    output[4] = (mode & S_IRGRP) ? 'r' : '-';
    output[5] = (mode & S_IWGRP) ? 'w' : '-';
    if (mode & S_ISGID) {
        output[6] = (mode & S_IXGRP) ? 's' : 'S';
    } else {
        output[6] = (mode & S_IXGRP) ? 'x' : '-';
    }

    /* Others permissions */
    output[7] = (mode & S_IROTH) ? 'r' : '-';
    output[8] = (mode & S_IWOTH) ? 'w' : '-';
    if (mode & S_ISVTX) {
        output[9] = (mode & S_IXOTH) ? 't' : 'T';
    } else {
        output[9] = (mode & S_IXOTH) ? 'x' : '-';
    }

    output[10] = '\0';
}

int mode_to_octal(mode_t mode) {
    /* Standard Unix permission bits including special bits (SUID 4000, SGID 2000, Sticky 1000) */
    return (int)(mode & (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO));
}

static void extract_filename(const char *path, char *dest, size_t max_len) {
    if (!path || !dest || max_len == 0) return;
    const char *last_slash = strrchr(path, '/');
    if (last_slash) {
        if (*(last_slash + 1) != '\0') {
            safe_copy(dest, last_slash + 1, max_len);
        } else {
            /* Path ended with slash, e.g. "demo/" */
            char temp[MAX_PATH_LEN];
            safe_copy(temp, path, sizeof(temp));
            size_t len = strlen(temp);
            while (len > 1 && temp[len - 1] == '/') {
                temp[len - 1] = '\0';
                len--;
            }
            const char *prev_slash = strrchr(temp, '/');
            if (prev_slash) {
                safe_copy(dest, prev_slash + 1, max_len);
            } else {
                safe_copy(dest, temp, max_len);
            }
        }
    } else {
        safe_copy(dest, path, max_len);
    }
}

int analyze_path(const char *path, PermissionInfo *info) {
    if (!path || !info) return -1;
    memset(info, 0, sizeof(PermissionInfo));

    safe_copy(info->path, path, sizeof(info->path));
    extract_filename(path, info->filename, sizeof(info->filename));

    /* Use lstat to examine symbolic links without following them */
    if (lstat(path, &info->stat_buf) != 0) {
        return -1;
    }

    info->mode = info->stat_buf.st_mode;
    info->uid = info->stat_buf.st_uid;
    info->gid = info->stat_buf.st_gid;
    info->size = info->stat_buf.st_size;
    info->mtime = info->stat_buf.st_mtime;

    /* Canonical resolved path */
    if (realpath(path, info->resolved_path) == NULL) {
        /* If realpath fails (e.g. broken symlink or permissions), keep original */
        safe_copy(info->resolved_path, path, sizeof(info->resolved_path));
    }

    /* Convert symbolic notation */
    mode_to_symbolic(info->mode, info->symbolic_perm, sizeof(info->symbolic_perm));
    safe_copy(info->permission_bits_only, info->symbolic_perm + 1, sizeof(info->permission_bits_only));

    /* Octal notation */
    info->octal_perm = mode_to_octal(info->mode);

    /* Resolve user name */
    struct passwd *pw = getpwuid(info->uid);
    if (pw && pw->pw_name) {
        safe_copy(info->owner_name, pw->pw_name, sizeof(info->owner_name));
    } else {
        snprintf(info->owner_name, sizeof(info->owner_name), "%u", (unsigned int)info->uid);
    }

    /* Resolve group name */
    struct group *gr = getgrgid(info->gid);
    if (gr && gr->gr_name) {
        safe_copy(info->group_name, gr->gr_name, sizeof(info->group_name));
    } else {
        snprintf(info->group_name, sizeof(info->group_name), "%u", (unsigned int)info->gid);
    }

    /* Format size */
    format_file_size(info->size, info->human_size, sizeof(info->human_size));

    /* Format modification time */
    struct tm tm_buf;
    if (localtime_r(&info->mtime, &tm_buf) != NULL) {
        strftime(info->mtime_str, sizeof(info->mtime_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
    } else {
        safe_copy(info->mtime_str, "Unknown", sizeof(info->mtime_str));
    }

    /* Categorize File Type */
    if (S_ISREG(info->mode)) {
        info->file_type = FT_REGULAR;
        info->file_type_str = "Regular File";
        info->is_symlink = false;
    } else if (S_ISDIR(info->mode)) {
        info->file_type = FT_DIRECTORY;
        info->file_type_str = "Directory";
        info->is_symlink = false;
    } else if (S_ISLNK(info->mode)) {
        info->file_type = FT_SYMLINK;
        info->file_type_str = "Symbolic Link";
        info->is_symlink = true;

        /* Read symlink target safely */
        ssize_t len = readlink(path, info->symlink_target, sizeof(info->symlink_target) - 1);
        if (len != -1) {
            info->symlink_target[len] = '\0';
        } else {
            safe_copy(info->symlink_target, "[unreadable target]", sizeof(info->symlink_target));
        }
    } else if (S_ISCHR(info->mode)) {
        info->file_type = FT_CHAR_DEV;
        info->file_type_str = "Character Device";
        info->is_symlink = false;
    } else if (S_ISBLK(info->mode)) {
        info->file_type = FT_BLOCK_DEV;
        info->file_type_str = "Block Device";
        info->is_symlink = false;
    } else if (S_ISFIFO(info->mode)) {
        info->file_type = FT_FIFO;
        info->file_type_str = "FIFO / Named Pipe";
        info->is_symlink = false;
    } else if (S_ISSOCK(info->mode)) {
        info->file_type = FT_SOCKET;
        info->file_type_str = "Socket";
        info->is_symlink = false;
    } else {
        info->file_type = FT_UNKNOWN;
        info->file_type_str = "Unknown Special File";
        info->is_symlink = false;
    }

    return 0;
}

/* Helper to check filename patterns for sensitive data */
static bool is_sensitive_filename(const char *filename) {
    if (!filename) return false;

    const char *sensitive_exact[] = {
        ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        ".bash_history", ".zsh_history", ".mysql_history",
        "shadow", "gshadow", "master.passwd", "htpasswd",
        ".netrc", ".pgpass", "wp-config.php", NULL
    };

    for (int i = 0; sensitive_exact[i] != NULL; i++) {
        if (strcmp(filename, sensitive_exact[i]) == 0) {
            return true;
        }
    }

    /* Check file extensions */
    const char *ext = strrchr(filename, '.');
    if (ext) {
        if (strcmp(ext, ".key") == 0 ||
            strcmp(ext, ".pem") == 0 ||
            strcmp(ext, ".pfx") == 0 ||
            strcmp(ext, ".p12") == 0 ||
            strcmp(ext, ".kdbx") == 0) {
            return true;
        }
    }

    return false;
}

/* Helper to check if directory name suggests sensitive storage */
static bool is_sensitive_directory(const char *filename) {
    if (!filename) return false;
    if (strcmp(filename, ".ssh") == 0 ||
        strcmp(filename, ".gnupg") == 0 ||
        strcmp(filename, ".aws") == 0 ||
        strcmp(filename, ".docker") == 0) {
        return true;
    }
    return false;
}

void evaluate_security_rules(const PermissionInfo *info, FindingsList *findings) {
    if (!info || !findings) return;

    mode_t mode = info->mode;
    int base_octal = (int)(mode & 0777);
    int full_octal = info->octal_perm;
    bool flagged = false;

    /* Symbolic links do not enforce permissions directly on Linux (target does) */
    if (info->is_symlink) {
        SecurityFinding f;
        memset(&f, 0, sizeof(f));
        safe_copy(f.path, info->path, sizeof(f.path));
        safe_copy(f.filename, info->filename, sizeof(f.filename));
        f.octal_perm = full_octal;
        safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
        f.severity = SEV_INFO;
        safe_copy(f.rule_id, "RULE-00", sizeof(f.rule_id));
        safe_copy(f.title, "Symbolic Link Encountered", sizeof(f.title));
        snprintf(f.explanation, sizeof(f.explanation),
                 "Symbolic links inherit permissions of their target file on Linux. Target is '%.250s'.",
                 info->symlink_target);
        snprintf(f.recommendation, sizeof(f.recommendation),
                 "Verify that the link destination points to a secure and expected path.");
        safe_copy(f.suggested_chmod, "N/A (Manage target file permissions)", sizeof(f.suggested_chmod));
        findings_list_add(findings, &f);
        return;
    }

    /* RULE-02 & RULE-01: Full 777 or World-Writable Regular File */
    if (S_ISREG(mode)) {
        if (base_octal == 0777) {
            SecurityFinding f;
            memset(&f, 0, sizeof(f));
            safe_copy(f.path, info->path, sizeof(f.path));
            safe_copy(f.filename, info->filename, sizeof(f.filename));
            f.octal_perm = full_octal;
            safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
            f.severity = SEV_HIGH;
            safe_copy(f.rule_id, "RULE-02", sizeof(f.rule_id));
            safe_copy(f.title, "Unrestricted Permissions (777)", sizeof(f.title));
            snprintf(f.explanation, sizeof(f.explanation),
                     "The file grants full Read, Write, and Execute access to Owner, Group, and Everyone (world). "
                     "Any local user can overwrite, truncate, or inject malicious content.");
            snprintf(f.recommendation, sizeof(f.recommendation),
                     "Restrict access to the owner and necessary group. Regular files rarely need 777.");
            snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod 644 \"%s\"", info->path);
            findings_list_add(findings, &f);
            flagged = true;
        } else if (mode & S_IWOTH) {
            SecurityFinding f;
            memset(&f, 0, sizeof(f));
            safe_copy(f.path, info->path, sizeof(f.path));
            safe_copy(f.filename, info->filename, sizeof(f.filename));
            f.octal_perm = full_octal;
            safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
            f.severity = SEV_HIGH;
            safe_copy(f.rule_id, "RULE-01", sizeof(f.rule_id));
            safe_copy(f.title, "World-Writable Regular File", sizeof(f.title));
            snprintf(f.explanation, sizeof(f.explanation),
                     "The file is writable by any unprivileged user on the operating system ('others' write bit is active). "
                     "This enables unauthorized data tampering or code injection.");
            snprintf(f.recommendation, sizeof(f.recommendation),
                     "Remove write permissions for others (o-w) unless this file is an explicitly shared public resource.");
            snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod 644 \"%s\"", info->path);
            findings_list_add(findings, &f);
            flagged = true;
        }
    }

    /* RULE-03 & RULE-06: World-Writable Directory & Sticky Bit Analysis */
    if (S_ISDIR(mode)) {
        if (mode & S_IWOTH) {
            if (!(mode & S_ISVTX)) {
                SecurityFinding f;
                memset(&f, 0, sizeof(f));
                safe_copy(f.path, info->path, sizeof(f.path));
                safe_copy(f.filename, info->filename, sizeof(f.filename));
                f.octal_perm = full_octal;
                safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
                f.severity = SEV_HIGH;
                safe_copy(f.rule_id, "RULE-03", sizeof(f.rule_id));
                safe_copy(f.title, "World-Writable Directory Without Sticky Bit", sizeof(f.title));
                snprintf(f.explanation, sizeof(f.explanation),
                         "Directory is world-writable and lacks the sticky bit (+t). "
                         "Any user can rename, delete, or replace files owned by other users inside this folder.");
                snprintf(f.recommendation, sizeof(f.recommendation),
                         "Revoke world write permissions or add the sticky bit (chmod +t) if intended as a shared temporary directory.");
                snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod 755 \"%s\" (or chmod +t)", info->path);
                findings_list_add(findings, &f);
                flagged = true;
            } else {
                SecurityFinding f;
                memset(&f, 0, sizeof(f));
                safe_copy(f.path, info->path, sizeof(f.path));
                safe_copy(f.filename, info->filename, sizeof(f.filename));
                f.octal_perm = full_octal;
                safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
                f.severity = SEV_INFO;
                safe_copy(f.rule_id, "RULE-06", sizeof(f.rule_id));
                safe_copy(f.title, "World-Writable Directory With Sticky Bit", sizeof(f.title));
                snprintf(f.explanation, sizeof(f.explanation),
                         "Directory is world-writable, but protected by the sticky bit (e.g. 1777 like /tmp). "
                         "Users can create files, but only the file owner or root can delete them.");
                snprintf(f.recommendation, sizeof(f.recommendation),
                         "Verify if public world-write access is necessary for this directory.");
                safe_copy(f.suggested_chmod, "Review access requirements (1777 is typical for /tmp)", sizeof(f.suggested_chmod));
                findings_list_add(findings, &f);
                flagged = true;
            }
        }
    }

    /* RULE-04: Sensitive Credentials / Configs with Broad Permissions */
    if (S_ISREG(mode) && is_sensitive_filename(info->filename)) {
        if ((mode & S_IROTH) || (mode & S_IWOTH) || (mode & S_IRGRP) || (mode & S_IWGRP)) {
            SecurityFinding f;
            memset(&f, 0, sizeof(f));
            safe_copy(f.path, info->path, sizeof(f.path));
            safe_copy(f.filename, info->filename, sizeof(f.filename));
            f.octal_perm = full_octal;
            safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
            f.severity = (mode & (S_IROTH | S_IWOTH)) ? SEV_HIGH : SEV_MEDIUM;
            safe_copy(f.rule_id, "RULE-04", sizeof(f.rule_id));
            safe_copy(f.title, "Sensitive Configuration / Key Exposing Access", sizeof(f.title));
            snprintf(f.explanation, sizeof(f.explanation),
                     "Filename '%s' indicates sensitive credentials, private keys, or system configuration. "
                     "Current permissions permit access by group or world users.",
                     info->filename);
            snprintf(f.recommendation, sizeof(f.recommendation),
                     "Restrict access exclusively to the owner (read/write only) to safeguard secrets.");
            snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod 600 \"%s\"", info->path);
            findings_list_add(findings, &f);
            flagged = true;
        }
    }

    /* RULE-05: SUID and SGID Special Bit Analysis */
    if (mode & S_ISUID) {
        SecurityFinding f;
        memset(&f, 0, sizeof(f));
        safe_copy(f.path, info->path, sizeof(f.path));
        safe_copy(f.filename, info->filename, sizeof(f.filename));
        f.octal_perm = full_octal;
        safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
        f.severity = (mode & (S_IWOTH | S_IWGRP)) ? SEV_HIGH : SEV_MEDIUM;
        safe_copy(f.rule_id, "RULE-05A", sizeof(f.rule_id));
        safe_copy(f.title, "Setuid (SUID) Bit Active", sizeof(f.title));
        snprintf(f.explanation, sizeof(f.explanation),
                 "The SUID bit allows this executable to execute with the permissions of the file owner (often root). "
                 "If vulnerable or writable, it can lead to local privilege escalation.");
        snprintf(f.recommendation, sizeof(f.recommendation),
                 "Audit this binary. Ensure it is not world/group writable and has no known CVEs. Remove SUID if unneeded.");
        snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod u-s \"%s\"", info->path);
        findings_list_add(findings, &f);
        flagged = true;
    }

    if (mode & S_ISGID) {
        if (!S_ISDIR(mode)) {
            SecurityFinding f;
            memset(&f, 0, sizeof(f));
            safe_copy(f.path, info->path, sizeof(f.path));
            safe_copy(f.filename, info->filename, sizeof(f.filename));
            f.octal_perm = full_octal;
            safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
            f.severity = (mode & S_IWOTH) ? SEV_HIGH : SEV_LOW;
            safe_copy(f.rule_id, "RULE-05B", sizeof(f.rule_id));
            safe_copy(f.title, "Setgid (SGID) Bit Active on Binary", sizeof(f.title));
            snprintf(f.explanation, sizeof(f.explanation),
                     "The binary runs with effective group privileges of group '%s'.",
                     info->group_name);
            snprintf(f.recommendation, sizeof(f.recommendation),
                     "Verify if group privilege elevation is required for this program.");
            snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod g-s \"%s\"", info->path);
            findings_list_add(findings, &f);
            flagged = true;
        }
    }

    /* RULE-07: Group-Writable File (without world-write) */
    if (S_ISREG(mode) && (mode & S_IWGRP) && !(mode & S_IWOTH) && base_octal != 0777) {
        SecurityFinding f;
        memset(&f, 0, sizeof(f));
        safe_copy(f.path, info->path, sizeof(f.path));
        safe_copy(f.filename, info->filename, sizeof(f.filename));
        f.octal_perm = full_octal;
        safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
        f.severity = (info->uid == 0) ? SEV_MEDIUM : SEV_LOW;
        safe_copy(f.rule_id, "RULE-07", sizeof(f.rule_id));
        safe_copy(f.title, "Group-Writable File", sizeof(f.title));
        snprintf(f.explanation, sizeof(f.explanation),
                 "File is writable by members of group '%s'. In shared multi-user environments, "
                 "untrusted group members can alter the file.",
                 info->group_name);
        snprintf(f.recommendation, sizeof(f.recommendation),
                 "Ensure only authorized accounts belong to group '%s', or revoke group write access.",
                 info->group_name);
        snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod g-w \"%s\"", info->path);
        findings_list_add(findings, &f);
        flagged = true;
    }

    /* RULE-08: Executable File with World-Write */
    if (S_ISREG(mode) && (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) && (mode & S_IWOTH) && base_octal != 0777) {
        SecurityFinding f;
        memset(&f, 0, sizeof(f));
        safe_copy(f.path, info->path, sizeof(f.path));
        safe_copy(f.filename, info->filename, sizeof(f.filename));
        f.octal_perm = full_octal;
        safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
        f.severity = SEV_HIGH;
        safe_copy(f.rule_id, "RULE-08", sizeof(f.rule_id));
        safe_copy(f.title, "World-Writable Executable", sizeof(f.title));
        snprintf(f.explanation, sizeof(f.explanation),
                 "This program or script is executable and world-writable. An attacker could rewrite its contents "
                 "to execute arbitrary commands when another user or root runs it.");
        snprintf(f.recommendation, sizeof(f.recommendation),
                 "Immediately remove world-write permissions from the executable.");
        snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod 755 \"%s\"", info->path);
        findings_list_add(findings, &f);
        flagged = true;
    }

    /* RULE-09: Sensitive Directory with World or Group Access */
    if (S_ISDIR(mode) && is_sensitive_directory(info->filename)) {
        if ((mode & (S_IROTH | S_IWOTH | S_IXOTH)) || (mode & (S_IRGRP | S_IWGRP | S_IXGRP))) {
            SecurityFinding f;
            memset(&f, 0, sizeof(f));
            safe_copy(f.path, info->path, sizeof(f.path));
            safe_copy(f.filename, info->filename, sizeof(f.filename));
            f.octal_perm = full_octal;
            safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
            f.severity = (mode & (S_IROTH | S_IWOTH | S_IXOTH)) ? SEV_HIGH : SEV_MEDIUM;
            safe_copy(f.rule_id, "RULE-09", sizeof(f.rule_id));
            safe_copy(f.title, "Sensitive Directory Exposed to Others", sizeof(f.title));
            snprintf(f.explanation, sizeof(f.explanation),
                     "Directory '%s' often stores private keys or credentials, but permits access by group or world users.",
                     info->filename);
            snprintf(f.recommendation, sizeof(f.recommendation),
                     "Restrict directory access strictly to the owner (rwx------).");
            snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod 700 \"%s\"", info->path);
            findings_list_add(findings, &f);
            flagged = true;
        }
    }

    /* RULE-10: Standard Compliant Permissions Baseline (Informational) */
    if (!flagged) {
        SecurityFinding f;
        memset(&f, 0, sizeof(f));
        safe_copy(f.path, info->path, sizeof(f.path));
        safe_copy(f.filename, info->filename, sizeof(f.filename));
        f.octal_perm = full_octal;
        safe_copy(f.symbolic_perm, info->symbolic_perm, sizeof(f.symbolic_perm));
        f.severity = SEV_INFO;
        safe_copy(f.rule_id, "RULE-10", sizeof(f.rule_id));
        safe_copy(f.title, "Standard Permissions Baseline", sizeof(f.title));

        if (base_octal == 0644) {
            snprintf(f.explanation, sizeof(f.explanation),
                     "Standard Unix permission: Owner read/write, Group read-only, Others read-only. Adheres to least privilege.");
        } else if (base_octal == 0755) {
            snprintf(f.explanation, sizeof(f.explanation),
                     "Standard Unix permission for directories and binaries: Owner full control, others read/execute.");
        } else if (base_octal == 0600) {
            snprintf(f.explanation, sizeof(f.explanation),
                     "Strict private permission: Only the owner has read/write access. Group and Others have zero access.");
        } else if (base_octal == 0700) {
            snprintf(f.explanation, sizeof(f.explanation),
                     "Strict private directory/executable permission: Only the owner can access or traverse.");
        } else {
            snprintf(f.explanation, sizeof(f.explanation),
                     "Permissions do not violate high-risk rules. Current configuration is within standard operational parameters.");
        }

        snprintf(f.recommendation, sizeof(f.recommendation),
                 "No corrective action required. Maintain current permission configuration.");
        safe_copy(f.suggested_chmod, "None (Compliant)", sizeof(f.suggested_chmod));
        findings_list_add(findings, &f);
    }
}

void print_single_finding(const SecurityFinding *finding, size_t index) {
    if (!finding) return;

    const char *color = severity_to_color(finding->severity);
    const char *sev_str = severity_to_string(finding->severity);

    printf("\n  " ANSI_BOLD "[Finding #%zu]" ANSI_RESET " %s[%s]%s %s%s%s\n",
           index + 1, color, sev_str, ANSI_RESET, ANSI_BOLD, finding->title, ANSI_RESET);
    printf("  Rule ID:         %s\n", finding->rule_id);
    printf("  Target:          %s\n", finding->path);
    printf("  Permissions:     %s (Octal: %03o)\n", finding->symbolic_perm, finding->octal_perm);
    printf("  Explanation:     %s\n", finding->explanation);
    printf("  Recommendation:  %s\n", finding->recommendation);
    if (strcmp(finding->suggested_chmod, "None (Compliant)") != 0 &&
        strcmp(finding->suggested_chmod, "N/A (Manage target file permissions)") != 0 &&
        strncmp(finding->suggested_chmod, "Review", 6) != 0) {
        printf("  Suggested Cmd:   " ANSI_CYAN "%s" ANSI_RESET "\n", finding->suggested_chmod);
    }
}

void print_file_analysis(const PermissionInfo *info, const FindingsList *findings) {
    if (!info) return;

    printf("\n=======================================================\n");
    printf("              FILE PERMISSION ANALYSIS\n");
    printf("=======================================================\n");
    printf("File Name:         " ANSI_BOLD "%s" ANSI_RESET "\n", info->filename);
    printf("Input Path:        %s\n", info->path);
    printf("Resolved Path:     %s\n", info->resolved_path);
    printf("File Type:         %s\n", info->file_type_str);
    if (info->is_symlink) {
        printf("Symlink Target:    %s\n", info->symlink_target);
    }
    printf("Permissions:       " ANSI_BOLD "%s" ANSI_RESET " (Bits: %s)\n",
           info->symbolic_perm, info->permission_bits_only);
    printf("Octal Notation:    " ANSI_BOLD "%03o" ANSI_RESET " (Full: %04o)\n",
           (info->octal_perm & 0777), info->octal_perm);
    printf("Owner:             %s (UID: %u)\n", info->owner_name, (unsigned int)info->uid);
    printf("Group:             %s (GID: %u)\n", info->group_name, (unsigned int)info->gid);
    printf("File Size:         %s (%ld bytes)\n", info->human_size, (long)info->size);
    printf("Last Modified:     %s\n", info->mtime_str);
    printf("-------------------------------------------------------\n");
    printf("SECURITY FINDINGS AND RECOMMENDATIONS:\n");

    if (!findings || findings->count == 0) {
        printf("  No security issues identified.\n");
    } else {
        for (size_t i = 0; i < findings->count; i++) {
            print_single_finding(&findings->items[i], i);
        }
    }
    printf("=======================================================\n\n");
}

void print_scan_summary(const ScanStats *stats) {
    if (!stats) return;

    printf("\n========== SCAN SUMMARY ==========\n\n");
    printf("Files scanned:         %zu\n", stats->total_files);
    printf("Directories scanned:   %zu\n", stats->total_dirs);
    if (stats->total_symlinks > 0) {
        printf("Symbolic links:        %zu\n", stats->total_symlinks);
    }
    printf("High findings:         " ANSI_RED "%zu" ANSI_RESET "\n", stats->high_findings);
    printf("Medium findings:       " ANSI_YELLOW "%zu" ANSI_RESET "\n", stats->medium_findings);
    printf("Low findings:          " ANSI_CYAN "%zu" ANSI_RESET "\n", stats->low_findings);
    printf("Informational findings:" ANSI_GREEN " %zu" ANSI_RESET "\n", stats->info_findings);
    printf("==================================\n\n");
}
