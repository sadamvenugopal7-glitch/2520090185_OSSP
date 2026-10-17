/**
 * ============================================================================
 * Project: Linux File Permission Analyzer
 * File:    analyzer.h
 * Authors: Abhishek Yadav K (2520090208)
 *          S Venu Gopal (2520090185)
 *          R ROHIT (2520080037)
 * Date:    17 October 2026
 *
 * Description:
 * Header file for the File Permission Analysis Engine. Defines core data
 * structures, permission representations, severity classifications, and
 * security rule definitions.
 * ============================================================================
 */

#ifndef ANALYZER_H
#define ANALYZER_H

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_PATH_LEN      4096
#define MAX_NAME_LEN      256
#define MAX_DESC_LEN      512
#define MAX_CMD_LEN       (MAX_PATH_LEN + 64)

/* Security Severity Levels */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW = 1,
    SEV_MEDIUM = 2,
    SEV_HIGH = 3
} SeverityLevel;

/* File Types Recognized by POSIX */
typedef enum {
    FT_REGULAR,
    FT_DIRECTORY,
    FT_SYMLINK,
    FT_CHAR_DEV,
    FT_BLOCK_DEV,
    FT_FIFO,
    FT_SOCKET,
    FT_UNKNOWN
} FileType;

/* Detailed Metadata & Permission Information for a Single Entry */
typedef struct {
    char path[MAX_PATH_LEN];               /* Path provided by user or scanner */
    char resolved_path[MAX_PATH_LEN];      /* Canonical absolute path */
    char filename[MAX_NAME_LEN];           /* Base filename */
    struct stat stat_buf;                  /* Raw POSIX stat structure */
    mode_t mode;                           /* Raw permission mode bits */
    char symbolic_perm[12];                /* Full symbolic mode (e.g. -rwxr-xr-x) */
    char permission_bits_only[10];         /* Permission part only (e.g. rwxr-xr-x) */
    int octal_perm;                        /* Standard 3 or 4-digit octal (e.g. 755) */
    uid_t uid;                             /* User ID of owner */
    gid_t gid;                             /* Group ID */
    char owner_name[64];                   /* Resolved owner username */
    char group_name[64];                   /* Resolved group name */
    off_t size;                            /* Size in bytes */
    char human_size[32];                   /* Human-readable size (e.g. "4.2 KB") */
    time_t mtime;                          /* Last modification time */
    char mtime_str[64];                    /* Formatted timestamp */
    FileType file_type;                    /* Categorized file type */
    const char *file_type_str;             /* Human-readable file type string */
    bool is_symlink;                       /* True if entry is a symbolic link */
    char symlink_target[MAX_PATH_LEN];     /* Target pointed by symlink if any */
} PermissionInfo;

/* Security Finding identified by Rule Engine */
typedef struct {
    char path[MAX_PATH_LEN];               /* Target file path */
    char filename[MAX_NAME_LEN];           /* Target file name */
    int octal_perm;                        /* Current octal permission */
    char symbolic_perm[12];                /* Current symbolic permission */
    SeverityLevel severity;                /* HIGH, MEDIUM, LOW, INFORMATIONAL */
    char rule_id[16];                      /* Rule identifier, e.g. "RULE-01" */
    char title[128];                       /* Short summary of finding */
    char explanation[MAX_DESC_LEN];        /* Why this is risky or noteworthy */
    char recommendation[MAX_DESC_LEN];     /* Recommended action */
    char suggested_chmod[MAX_CMD_LEN];     /* Specific command suggestion */
} SecurityFinding;

/* List of Security Findings (Dynamic Array) */
typedef struct {
    SecurityFinding *items;
    size_t count;
    size_t capacity;
} FindingsList;

/* Scan Statistics Summary */
typedef struct {
    size_t total_files;
    size_t total_dirs;
    size_t total_symlinks;
    size_t total_others;
    size_t high_findings;
    size_t medium_findings;
    size_t low_findings;
    size_t info_findings;
} ScanStats;

/* Function Prototypes */

/* Initializes a findings list */
void findings_list_init(FindingsList *list);

/* Appends a finding to the list */
bool findings_list_add(FindingsList *list, const SecurityFinding *finding);

/* Frees memory allocated for findings list */
void findings_list_free(FindingsList *list);

/* Collects full metadata and inspects permissions for a file/directory */
int analyze_path(const char *path, PermissionInfo *info);

/* Converts mode_t to 10-char full symbolic notation (e.g. -rw-r--r--) */
void mode_to_symbolic(mode_t mode, char *output, size_t size);

/* Extracts octal representation (e.g. 644 or 1777) */
int mode_to_octal(mode_t mode);

/* Evaluates security rules against collected file metadata */
void evaluate_security_rules(const PermissionInfo *info, FindingsList *findings);

/* Helpers for severity display and ANSI colors */
const char* severity_to_string(SeverityLevel sev);
const char* severity_to_color(SeverityLevel sev);

/* Formats byte size into human-readable string (B, KB, MB, GB) */
void format_file_size(off_t size, char *output, size_t max_len);

/* Displays single file analysis in terminal */
void print_file_analysis(const PermissionInfo *info, const FindingsList *findings);

/* Displays a formatted finding item */
void print_single_finding(const SecurityFinding *finding, size_t index);

/* Displays the standard scan summary block */
void print_scan_summary(const ScanStats *stats);

#endif /* ANALYZER_H */
