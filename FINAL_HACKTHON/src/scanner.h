/**
 * ============================================================================
 * Project: Linux File Permission Analyzer
 * File:    scanner.h
 * Authors: Abhishek Yadav K (2520090208)
 *          S Venu Gopal (2520090185)
 *          R ROHIT (2520080037)
 * Date:    17 October 2026
 *
 * Description:
 * Header file for the Directory Scanner Engine. Provides both single-level
 * and deep recursive directory traversal using POSIX APIs, with loop protection,
 * symlink boundary safeguards, and graceful error handling.
 * ============================================================================
 */

#ifndef SCANNER_H
#define SCANNER_H

#include "analyzer.h"
#include <sys/types.h>
#include <stdbool.h>

#define DEFAULT_MAX_DEPTH 25

/* Recorded record of a scanned file/directory for report generation */
typedef struct {
    char path[MAX_PATH_LEN];
    char filename[MAX_NAME_LEN];
    int octal_perm;
    char symbolic_perm[12];
    char owner_name[64];
    char group_name[64];
    char human_size[32];
    char mtime_str[64];
    FileType file_type;
    const char *file_type_str;
    bool has_findings;
    SeverityLevel max_severity;
} ScannedEntry;

/* Dynamic Array of Scanned Entries */
typedef struct {
    ScannedEntry *items;
    size_t count;
    size_t capacity;
} ScannedEntriesList;

/* Scan Context holding scan configuration and cumulative results */
typedef struct {
    char root_path[MAX_PATH_LEN];
    char scan_start_time[64];
    char scan_end_time[64];
    bool recursive;
    int max_depth;
    bool verbose;

    ScanStats stats;
    FindingsList findings;
    ScannedEntriesList entries;

    /* Loop detection tracking */
    dev_t *visited_devs;
    ino_t *visited_inos;
    size_t visited_count;
    size_t visited_capacity;
} ScanContext;

/* Initializes a scan context */
void scan_context_init(ScanContext *ctx);

/* Cleans up and frees memory allocated in scan context */
void scan_context_free(ScanContext *ctx);

/* Analyzes a directory (single level or recursive) */
int scan_directory(const char *dir_path, bool recursive, ScanContext *ctx);

/* Displays the directory analysis results in terminal */
void print_directory_analysis(const ScanContext *ctx);

#endif /* SCANNER_H */
