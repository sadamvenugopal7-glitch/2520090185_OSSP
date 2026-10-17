/**
 * ============================================================================
 * Project: Linux File Permission Analyzer
 * File:    scanner.c
 * Authors: Abhishek Yadav K (2520090208) - Path Resolution & Metadata Binding
 *          S Venu Gopal (2520090185)     - Findings Aggregation & Error Safeguards
 *          R ROHIT (2520080037)          - Directory Traversal & Recursion
 * Date:    17 October 2026
 *
 * Description:
 * Implements single-level and recursive directory scanning using POSIX
 * directory APIs (opendir, readdir, closedir, lstat). Protects against loops,
 * avoids traversing symlinks, and captures permission-denied events gracefully.
 * ============================================================================
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_RED        "\033[31m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_BLUE       "\033[34m"
#define ANSI_CYAN       "\033[36m"

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

void scan_context_init(ScanContext *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(ScanContext));
    ctx->max_depth = DEFAULT_MAX_DEPTH;
    ctx->recursive = true;
    ctx->verbose = false;

    findings_list_init(&ctx->findings);

    ctx->entries.items = NULL;
    ctx->entries.count = 0;
    ctx->entries.capacity = 0;

    ctx->visited_devs = NULL;
    ctx->visited_inos = NULL;
    ctx->visited_count = 0;
    ctx->visited_capacity = 0;
}

void scan_context_free(ScanContext *ctx) {
    if (!ctx) return;

    findings_list_free(&ctx->findings);

    if (ctx->entries.items) {
        free(ctx->entries.items);
        ctx->entries.items = NULL;
    }
    ctx->entries.count = 0;
    ctx->entries.capacity = 0;

    if (ctx->visited_devs) {
        free(ctx->visited_devs);
        ctx->visited_devs = NULL;
    }
    if (ctx->visited_inos) {
        free(ctx->visited_inos);
        ctx->visited_inos = NULL;
    }
    ctx->visited_count = 0;
    ctx->visited_capacity = 0;
}

static bool entries_list_add(ScannedEntriesList *list, const ScannedEntry *entry) {
    if (!list || !entry) return false;

    if (list->count >= list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 64 : list->capacity * 2;
        ScannedEntry *new_items = (ScannedEntry *)realloc(list->items, new_cap * sizeof(ScannedEntry));
        if (!new_items) return false;
        list->items = new_items;
        list->capacity = new_cap;
    }

    list->items[list->count] = *entry;
    list->count++;
    return true;
}

static bool is_visited_directory(ScanContext *ctx, dev_t dev, ino_t ino) {
    for (size_t i = 0; i < ctx->visited_count; i++) {
        if (ctx->visited_devs[i] == dev && ctx->visited_inos[i] == ino) {
            return true;
        }
    }
    return false;
}

static bool mark_visited_directory(ScanContext *ctx, dev_t dev, ino_t ino) {
    if (ctx->visited_count >= ctx->visited_capacity) {
        size_t new_cap = (ctx->visited_capacity == 0) ? 64 : ctx->visited_capacity * 2;
        dev_t *new_devs = (dev_t *)realloc(ctx->visited_devs, new_cap * sizeof(dev_t));
        ino_t *new_inos = (ino_t *)realloc(ctx->visited_inos, new_cap * sizeof(ino_t));
        if (!new_devs || !new_inos) {
            if (new_devs) ctx->visited_devs = new_devs;
            if (new_inos) ctx->visited_inos = new_inos;
            return false;
        }
        ctx->visited_devs = new_devs;
        ctx->visited_inos = new_inos;
        ctx->visited_capacity = new_cap;
    }

    ctx->visited_devs[ctx->visited_count] = dev;
    ctx->visited_inos[ctx->visited_count] = ino;
    ctx->visited_count++;
    return true;
}

static void update_stats_with_findings(ScanStats *stats, const FindingsList *findings, size_t start_idx) {
    for (size_t i = start_idx; i < findings->count; i++) {
        switch (findings->items[i].severity) {
            case SEV_HIGH:   stats->high_findings++; break;
            case SEV_MEDIUM: stats->medium_findings++; break;
            case SEV_LOW:    stats->low_findings++; break;
            case SEV_INFO:   stats->info_findings++; break;
        }
    }
}

static int recursive_scan_internal(const char *current_path, int current_depth, ScanContext *ctx) {
    if (!current_path || !ctx) return -1;

    /* Prevent runaway recursion beyond configured max depth */
    if (current_depth > ctx->max_depth) {
        return 0;
    }

    /* Analyze the directory itself first */
    PermissionInfo dir_info;
    if (analyze_path(current_path, &dir_info) != 0) {
        /* Inaccessible path */
        ctx->stats.total_dirs++;
        SecurityFinding f;
        memset(&f, 0, sizeof(f));
        safe_copy(f.path, current_path, sizeof(f.path));
        safe_copy(f.filename, current_path, sizeof(f.filename));
        f.severity = SEV_MEDIUM;
        safe_copy(f.rule_id, "ERR-ACCESS", sizeof(f.rule_id));
        safe_copy(f.title, "Cannot Inspect Directory Metadata", sizeof(f.title));
        snprintf(f.explanation, sizeof(f.explanation), "System call failed: %s", strerror(errno));
        safe_copy(f.recommendation, "Check directory access permissions.", sizeof(f.recommendation));
        safe_copy(f.suggested_chmod, "None", sizeof(f.suggested_chmod));
        findings_list_add(&ctx->findings, &f);
        ctx->stats.medium_findings++;
        return -1;
    }

    /* Ensure we do not follow a symlink as a directory (prevent infinite loops) */
    if (dir_info.is_symlink) {
        ctx->stats.total_symlinks++;
        size_t prev_count = ctx->findings.count;
        evaluate_security_rules(&dir_info, &ctx->findings);
        update_stats_with_findings(&ctx->stats, &ctx->findings, prev_count);
        return 0;
    }

    /* Check for directory loops using dev/ino */
    if (is_visited_directory(ctx, dir_info.stat_buf.st_dev, dir_info.stat_buf.st_ino)) {
        return 0; /* Already visited */
    }
    mark_visited_directory(ctx, dir_info.stat_buf.st_dev, dir_info.stat_buf.st_ino);

    ctx->stats.total_dirs++;

    /* Record findings for this directory itself */
    size_t prev_findings_count = ctx->findings.count;
    evaluate_security_rules(&dir_info, &ctx->findings);
    update_stats_with_findings(&ctx->stats, &ctx->findings, prev_findings_count);

    /* Record in scanned entries list */
    ScannedEntry dir_entry;
    memset(&dir_entry, 0, sizeof(dir_entry));
    safe_copy(dir_entry.path, dir_info.path, sizeof(dir_entry.path));
    safe_copy(dir_entry.filename, dir_info.filename, sizeof(dir_entry.filename));
    dir_entry.octal_perm = dir_info.octal_perm;
    safe_copy(dir_entry.symbolic_perm, dir_info.symbolic_perm, sizeof(dir_entry.symbolic_perm));
    safe_copy(dir_entry.owner_name, dir_info.owner_name, sizeof(dir_entry.owner_name));
    safe_copy(dir_entry.group_name, dir_info.group_name, sizeof(dir_entry.group_name));
    safe_copy(dir_entry.human_size, dir_info.human_size, sizeof(dir_entry.human_size));
    safe_copy(dir_entry.mtime_str, dir_info.mtime_str, sizeof(dir_entry.mtime_str));
    dir_entry.file_type = dir_info.file_type;
    dir_entry.file_type_str = dir_info.file_type_str;
    dir_entry.has_findings = (ctx->findings.count > prev_findings_count);
    if (dir_entry.has_findings) {
        dir_entry.max_severity = ctx->findings.items[ctx->findings.count - 1].severity;
    }
    entries_list_add(&ctx->entries, &dir_entry);

    /* Open directory for listing */
    DIR *dir = opendir(current_path);
    if (!dir) {
        /* Gracefully capture permission denied or read errors */
        SecurityFinding f;
        memset(&f, 0, sizeof(f));
        safe_copy(f.path, current_path, sizeof(f.path));
        safe_copy(f.filename, dir_info.filename, sizeof(f.filename));
        f.octal_perm = dir_info.octal_perm;
        safe_copy(f.symbolic_perm, dir_info.symbolic_perm, sizeof(f.symbolic_perm));
        f.severity = SEV_MEDIUM;
        safe_copy(f.rule_id, "ERR-UNREAD", sizeof(f.rule_id));
        safe_copy(f.title, "Directory Unreadable (Permission Denied)", sizeof(f.title));
        snprintf(f.explanation, sizeof(f.explanation),
                 "Failed to open directory '%s' for listing: %s. Contents cannot be inspected.",
                 current_path, strerror(errno));
        snprintf(f.recommendation, sizeof(f.recommendation),
                 "Ensure the reading process or user has read and execute permissions on this directory.");
        snprintf(f.suggested_chmod, sizeof(f.suggested_chmod), "chmod 755 \"%s\"", current_path);
        findings_list_add(&ctx->findings, &f);
        ctx->stats.medium_findings++;
        return 0;
    }

    struct dirent *dp;
    while ((dp = readdir(dir)) != NULL) {
        /* Skip current and parent directory pointers */
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }

        /* Build child path safely */
        char child_path[MAX_PATH_LEN];
        size_t cur_len = strlen(current_path);
        if (cur_len > 0 && current_path[cur_len - 1] == '/') {
            snprintf(child_path, sizeof(child_path), "%s%s", current_path, dp->d_name);
        } else {
            snprintf(child_path, sizeof(child_path), "%s/%s", current_path, dp->d_name);
        }

        /* Analyze the child entry */
        PermissionInfo child_info;
        if (analyze_path(child_path, &child_info) != 0) {
            /* Child entry could not be stat'd */
            continue;
        }

        /* If child is a directory and recursion is enabled, descend directly.
         * The child call to recursive_scan_internal() handles its metadata, findings, and entry logging.
         */
        if (ctx->recursive && child_info.file_type == FT_DIRECTORY && !child_info.is_symlink) {
            recursive_scan_internal(child_path, current_depth + 1, ctx);
            continue;
        }

        /* Categorize and increment counters for non-recursed entries */
        if (child_info.is_symlink) {
            ctx->stats.total_symlinks++;
        } else if (child_info.file_type == FT_DIRECTORY) {
            ctx->stats.total_dirs++;
        } else if (child_info.file_type == FT_REGULAR) {
            ctx->stats.total_files++;
        } else {
            ctx->stats.total_others++;
        }

        /* Check security rules */
        size_t prev_child_findings = ctx->findings.count;
        evaluate_security_rules(&child_info, &ctx->findings);
        update_stats_with_findings(&ctx->stats, &ctx->findings, prev_child_findings);

        /* Add to scanned entries */
        ScannedEntry child_entry;
        memset(&child_entry, 0, sizeof(child_entry));
        safe_copy(child_entry.path, child_info.path, sizeof(child_entry.path));
        safe_copy(child_entry.filename, child_info.filename, sizeof(child_entry.filename));
        child_entry.octal_perm = child_info.octal_perm;
        safe_copy(child_entry.symbolic_perm, child_info.symbolic_perm, sizeof(child_entry.symbolic_perm));
        safe_copy(child_entry.owner_name, child_info.owner_name, sizeof(child_entry.owner_name));
        safe_copy(child_entry.group_name, child_info.group_name, sizeof(child_entry.group_name));
        safe_copy(child_entry.human_size, child_info.human_size, sizeof(child_entry.human_size));
        safe_copy(child_entry.mtime_str, child_info.mtime_str, sizeof(child_entry.mtime_str));
        child_entry.file_type = child_info.file_type;
        child_entry.file_type_str = child_info.file_type_str;
        child_entry.has_findings = (ctx->findings.count > prev_child_findings);
        if (child_entry.has_findings) {
            child_entry.max_severity = ctx->findings.items[ctx->findings.count - 1].severity;
        }
        entries_list_add(&ctx->entries, &child_entry);
    }

    closedir(dir);
    return 0;
}

int scan_directory(const char *dir_path, bool recursive, ScanContext *ctx) {
    if (!dir_path || !ctx) return -1;

    /* Timestamp start */
    time_t now = time(NULL);
    struct tm tm_buf;
    if (localtime_r(&now, &tm_buf) != NULL) {
        strftime(ctx->scan_start_time, sizeof(ctx->scan_start_time), "%Y-%m-%d %H:%M:%S", &tm_buf);
    }

    safe_copy(ctx->root_path, dir_path, sizeof(ctx->root_path));
    ctx->recursive = recursive;

    /* Perform recursive or single-level traversal */
    int res = recursive_scan_internal(dir_path, 0, ctx);

    /* Timestamp end */
    now = time(NULL);
    if (localtime_r(&now, &tm_buf) != NULL) {
        strftime(ctx->scan_end_time, sizeof(ctx->scan_end_time), "%Y-%m-%d %H:%M:%S", &tm_buf);
    }

    return res;
}

void print_directory_analysis(const ScanContext *ctx) {
    if (!ctx) return;

    printf("\n=======================================================\n");
    printf("             DIRECTORY PERMISSION ANALYSIS\n");
    printf("=======================================================\n");
    printf("Target Directory:  " ANSI_BOLD "%s" ANSI_RESET "\n", ctx->root_path);
    printf("Scan Mode:         %s\n", ctx->recursive ? "Recursive" : "Single Level");
    printf("Start Time:        %s\n", ctx->scan_start_time);
    printf("Total Entries:     %zu (Files: %zu, Dirs: %zu, Symlinks: %zu)\n",
           ctx->entries.count, ctx->stats.total_files, ctx->stats.total_dirs, ctx->stats.total_symlinks);
    printf("-------------------------------------------------------\n");
    printf("RECORDED SECURITY FINDINGS (%zu total):\n", ctx->findings.count);

    if (ctx->findings.count == 0) {
        printf("  No security risks detected in directory.\n");
    } else {
        /* Print top findings or all findings */
        size_t to_show = (ctx->findings.count > 25) ? 25 : ctx->findings.count;
        for (size_t i = 0; i < to_show; i++) {
            print_single_finding(&ctx->findings.items[i], i);
        }
        if (ctx->findings.count > to_show) {
            printf("\n  " ANSI_YELLOW "... and %zu more findings (see full report for complete log)" ANSI_RESET "\n",
                   ctx->findings.count - to_show);
        }
    }

    print_scan_summary(&ctx->stats);
}
