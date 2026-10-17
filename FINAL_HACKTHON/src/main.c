/**
 * ============================================================================
 * Project: Linux File Permission Analyzer
 * File:    main.c
 * Authors: Abhishek Yadav K (2520090208) - Core Logic & Input Processing
 *          S Venu Gopal (2520090185)     - CLI Dispatch & Integration
 *          R ROHIT (2520080037)          - Interactive Menu & User Experience
 * Date:    17 October 2026
 *
 * Description:
 * Entry point and Interactive Terminal User Interface (TUI) for the Linux
 * File Permission Analyzer. Supports both interactive menu navigation and
 * scriptable command-line arguments.
 * ============================================================================
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include "analyzer.h"
#include "scanner.h"
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_RED        "\033[31m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_BLUE       "\033[34m"
#define ANSI_MAGENTA    "\033[35m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_WHITE      "\033[37m"

static void trim_newline(char *str) {
    if (!str) return;
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

static void show_banner(void) {
    printf("\n" ANSI_CYAN ANSI_BOLD);
    printf("===============================================\n");
    printf("       LINUX FILE PERMISSION ANALYZER          \n");
    printf("===============================================\n");
    printf(ANSI_RESET);
}

static void show_menu(void) {
    show_banner();
    printf("1. Analyze a single file\n");
    printf("2. Analyze a directory\n");
    printf("3. Recursively scan a directory\n");
    printf("4. View security findings\n");
    printf("5. Generate a text security report\n");
    printf("6. Generate an HTML security report\n");
    printf("7. View project information\n");
    printf("0. Exit\n\n");
    printf("Enter your choice: ");
    fflush(stdout);
}

static void show_project_info(void) {
    printf("\n" ANSI_BLUE ANSI_BOLD "=======================================================\n");
    printf("              PROJECT INFORMATION\n");
    printf("=======================================================\n" ANSI_RESET);
    printf(ANSI_BOLD "Project Title:" ANSI_RESET "    Linux File Permission Analyzer\n");
    printf(ANSI_BOLD "Category:" ANSI_RESET "         Linux System Programming / Cybersecurity\n");
    printf(ANSI_BOLD "Hackathon Date:" ANSI_RESET "   17 October 2026\n");
    printf(ANSI_BOLD "Language / OS:" ANSI_RESET "    C (C99 / POSIX.1-2008) on Ubuntu Linux / WSL\n");
    printf(ANSI_BOLD "Compiler:" ANSI_RESET "         GCC with -Wall -Wextra -Wpedantic\n");
    printf("\n" ANSI_BOLD "DEVELOPMENT TEAM:" ANSI_RESET "\n");
    printf("  1. " ANSI_CYAN "Abhishek Yadav K" ANSI_RESET " — Roll: 2520090208\n");
    printf("     Responsibilities: File metadata collection & permission representation\n");
    printf("  2. " ANSI_CYAN "S Venu Gopal" ANSI_RESET "     — Roll: 2520090185\n");
    printf("     Responsibilities: Security rule engine & risk severity classification\n");
    printf("  3. " ANSI_CYAN "R ROHIT" ANSI_RESET "          — Roll: 2520080037\n");
    printf("     Responsibilities: Directory scanner & text/HTML report generation\n");
    printf("\n" ANSI_BOLD "SAFETY & ETHICS POLICY:" ANSI_RESET "\n");
    printf("  - READ-ONLY AUDIT MODE: No files or permissions are ever modified.\n");
    printf("  - Safe symlink handling to prevent loop recursion.\n");
    printf("  - Real Linux metadata via POSIX stat(), lstat(), opendir(), readdir().\n");
    printf("=======================================================\n\n");
}

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

static void handle_single_file(ScanContext *ctx) {
    char path[MAX_PATH_LEN];
    printf("\nEnter file path to analyze: ");
    if (!fgets(path, sizeof(path), stdin)) return;
    trim_newline(path);

    if (strlen(path) == 0) {
        printf(ANSI_RED "[-] Error: Path cannot be empty.\n" ANSI_RESET);
        return;
    }

    PermissionInfo info;
    if (analyze_path(path, &info) != 0) {
        printf(ANSI_RED "[-] Error: Unable to access or inspect '%s'. File may not exist or permission is denied.\n" ANSI_RESET, path);
        return;
    }

    /* Reset session scan context to store this analysis */
    scan_context_free(ctx);
    scan_context_init(ctx);
    safe_copy(ctx->root_path, path, sizeof(ctx->root_path));

    time_t now = time(NULL);
    struct tm tm_buf;
    if (localtime_r(&now, &tm_buf) != NULL) {
        strftime(ctx->scan_start_time, sizeof(ctx->scan_start_time), "%Y-%m-%d %H:%M:%S", &tm_buf);
        strftime(ctx->scan_end_time, sizeof(ctx->scan_end_time), "%Y-%m-%d %H:%M:%S", &tm_buf);
    }

    if (info.file_type == FT_DIRECTORY) {
        ctx->stats.total_dirs++;
    } else if (info.is_symlink) {
        ctx->stats.total_symlinks++;
    } else if (info.file_type == FT_REGULAR) {
        ctx->stats.total_files++;
    } else {
        ctx->stats.total_others++;
    }

    evaluate_security_rules(&info, &ctx->findings);

    for (size_t i = 0; i < ctx->findings.count; i++) {
        switch (ctx->findings.items[i].severity) {
            case SEV_HIGH:   ctx->stats.high_findings++; break;
            case SEV_MEDIUM: ctx->stats.medium_findings++; break;
            case SEV_LOW:    ctx->stats.low_findings++; break;
            case SEV_INFO:   ctx->stats.info_findings++; break;
        }
    }

    ScannedEntry e;
    memset(&e, 0, sizeof(e));
    safe_copy(e.path, info.path, sizeof(e.path));
    safe_copy(e.filename, info.filename, sizeof(e.filename));
    e.octal_perm = info.octal_perm;
    safe_copy(e.symbolic_perm, info.symbolic_perm, sizeof(e.symbolic_perm));
    safe_copy(e.owner_name, info.owner_name, sizeof(e.owner_name));
    safe_copy(e.group_name, info.group_name, sizeof(e.group_name));
    safe_copy(e.human_size, info.human_size, sizeof(e.human_size));
    safe_copy(e.mtime_str, info.mtime_str, sizeof(e.mtime_str));
    e.file_type = info.file_type;
    e.file_type_str = info.file_type_str;
    e.has_findings = (ctx->findings.count > 0);
    if (e.has_findings) {
        e.max_severity = ctx->findings.items[0].severity;
    }

    /* Add single entry to list */
    ctx->entries.items = (ScannedEntry *)malloc(sizeof(ScannedEntry));
    if (ctx->entries.items) {
        ctx->entries.items[0] = e;
        ctx->entries.count = 1;
        ctx->entries.capacity = 1;
    }

    print_file_analysis(&info, &ctx->findings);
}

static void handle_directory_scan(ScanContext *ctx, bool recursive) {
    char path[MAX_PATH_LEN];
    printf("\nEnter directory path to %s: ", recursive ? "recursively scan" : "analyze");
    if (!fgets(path, sizeof(path), stdin)) return;
    trim_newline(path);

    if (strlen(path) == 0) {
        printf(ANSI_RED "[-] Error: Path cannot be empty.\n" ANSI_RESET);
        return;
    }

    /* Guard against accidental full-system scan if root is specified */
    if (strcmp(path, "/") == 0 && recursive) {
        char confirm[16];
        printf(ANSI_YELLOW "[!] Warning: Scanning root '/' recursively may take a long time.\n" ANSI_RESET);
        printf("Are you sure you want to proceed? (y/N): ");
        if (!fgets(confirm, sizeof(confirm), stdin)) return;
        trim_newline(confirm);
        if (confirm[0] != 'y' && confirm[0] != 'Y') {
            printf("[*] Scan cancelled by user.\n");
            return;
        }
    }

    /* Check if path exists and is accessible */
    PermissionInfo pinfo;
    if (analyze_path(path, &pinfo) != 0) {
        printf(ANSI_RED "[-] Error: Cannot access path '%s'. Please check spelling and permissions.\n" ANSI_RESET, path);
        return;
    }

    if (pinfo.file_type != FT_DIRECTORY) {
        printf(ANSI_YELLOW "[!] Note: '%s' is a %s, not a directory. Performing single-file analysis instead.\n" ANSI_RESET,
               path, pinfo.file_type_str);
    }

    scan_context_free(ctx);
    scan_context_init(ctx);

    printf("\n[*] Scanning %s'%s' (%s)... please wait.\n",
           ANSI_BOLD, path, recursive ? "recursive" : "single-level");

    if (scan_directory(path, recursive, ctx) != 0) {
        printf(ANSI_RED "[-] Scan encountered errors while reading directory.\n" ANSI_RESET);
    }

    print_directory_analysis(ctx);
}

static void handle_view_findings(const ScanContext *ctx) {
    if (ctx->entries.count == 0 && ctx->findings.count == 0) {
        printf(ANSI_YELLOW "\n[!] No scan results in current session. Please run a file or directory analysis first.\n" ANSI_RESET);
        return;
    }

    printf("\n=======================================================\n");
    printf("       SECURITY FINDINGS IN CURRENT SESSION (%zu total)\n", ctx->findings.count);
    printf("=======================================================\n");
    printf("Target: %s\n\n", ctx->root_path);

    for (size_t i = 0; i < ctx->findings.count; i++) {
        print_single_finding(&ctx->findings.items[i], i);
    }

    print_scan_summary(&ctx->stats);
}

static void handle_generate_text_report(const ScanContext *ctx) {
    if (ctx->entries.count == 0 && ctx->findings.count == 0) {
        printf(ANSI_YELLOW "\n[!] No scan results in current session. Please run a file or directory scan first.\n" ANSI_RESET);
        return;
    }

    char default_path[MAX_PATH_LEN];
    generate_default_report_path("txt", default_path, sizeof(default_path));

    char user_path[MAX_PATH_LEN];
    printf("\nEnter output text report path [Default: %s]: ", default_path);
    if (!fgets(user_path, sizeof(user_path), stdin)) return;
    trim_newline(user_path);

    const char *target = (strlen(user_path) > 0) ? user_path : default_path;

    if (generate_text_report(ctx, target) == 0) {
        printf(ANSI_GREEN "\n[+] Text security report generated successfully!\n" ANSI_RESET);
        printf("    Saved to: " ANSI_BOLD "%s" ANSI_RESET "\n\n", target);
    } else {
        printf(ANSI_RED "[-] Error: Failed to write text report to '%s'. Check directory permissions.\n" ANSI_RESET, target);
    }
}

static void handle_generate_html_report(const ScanContext *ctx) {
    if (ctx->entries.count == 0 && ctx->findings.count == 0) {
        printf(ANSI_YELLOW "\n[!] No scan results in current session. Please run a file or directory scan first.\n" ANSI_RESET);
        return;
    }

    char default_path[MAX_PATH_LEN];
    generate_default_report_path("html", default_path, sizeof(default_path));

    char user_path[MAX_PATH_LEN];
    printf("\nEnter output HTML dashboard path [Default: %s]: ", default_path);
    if (!fgets(user_path, sizeof(user_path), stdin)) return;
    trim_newline(user_path);

    const char *target = (strlen(user_path) > 0) ? user_path : default_path;

    if (generate_html_report(ctx, target) == 0) {
        printf(ANSI_GREEN "\n[+] HTML Cybersecurity Dashboard generated successfully!\n" ANSI_RESET);
        printf("    Saved to: " ANSI_BOLD "%s" ANSI_RESET "\n", target);
        printf("    Open this file in Google Chrome, Microsoft Edge, or Mozilla Firefox to inspect.\n\n");
    } else {
        printf(ANSI_RED "[-] Error: Failed to write HTML report to '%s'. Check directory permissions.\n" ANSI_RESET, target);
    }
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Linux File Permission Analyzer - Cybersecurity Hackathon 2026\n\n");
    printf("Interactive Mode:\n");
    printf("  %s                      Launch interactive terminal menu\n\n", prog_name);
    printf("Command-line Options:\n");
    printf("  -f, --file <path>        Analyze a single file and display security findings\n");
    printf("  -d, --dir <path>         Analyze immediate contents of a directory (non-recursive)\n");
    printf("  -r, --recursive <path>   Recursively scan a directory tree\n");
    printf("  -t, --txt <output.txt>   Write security report to text file\n");
    printf("  -H, --html <output.html> Write security dashboard to HTML file\n");
    printf("  -v, --version            Display version and author information\n");
    printf("  -h, --help               Display this help dialog\n\n");
    printf("Examples:\n");
    printf("  %s -f demo_files/risky.txt\n", prog_name);
    printf("  %s -r demo_files/ -H reports/demo_report.html\n", prog_name);
}

int main(int argc, char *argv[]) {
    ScanContext ctx;
    scan_context_init(&ctx);

    /* Command-Line Argument Processing */
    if (argc > 1) {
        const char *file_target = NULL;
        const char *dir_target = NULL;
        bool recursive_flag = false;
        const char *txt_out = NULL;
        const char *html_out = NULL;

        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                print_usage(argv[0]);
                scan_context_free(&ctx);
                return 0;
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
                printf("Linux File Permission Analyzer v1.0.0 (17 October 2026)\n");
                printf("By Abhishek Yadav K, S Venu Gopal, R ROHIT\n");
                scan_context_free(&ctx);
                return 0;
            } else if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) && i + 1 < argc) {
                file_target = argv[++i];
            } else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dir") == 0) && i + 1 < argc) {
                dir_target = argv[++i];
                recursive_flag = false;
            } else if ((strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--recursive") == 0) && i + 1 < argc) {
                dir_target = argv[++i];
                recursive_flag = true;
            } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--txt") == 0) && i + 1 < argc) {
                txt_out = argv[++i];
            } else if ((strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--html") == 0) && i + 1 < argc) {
                html_out = argv[++i];
            } else {
                fprintf(stderr, "Unknown option: %s. Use -h for help.\n", argv[i]);
                scan_context_free(&ctx);
                return 1;
            }
        }

        if (file_target) {
            PermissionInfo info;
            if (analyze_path(file_target, &info) != 0) {
                fprintf(stderr, "Error: Cannot inspect '%s': %s\n", file_target, strerror(errno));
                scan_context_free(&ctx);
                return 1;
            }
            evaluate_security_rules(&info, &ctx.findings);
            print_file_analysis(&info, &ctx.findings);
        } else if (dir_target) {
            if (scan_directory(dir_target, recursive_flag, &ctx) != 0) {
                fprintf(stderr, "Warning: Errors occurred during directory scan.\n");
            }
            print_directory_analysis(&ctx);
        }

        if (txt_out) {
            if (generate_text_report(&ctx, txt_out) == 0) {
                printf("[+] Text report saved to: %s\n", txt_out);
            }
        }
        if (html_out) {
            if (generate_html_report(&ctx, html_out) == 0) {
                printf("[+] HTML report saved to: %s\n", html_out);
            }
        }

        scan_context_free(&ctx);
        return 0;
    }

    /* Interactive Terminal Menu Loop */
    char input_buf[64];
    int running = 1;

    while (running) {
        show_menu();
        if (!fgets(input_buf, sizeof(input_buf), stdin)) {
            break;
        }
        trim_newline(input_buf);

        if (strlen(input_buf) == 0) {
            continue;
        }

        char choice = input_buf[0];
        switch (choice) {
            case '1':
                handle_single_file(&ctx);
                break;
            case '2':
                handle_directory_scan(&ctx, false);
                break;
            case '3':
                handle_directory_scan(&ctx, true);
                break;
            case '4':
                handle_view_findings(&ctx);
                break;
            case '5':
                handle_generate_text_report(&ctx);
                break;
            case '6':
                handle_generate_html_report(&ctx);
                break;
            case '7':
                show_project_info();
                break;
            case '0':
                printf("\nExiting Linux File Permission Analyzer. Goodbye!\n");
                running = 0;
                break;
            default:
                printf(ANSI_RED "\n[-] Invalid option '%s'. Please select a number from 0 to 7.\n" ANSI_RESET, input_buf);
                break;
        }
    }

    scan_context_free(&ctx);
    return 0;
}
