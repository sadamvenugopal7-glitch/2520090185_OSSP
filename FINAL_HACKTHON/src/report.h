/**
 * ============================================================================
 * Project: Linux File Permission Analyzer
 * File:    report.h
 * Authors: Abhishek Yadav K (2520090208)
 *          S Venu Gopal (2520090185)
 *          R ROHIT (2520080037)
 * Date:    17 October 2026
 *
 * Description:
 * Header for Report Generation Module. Supports generating clean formatted
 * plain-text audit reports and modern cybersecurity dashboard HTML reports.
 * ============================================================================
 */

#ifndef REPORT_H
#define REPORT_H

#include "scanner.h"

/* Generates formatted ASCII security report to specified file path */
int generate_text_report(const ScanContext *ctx, const char *filepath);

/* Generates modern cybersecurity dashboard HTML report to specified file path */
int generate_html_report(const ScanContext *ctx, const char *filepath);

/* Escapes HTML special characters to prevent injection / XSS */
void escape_html(const char *input, char *output, size_t max_out);

/* Constructs default report filename with timestamp in reports/ directory */
void generate_default_report_path(const char *extension, char *output, size_t max_len);

#endif /* REPORT_H */
