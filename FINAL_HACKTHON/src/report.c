/**
 * ============================================================================
 * Project: Linux File Permission Analyzer
 * File:    report.c
 * Authors: Abhishek Yadav K (2520090208) - Text Report Structuring
 *          S Venu Gopal (2520090185)     - HTML Escaping & Security Audit
 *          R ROHIT (2520080037)          - HTML Dashboard Styling & UI/UX
 * Date:    17 October 2026
 *
 * Description:
 * Implements Text and HTML security report generation from actual scan results.
 * Produces an executive-grade cybersecurity dashboard with dark navy theme,
 * statistics cards, severity filtering, and corrective chmod guidance.
 * ============================================================================
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

void escape_html(const char *input, char *output, size_t max_out) {
    if (!input || !output || max_out == 0) return;

    size_t o = 0;
    for (size_t i = 0; input[i] != '\0' && o < max_out - 1; i++) {
        switch (input[i]) {
            case '&':
                if (o + 5 < max_out) { strcpy(&output[o], "&amp;"); o += 5; }
                break;
            case '<':
                if (o + 4 < max_out) { strcpy(&output[o], "&lt;"); o += 4; }
                break;
            case '>':
                if (o + 4 < max_out) { strcpy(&output[o], "&gt;"); o += 4; }
                break;
            case '"':
                if (o + 6 < max_out) { strcpy(&output[o], "&quot;"); o += 6; }
                break;
            case '\'':
                if (o + 5 < max_out) { strcpy(&output[o], "&#39;"); o += 5; }
                break;
            default:
                output[o++] = input[i];
                break;
        }
    }
    output[o] = '\0';
}

void generate_default_report_path(const char *extension, char *output, size_t max_len) {
    if (!output || max_len == 0) return;
    time_t now = time(NULL);
    struct tm tm_buf;
    if (localtime_r(&now, &tm_buf) != NULL) {
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%Y%m%d_%H%M%S", &tm_buf);
        snprintf(output, max_len, "reports/scan_report_%s.%s", time_str, extension ? extension : "txt");
    } else {
        snprintf(output, max_len, "reports/scan_report.%s", extension ? extension : "txt");
    }
}

int generate_text_report(const ScanContext *ctx, const char *filepath) {
    if (!ctx || !filepath) return -1;

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        return -1;
    }

    fprintf(fp, "================================================================================\n");
    fprintf(fp, "                  LINUX FILE PERMISSION ANALYZER - AUDIT REPORT                 \n");
    fprintf(fp, "================================================================================\n");
    fprintf(fp, "Generated:        %s\n", ctx->scan_end_time[0] ? ctx->scan_end_time : "N/A");
    fprintf(fp, "Target Scanned:   %s\n", ctx->root_path);
    fprintf(fp, "Scan Mode:        %s\n", ctx->recursive ? "Recursive Directory Traversal" : "Single-Level Directory");
    fprintf(fp, "Project:          Linux File Permission Analyzer (Hackathon 2026)\n");
    fprintf(fp, "Team Members:     Abhishek Yadav K (2520090208)\n");
    fprintf(fp, "                  S Venu Gopal     (2520090185)\n");
    fprintf(fp, "                  R ROHIT          (2520080037)\n");
    fprintf(fp, "Operation Mode:   READ-ONLY AUDIT (No filesystem modifications executed)\n");
    fprintf(fp, "================================================================================\n\n");

    fprintf(fp, "--------------------------------------------------------------------------------\n");
    fprintf(fp, "1. EXECUTIVE SUMMARY\n");
    fprintf(fp, "--------------------------------------------------------------------------------\n");
    fprintf(fp, "  Total Files Scanned:        %zu\n", ctx->stats.total_files);
    fprintf(fp, "  Total Directories Scanned:  %zu\n", ctx->stats.total_dirs);
    fprintf(fp, "  Symbolic Links Observed:    %zu\n", ctx->stats.total_symlinks);
    fprintf(fp, "  Total Recorded Entries:     %zu\n\n", ctx->entries.count);
    fprintf(fp, "  FINDINGS SEVERITY BREAKDOWN:\n");
    fprintf(fp, "  [-] HIGH Risk Findings:     %zu\n", ctx->stats.high_findings);
    fprintf(fp, "  [-] MEDIUM Risk Findings:   %zu\n", ctx->stats.medium_findings);
    fprintf(fp, "  [-] LOW Risk Findings:      %zu\n", ctx->stats.low_findings);
    fprintf(fp, "  [-] INFORMATIONAL Findings: %zu\n\n", ctx->stats.info_findings);

    fprintf(fp, "--------------------------------------------------------------------------------\n");
    fprintf(fp, "2. DETAILED SECURITY FINDINGS & RECOMMENDATIONS\n");
    fprintf(fp, "--------------------------------------------------------------------------------\n\n");

    if (ctx->findings.count == 0) {
        fprintf(fp, "  No security findings were generated during this scan.\n\n");
    } else {
        for (size_t i = 0; i < ctx->findings.count; i++) {
            const SecurityFinding *f = &ctx->findings.items[i];
            fprintf(fp, "[Finding #%03zu] %-13s | Rule: %-8s | Mode: %s (%03o)\n",
                    i + 1, severity_to_string(f->severity), f->rule_id, f->symbolic_perm, f->octal_perm);
            fprintf(fp, "  Title:          %s\n", f->title);
            fprintf(fp, "  Target Path:    %s\n", f->path);
            fprintf(fp, "  Explanation:    %s\n", f->explanation);
            fprintf(fp, "  Recommendation: %s\n", f->recommendation);
            if (strcmp(f->suggested_chmod, "None (Compliant)") != 0 &&
                strcmp(f->suggested_chmod, "N/A (Manage target file permissions)") != 0) {
                fprintf(fp, "  Suggested Fix:  %s\n", f->suggested_chmod);
            }
            fprintf(fp, "  ----------------------------------------------------------------------------\n");
        }
    }

    fprintf(fp, "\n--------------------------------------------------------------------------------\n");
    fprintf(fp, "3. SCANNED INVENTORY SUMMARY\n");
    fprintf(fp, "--------------------------------------------------------------------------------\n");
    fprintf(fp, "%-12s %-6s %-12s %-12s %-10s %s\n",
            "PERMISSIONS", "OCTAL", "OWNER", "GROUP", "SIZE", "PATH");
    fprintf(fp, "--------------------------------------------------------------------------------\n");

    for (size_t i = 0; i < ctx->entries.count; i++) {
        const ScannedEntry *e = &ctx->entries.items[i];
        fprintf(fp, "%-12s %03o    %-12s %-12s %-10s %s\n",
                e->symbolic_perm, e->octal_perm & 0777, e->owner_name, e->group_name, e->human_size, e->path);
    }

    fprintf(fp, "\n================================================================================\n");
    fprintf(fp, "End of Audit Report. Generated by Linux File Permission Analyzer.\n");
    fprintf(fp, "================================================================================\n");

    fclose(fp);
    return 0;
}

int generate_html_report(const ScanContext *ctx, const char *filepath) {
    if (!ctx || !filepath) return -1;

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        return -1;
    }

    char esc_root[MAX_PATH_LEN * 2];
    escape_html(ctx->root_path, esc_root, sizeof(esc_root));

    fprintf(fp, "<!DOCTYPE html>\n");
    fprintf(fp, "<html lang=\"en\">\n<head>\n");
    fprintf(fp, "  <meta charset=\"UTF-8\">\n");
    fprintf(fp, "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    fprintf(fp, "  <title>Security Audit Report - Linux File Permission Analyzer</title>\n");
    fprintf(fp, "  <style>\n");
    fprintf(fp, "    :root {\n");
    fprintf(fp, "      --bg-dark: #0b1120;\n");
    fprintf(fp, "      --surface-card: #151e32;\n");
    fprintf(fp, "      --surface-card-hover: #1c2742;\n");
    fprintf(fp, "      --border-color: #243250;\n");
    fprintf(fp, "      --text-main: #f1f5f9;\n");
    fprintf(fp, "      --text-muted: #94a3b8;\n");
    fprintf(fp, "      --primary: #38bdf8;\n");
    fprintf(fp, "      --primary-glow: rgba(56, 189, 248, 0.15);\n");
    fprintf(fp, "      --sev-high: #f87171;\n");
    fprintf(fp, "      --sev-high-bg: rgba(239, 68, 68, 0.15);\n");
    fprintf(fp, "      --sev-med: #fbbf24;\n");
    fprintf(fp, "      --sev-med-bg: rgba(245, 158, 11, 0.15);\n");
    fprintf(fp, "      --sev-low: #38bdf8;\n");
    fprintf(fp, "      --sev-low-bg: rgba(56, 189, 248, 0.15);\n");
    fprintf(fp, "      --sev-info: #34d399;\n");
    fprintf(fp, "      --sev-info-bg: rgba(52, 211, 153, 0.15);\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    * { box-sizing: border-box; margin: 0; padding: 0; }\n");
    fprintf(fp, "    body {\n");
    fprintf(fp, "      background-color: var(--bg-dark);\n");
    fprintf(fp, "      color: var(--text-main);\n");
    fprintf(fp, "      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;\n");
    fprintf(fp, "      line-height: 1.6;\n");
    fprintf(fp, "      padding: 30px 20px;\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    .container { max-width: 1300px; margin: 0 auto; }\n");
    fprintf(fp, "    header {\n");
    fprintf(fp, "      background: linear-gradient(135deg, #101b33 0%%, #172554 100%%);\n");
    fprintf(fp, "      border: 1px solid var(--border-color);\n");
    fprintf(fp, "      border-radius: 12px;\n");
    fprintf(fp, "      padding: 30px;\n");
    fprintf(fp, "      margin-bottom: 25px;\n");
    fprintf(fp, "      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    .header-top { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 15px; }\n");
    fprintf(fp, "    .title-group h1 { font-size: 1.85rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; }\n");
    fprintf(fp, "    .shield-badge { background: var(--primary-glow); border: 1px solid var(--primary); color: var(--primary); padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; text-transform: uppercase; font-weight: 600; }\n");
    fprintf(fp, "    .subtitle { color: var(--text-muted); font-size: 0.95rem; margin-top: 6px; }\n");
    fprintf(fp, "    .team-badge { background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-color); padding: 10px 16px; border-radius: 8px; font-size: 0.85rem; color: #cbd5e1; }\n");
    fprintf(fp, "    .scan-metadata { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-top: 25px; border-top: 1px solid rgba(255, 255, 255, 0.08); padding-top: 20px; }\n");
    fprintf(fp, "    .meta-item { font-size: 0.9rem; }\n");
    fprintf(fp, "    .meta-label { color: var(--text-muted); display: block; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }\n");
    fprintf(fp, "    .meta-value { font-weight: 600; color: #f8fafc; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }\n");
    fprintf(fp, "    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 18px; margin-bottom: 30px; }\n");
    fprintf(fp, "    .card { background-color: var(--surface-card); border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; transition: transform 0.2s, background-color 0.2s; }\n");
    fprintf(fp, "    .card:hover { transform: translateY(-2px); background-color: var(--surface-card-hover); }\n");
    fprintf(fp, "    .card-title { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }\n");
    fprintf(fp, "    .card-num { font-size: 2.2rem; font-weight: 800; margin-top: 6px; }\n");
    fprintf(fp, "    .num-high { color: var(--sev-high); }\n");
    fprintf(fp, "    .num-med { color: var(--sev-med); }\n");
    fprintf(fp, "    .num-low { color: var(--sev-low); }\n");
    fprintf(fp, "    .num-info { color: var(--sev-info); }\n");
    fprintf(fp, "    .num-total { color: #f8fafc; }\n");
    fprintf(fp, "    .section-card { background-color: var(--surface-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 25px; margin-bottom: 30px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3); }\n");
    fprintf(fp, "    .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }\n");
    fprintf(fp, "    .section-header h2 { font-size: 1.3rem; font-weight: 700; color: #fff; }\n");
    fprintf(fp, "    .filter-group { display: flex; gap: 8px; flex-wrap: wrap; }\n");
    fprintf(fp, "    .filter-btn { background: #1e293b; border: 1px solid var(--border-color); color: var(--text-muted); padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-weight: 600; transition: all 0.2s; }\n");
    fprintf(fp, "    .filter-btn:hover, .filter-btn.active { background: var(--primary); color: #0b1120; border-color: var(--primary); }\n");
    fprintf(fp, "    .search-box { background: #0f172a; border: 1px solid var(--border-color); color: #fff; padding: 8px 14px; border-radius: 6px; font-size: 0.85rem; min-width: 240px; }\n");
    fprintf(fp, "    table { width: 100%%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }\n");
    fprintf(fp, "    th { background-color: #0f172a; color: var(--text-muted); font-weight: 600; padding: 12px 14px; border-bottom: 1px solid var(--border-color); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; }\n");
    fprintf(fp, "    td { padding: 14px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); vertical-align: top; }\n");
    fprintf(fp, "    tr:hover td { background-color: rgba(255, 255, 255, 0.02); }\n");
    fprintf(fp, "    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }\n");
    fprintf(fp, "    .badge-high { background-color: var(--sev-high-bg); color: var(--sev-high); border: 1px solid var(--sev-high); }\n");
    fprintf(fp, "    .badge-medium { background-color: var(--sev-med-bg); color: var(--sev-med); border: 1px solid var(--sev-med); }\n");
    fprintf(fp, "    .badge-low { background-color: var(--sev-low-bg); color: var(--sev-low); border: 1px solid var(--sev-low); }\n");
    fprintf(fp, "    .badge-info { background-color: var(--sev-info-bg); color: var(--sev-info); border: 1px solid var(--sev-info); }\n");
    fprintf(fp, "    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; }\n");
    fprintf(fp, "    .code-cmd { background-color: #090d16; border: 1px solid #1e293b; color: #38bdf8; padding: 4px 8px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8rem; display: inline-block; margin-top: 4px; }\n");
    fprintf(fp, "    .copy-btn { background: none; border: none; color: var(--text-muted); cursor: pointer; margin-left: 6px; font-size: 0.8rem; }\n");
    fprintf(fp, "    .copy-btn:hover { color: #fff; }\n");
    fprintf(fp, "    footer { text-align: center; color: var(--text-muted); font-size: 0.85rem; padding: 25px 0; border-top: 1px solid var(--border-color); }\n");
    fprintf(fp, "    .read-only-banner { display: inline-flex; align-items: center; gap: 8px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; padding: 6px 14px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; margin-bottom: 15px; }\n");
    fprintf(fp, "  </style>\n");
    fprintf(fp, "</head>\n<body>\n<div class=\"container\">\n");

    /* Header */
    fprintf(fp, "  <header>\n");
    fprintf(fp, "    <div class=\"read-only-banner\">\n");
    fprintf(fp, "      <span>&#9679;</span> Read-Only Analysis Mode: No files were modified during this scan\n");
    fprintf(fp, "    </div>\n");
    fprintf(fp, "    <div class=\"header-top\">\n");
    fprintf(fp, "      <div class=\"title-group\">\n");
    fprintf(fp, "        <h1>Linux File Permission Analyzer <span class=\"shield-badge\">Security Dashboard</span></h1>\n");
    fprintf(fp, "        <div class=\"subtitle\">Automated POSIX metadata audit &amp; least-privilege risk classification</div>\n");
    fprintf(fp, "      </div>\n");
    fprintf(fp, "      <div class=\"team-badge\">\n");
    fprintf(fp, "        <strong>Hackathon Team:</strong><br>\n");
    fprintf(fp, "        Abhishek Yadav K (2520090208)<br>\n");
    fprintf(fp, "        S Venu Gopal (2520090185)<br>\n");
    fprintf(fp, "        R ROHIT (2520080037)\n");
    fprintf(fp, "      </div>\n");
    fprintf(fp, "    </div>\n");

    fprintf(fp, "    <div class=\"scan-metadata\">\n");
    fprintf(fp, "      <div class=\"meta-item\"><span class=\"meta-label\">Scanned Path</span><span class=\"meta-value\">%s</span></div>\n", esc_root);
    fprintf(fp, "      <div class=\"meta-item\"><span class=\"meta-label\">Scan Mode</span><span class=\"meta-value\">%s</span></div>\n",
            ctx->recursive ? "Recursive Traversal" : "Single Directory");
    fprintf(fp, "      <div class=\"meta-item\"><span class=\"meta-label\">Start Timestamp</span><span class=\"meta-value\">%s</span></div>\n",
            ctx->scan_start_time[0] ? ctx->scan_start_time : "N/A");
    fprintf(fp, "      <div class=\"meta-item\"><span class=\"meta-label\">Completion</span><span class=\"meta-value\">%s</span></div>\n",
            ctx->scan_end_time[0] ? ctx->scan_end_time : "N/A");
    fprintf(fp, "    </div>\n");
    fprintf(fp, "  </header>\n");

    /* Stats Grid */
    fprintf(fp, "  <div class=\"stats-grid\">\n");
    fprintf(fp, "    <div class=\"card\"><div class=\"card-title\">Total Files</div><div class=\"card-num num-total\">%zu</div></div>\n", ctx->stats.total_files);
    fprintf(fp, "    <div class=\"card\"><div class=\"card-title\">Directories</div><div class=\"card-num num-total\">%zu</div></div>\n", ctx->stats.total_dirs);
    fprintf(fp, "    <div class=\"card\"><div class=\"card-title\">High Severity</div><div class=\"card-num num-high\">%zu</div></div>\n", ctx->stats.high_findings);
    fprintf(fp, "    <div class=\"card\"><div class=\"card-title\">Medium Severity</div><div class=\"card-num num-med\">%zu</div></div>\n", ctx->stats.medium_findings);
    fprintf(fp, "    <div class=\"card\"><div class=\"card-title\">Low Severity</div><div class=\"card-num num-low\">%zu</div></div>\n", ctx->stats.low_findings);
    fprintf(fp, "    <div class=\"card\"><div class=\"card-title\">Informational</div><div class=\"card-num num-info\">%zu</div></div>\n", ctx->stats.info_findings);
    fprintf(fp, "  </div>\n");

    /* Findings Section */
    fprintf(fp, "  <div class=\"section-card\">\n");
    fprintf(fp, "    <div class=\"section-header\">\n");
    fprintf(fp, "      <h2>Security Findings &amp; Corrective Guidance (%zu)</h2>\n", ctx->findings.count);
    fprintf(fp, "      <div style=\"display:flex; gap:12px; flex-wrap:wrap;\">\n");
    fprintf(fp, "        <input type=\"text\" id=\"searchBox\" class=\"search-box\" placeholder=\"Filter by path or rule...\" onkeyup=\"filterFindings()\">\n");
    fprintf(fp, "        <div class=\"filter-group\">\n");
    fprintf(fp, "          <button class=\"filter-btn active\" onclick=\"setFilter('all', this)\">All</button>\n");
    fprintf(fp, "          <button class=\"filter-btn\" onclick=\"setFilter('HIGH', this)\">High (%zu)</button>\n", ctx->stats.high_findings);
    fprintf(fp, "          <button class=\"filter-btn\" onclick=\"setFilter('MEDIUM', this)\">Medium (%zu)</button>\n", ctx->stats.medium_findings);
    fprintf(fp, "          <button class=\"filter-btn\" onclick=\"setFilter('LOW', this)\">Low (%zu)</button>\n", ctx->stats.low_findings);
    fprintf(fp, "          <button class=\"filter-btn\" onclick=\"setFilter('INFORMATIONAL', this)\">Info (%zu)</button>\n", ctx->stats.info_findings);
    fprintf(fp, "        </div>\n");
    fprintf(fp, "      </div>\n");
    fprintf(fp, "    </div>\n");

    fprintf(fp, "    <div style=\"overflow-x: auto;\">\n");
    fprintf(fp, "      <table id=\"findingsTable\">\n");
    fprintf(fp, "        <thead>\n");
    fprintf(fp, "          <tr>\n");
    fprintf(fp, "            <th>#</th>\n");
    fprintf(fp, "            <th>Severity</th>\n");
    fprintf(fp, "            <th>Rule</th>\n");
    fprintf(fp, "            <th>Target Path</th>\n");
    fprintf(fp, "            <th>Permissions</th>\n");
    fprintf(fp, "            <th>Risk Analysis</th>\n");
    fprintf(fp, "            <th>Recommendation</th>\n");
    fprintf(fp, "          </tr>\n");
    fprintf(fp, "        </thead>\n");
    fprintf(fp, "        <tbody>\n");

    if (ctx->findings.count == 0) {
        fprintf(fp, "          <tr><td colspan=\"7\" style=\"text-align:center; padding: 25px; color: var(--text-muted);\">No security findings recorded. All permissions adhere to default secure baselines.</td></tr>\n");
    } else {
        for (size_t i = 0; i < ctx->findings.count; i++) {
            const SecurityFinding *f = &ctx->findings.items[i];
            const char *sev_str = severity_to_string(f->severity);
            const char *badge_cls = "badge-info";
            if (f->severity == SEV_HIGH) badge_cls = "badge-high";
            else if (f->severity == SEV_MEDIUM) badge_cls = "badge-medium";
            else if (f->severity == SEV_LOW) badge_cls = "badge-low";

            char esc_path[MAX_PATH_LEN * 2];
            char esc_title[256];
            char esc_expl[MAX_DESC_LEN * 2];
            char esc_recom[MAX_DESC_LEN * 2];
            char esc_cmd[MAX_CMD_LEN * 2];

            escape_html(f->path, esc_path, sizeof(esc_path));
            escape_html(f->title, esc_title, sizeof(esc_title));
            escape_html(f->explanation, esc_expl, sizeof(esc_expl));
            escape_html(f->recommendation, esc_recom, sizeof(esc_recom));
            escape_html(f->suggested_chmod, esc_cmd, sizeof(esc_cmd));

            fprintf(fp, "          <tr data-severity=\"%s\">\n", sev_str);
            fprintf(fp, "            <td class=\"mono\">%03zu</td>\n", i + 1);
            fprintf(fp, "            <td><span class=\"badge %s\">%s</span></td>\n", badge_cls, sev_str);
            fprintf(fp, "            <td class=\"mono\"><strong>%s</strong></td>\n", f->rule_id);
            fprintf(fp, "            <td class=\"mono\"><strong style=\"color:#fff;\">%s</strong></td>\n", esc_path);
            fprintf(fp, "            <td class=\"mono\"><code>%s</code><br><span style=\"color:var(--text-muted); font-size:0.8rem;\">Octal: %03o</span></td>\n",
                    f->symbolic_perm, f->octal_perm & 0777);
            fprintf(fp, "            <td><strong>%s</strong><div style=\"font-size:0.85rem; color:var(--text-muted); margin-top:4px;\">%s</div></td>\n",
                    esc_title, esc_expl);
            fprintf(fp, "            <td>\n");
            fprintf(fp, "              <div>%s</div>\n", esc_recom);
            if (strcmp(f->suggested_chmod, "None (Compliant)") != 0 &&
                strcmp(f->suggested_chmod, "N/A (Manage target file permissions)") != 0) {
                fprintf(fp, "              <div class=\"code-cmd\">%s</div>\n", esc_cmd);
            }
            fprintf(fp, "            </td>\n");
            fprintf(fp, "          </tr>\n");
        }
    }

    fprintf(fp, "        </tbody>\n");
    fprintf(fp, "      </table>\n");
    fprintf(fp, "    </div>\n");
    fprintf(fp, "  </div>\n");

    /* Scanned Files Inventory Section */
    fprintf(fp, "  <div class=\"section-card\">\n");
    fprintf(fp, "    <div class=\"section-header\">\n");
    fprintf(fp, "      <h2>Scanned Files &amp; Directories Inventory (%zu)</h2>\n", ctx->entries.count);
    fprintf(fp, "    </div>\n");
    fprintf(fp, "    <div style=\"max-height: 400px; overflow-y: auto;\">\n");
    fprintf(fp, "      <table>\n");
    fprintf(fp, "        <thead>\n");
    fprintf(fp, "          <tr>\n");
    fprintf(fp, "            <th>Type</th>\n");
    fprintf(fp, "            <th>Path</th>\n");
    fprintf(fp, "            <th>Permissions</th>\n");
    fprintf(fp, "            <th>Octal</th>\n");
    fprintf(fp, "            <th>Owner</th>\n");
    fprintf(fp, "            <th>Group</th>\n");
    fprintf(fp, "            <th>Size</th>\n");
    fprintf(fp, "            <th>Modified</th>\n");
    fprintf(fp, "          </tr>\n");
    fprintf(fp, "        </thead>\n");
    fprintf(fp, "        <tbody>\n");

    for (size_t i = 0; i < ctx->entries.count; i++) {
        const ScannedEntry *e = &ctx->entries.items[i];
        char esc_p[MAX_PATH_LEN * 2];
        escape_html(e->path, esc_p, sizeof(esc_p));

        fprintf(fp, "          <tr>\n");
        fprintf(fp, "            <td>%s</td>\n", e->file_type_str);
        fprintf(fp, "            <td class=\"mono\">%s</td>\n", esc_p);
        fprintf(fp, "            <td class=\"mono\"><code>%s</code></td>\n", e->symbolic_perm);
        fprintf(fp, "            <td class=\"mono\">%03o</td>\n", e->octal_perm & 0777);
        fprintf(fp, "            <td>%s</td>\n", e->owner_name);
        fprintf(fp, "            <td>%s</td>\n", e->group_name);
        fprintf(fp, "            <td class=\"mono\">%s</td>\n", e->human_size);
        fprintf(fp, "            <td class=\"mono\" style=\"font-size:0.8rem; color:var(--text-muted);\">%s</td>\n", e->mtime_str);
        fprintf(fp, "          </tr>\n");
    }

    fprintf(fp, "        </tbody>\n");
    fprintf(fp, "      </table>\n");
    fprintf(fp, "    </div>\n");
    fprintf(fp, "  </div>\n");

    /* Footer */
    fprintf(fp, "  <footer>\n");
    fprintf(fp, "    <p>Linux File Permission Analyzer &mdash; Hackathon 17 October 2026</p>\n");
    fprintf(fp, "    <p style=\"margin-top: 4px; font-size: 0.8rem;\">Developed by Abhishek Yadav K, S Venu Gopal, R ROHIT | System Programming &amp; Cybersecurity</p>\n");
    fprintf(fp, "  </footer>\n");

    /* Client-side script for interactive filtering */
    fprintf(fp, "</div>\n");
    fprintf(fp, "<script>\n");
    fprintf(fp, "  let activeSeverity = 'all';\n");
    fprintf(fp, "  function setFilter(sev, btn) {\n");
    fprintf(fp, "    activeSeverity = sev;\n");
    fprintf(fp, "    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));\n");
    fprintf(fp, "    btn.classList.add('active');\n");
    fprintf(fp, "    filterFindings();\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "  function filterFindings() {\n");
    fprintf(fp, "    const search = document.getElementById('searchBox').value.toLowerCase();\n");
    fprintf(fp, "    const rows = document.querySelectorAll('#findingsTable tbody tr');\n");
    fprintf(fp, "    rows.forEach(row => {\n");
    fprintf(fp, "      const rowSev = row.getAttribute('data-severity');\n");
    fprintf(fp, "      const rowText = row.innerText.toLowerCase();\n");
    fprintf(fp, "      const matchesSev = (activeSeverity === 'all' || rowSev === activeSeverity);\n");
    fprintf(fp, "      const matchesSearch = rowText.includes(search);\n");
    fprintf(fp, "      if (matchesSev && matchesSearch) {\n");
    fprintf(fp, "        row.style.display = '';\n");
    fprintf(fp, "      } else {\n");
    fprintf(fp, "        row.style.display = 'none';\n");
    fprintf(fp, "      }\n");
    fprintf(fp, "    });\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "</script>\n");
    fprintf(fp, "</body>\n</html>\n");

    fclose(fp);
    return 0;
}
