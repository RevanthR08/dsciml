"""
Forensic Examination Report Generator
Case: FSL-DF-2026-0314 | TechCorp Solutions Pvt. Ltd.
Generates the full 24-page PDF report with all charts, tables, and sections.
"""

import io
import os
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
import numpy as np
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.colors import HexColor, black, white
from reportlab.pdfgen import canvas as pdfcanvas

# ─────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────
NAVY       = HexColor('#1a2744')
DARK_BLUE  = HexColor('#1e3a5f')
MID_BLUE   = HexColor('#2d5986')
LIGHT_BLUE = HexColor('#4a90d9')
ACCENT     = HexColor('#e63946')
GOLD       = HexColor('#f4a261')
GREEN      = HexColor('#2a9d8f')
LIGHT_GREY = HexColor('#f0f4f8')
MED_GREY   = HexColor('#c8d4e0')
TEXT_DARK  = HexColor('#1a1a2e')
CRITICAL   = HexColor('#d62828')
HIGH       = HexColor('#e07b39')
MEDIUM     = HexColor('#e9c46a')
LOW        = HexColor('#2a9d8f')
STRIPE     = HexColor('#eaf0f7')

PAGE_W, PAGE_H = A4

# ─────────────────────────────────────────────
# DATA
# ─────────────────────────────────────────────
TECHNIQUES = ['Log Tampering', 'Brute Force', 'Lateral Movement',
              'Privilege Escalation', 'Malicious Service Install']
EVENT_COUNTS  = [4821, 38440, 2104, 873, 312]
RISK_SCORES   = [28900, 19200, 24600, 18700, 3300]
EIDS          = ['1102', '4625', '4624', '4688', '7045']
SEVERITIES    = ['CRITICAL', 'HIGH', 'CRITICAL', 'HIGH', 'MEDIUM']
MITRE_TACTICS = ['Defense Evasion', 'Credential Access', 'Lateral Movement',
                 'Privilege Escalation', 'Persistence']
TECHNIQUE_IDS = ['T1070.001', 'T1110.003', 'T1021.001', 'T1059.001', 'T1543.003']

HOSTS = ['CORP-DC-01', 'CORP-VPN-01', 'CORP-FS-02', 'CORP-DB-01',
         'CORP-WEB-03', 'CORP-WKSTN-47', 'CORP-HR-01', 'CORP-FIN-01', 'CORP-MAIL-01']

HEAT_MAP = {
    'Log Tampering':    [9, None, 7, 8, 8, 5, None, None, None],
    'Brute Force':      [None, 9, None, None, None, None, None, None, 4],
    'Lateral Mvmt':     [None, None, 8, 7, None, 6, 5, 5, None],
    'Priv. Escalation': [None, None, None, None, None, 8, None, None, None],
    'Svc Install':      [None, None, 4, None, None, 7, None, None, None],
}

# ─────────────────────────────────────────────
# HELPER: save matplotlib figure to bytes
# ─────────────────────────────────────────────
def fig_to_image(fig, width_pts, height_pts):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    buf.seek(0)
    plt.close(fig)
    return Image(buf, width=width_pts, height=height_pts)


# ─────────────────────────────────────────────
# CHART GENERATORS
# ─────────────────────────────────────────────
def make_dashboard_fig():
    """Fig 1 – Three-panel threat intelligence dashboard."""
    fig = plt.figure(figsize=(14, 5), facecolor='#0d1b2a')
    gs  = gridspec.GridSpec(1, 3, figure=fig, wspace=0.4)

    tech_colors = ['#e63946','#f4a261','#4a90d9','#a8dadc','#2a9d8f']

    # ── Panel 1: horizontal bar chart ──────────────────────────
    ax1 = fig.add_subplot(gs[0])
    ax1.set_facecolor('#0d1b2a')
    bars = ax1.barh(TECHNIQUES, EVENT_COUNTS, color=tech_colors, edgecolor='none', height=0.55)
    for bar, val in zip(bars, EVENT_COUNTS):
        ax1.text(bar.get_width() + 300, bar.get_y() + bar.get_height()/2,
                 f'{val:,}', va='center', ha='left', color='white', fontsize=7)
    ax1.set_xlabel('Event Count', color='#8ab4d4', fontsize=8)
    ax1.set_title('Event Frequency by Technique', color='white', fontsize=9, fontweight='bold', pad=8)
    ax1.tick_params(colors='#8ab4d4', labelsize=7)
    ax1.spines[:].set_color('#1e3a5f')
    ax1.set_xlim(0, max(EVENT_COUNTS) * 1.25)

    # ── Panel 2: donut ──────────────────────────────────────────
    ax2 = fig.add_subplot(gs[1])
    ax2.set_facecolor('#0d1b2a')
    wedges, _ = ax2.pie(RISK_SCORES, colors=tech_colors, startangle=90,
                        wedgeprops=dict(width=0.5, edgecolor='#0d1b2a', linewidth=2))
    ax2.text(0, 0, f'94,700\nRisk Idx', ha='center', va='center',
             color='white', fontsize=9, fontweight='bold')
    ax2.set_title('Risk Score Distribution', color='white', fontsize=9, fontweight='bold', pad=8)
    legend_labels = [f'{t} ({r/sum(RISK_SCORES)*100:.1f}%)' for t, r in zip(TECHNIQUES, RISK_SCORES)]
    ax2.legend(wedges, legend_labels, loc='lower center', bbox_to_anchor=(0.5, -0.35),
               fontsize=6, ncol=2, framealpha=0, labelcolor='#8ab4d4')

    # ── Panel 3: bubble scatter ─────────────────────────────────
    ax3 = fig.add_subplot(gs[2])
    ax3.set_facecolor('#0d1b2a')
    sizes = [e/8 for e in EVENT_COUNTS]
    sc = ax3.scatter(EVENT_COUNTS, RISK_SCORES, s=sizes, c=tech_colors,
                     alpha=0.85, edgecolors='white', linewidths=0.5)
    for i, t in enumerate(TECHNIQUES):
        ax3.annotate(t, (EVENT_COUNTS[i], RISK_SCORES[i]),
                     textcoords='offset points', xytext=(5, 5),
                     color='#8ab4d4', fontsize=6)
    ax3.set_xlabel('Event Count', color='#8ab4d4', fontsize=8)
    ax3.set_ylabel('Risk Score', color='#8ab4d4', fontsize=8)
    ax3.set_title('Volume vs Risk Correlation', color='white', fontsize=9, fontweight='bold', pad=8)
    ax3.tick_params(colors='#8ab4d4', labelsize=7)
    ax3.spines[:].set_color('#1e3a5f')

    title = fig.suptitle('ANALYTICAL DASHBOARD — THREAT INTELLIGENCE OVERVIEW',
                         color='white', fontsize=11, fontweight='bold', y=1.02)
    return fig


def make_timeline_fig():
    """Fig 2 – 24-hour event distribution grouped bar."""
    windows = ['00-04h', '04-08h', '08-12h', '12-16h', '16-20h', '20-24h']
    data = {
        'Log Tampering':   [2800, 1200,  400,  200, 100, 121],
        'Brute Force':     [18000, 9500, 3200, 2800, 2640, 2300],
        'Lateral Movement':[1400,  480,  100,   70,  30,  24],
        'Priv. Escalation':[620,   150,   50,   30,  15,   8],
        'Malicious Svc':   [180,    80,   25,   15,   8,   4],
    }
    tech_colors = ['#e63946','#f4a261','#4a90d9','#a8dadc','#2a9d8f']

    fig, ax = plt.subplots(figsize=(14, 4), facecolor='#0d1b2a')
    ax.set_facecolor('#0d1b2a')
    x      = np.arange(len(windows))
    n      = len(data)
    width  = 0.15
    cumulative = np.zeros(len(windows))

    for i, (tech, vals) in enumerate(data.items()):
        ax.barh(list(data.keys())[i:i+1] * len(windows),
                vals, color=tech_colors[i], height=0.6, label=windows[0])

    # rebuild as proper grouped horizontal bars
    ax.cla()
    ax.set_facecolor('#0d1b2a')
    for i, (tech, vals) in enumerate(data.items()):
        offset = np.cumsum([0] + vals[:-1])
        ax.barh([i] * len(vals), vals, left=offset, height=0.6,
                color=tech_colors, alpha=0.85)

    ax.set_yticks(range(n))
    ax.set_yticklabels(list(data.keys()), color='#8ab4d4', fontsize=8)
    ax.set_xlabel('Cumulative Event Count', color='#8ab4d4', fontsize=8)
    ax.set_title('24-Hour Attack Timeline — Event Distribution by Technique',
                 color='white', fontsize=10, fontweight='bold', pad=10)
    ax.tick_params(colors='#8ab4d4', labelsize=7)
    ax.spines[:].set_color('#1e3a5f')

    patches = [mpatches.Patch(color=c, label=w) for c, w in zip(tech_colors[:len(windows)], windows)]
    ax.legend(handles=patches, loc='lower right', framealpha=0,
              labelcolor='#8ab4d4', fontsize=7, ncol=6)
    fig.tight_layout()
    return fig


def make_brute_force_fig():
    """Fig 3 – Hourly brute force distribution."""
    hours  = list(range(24))
    counts = [820,1050,1200,950,300,80,30,20,15,10,8,5,4,3,2,2,1,1,1,50,80,120,200,320]
    thresh = 500

    fig, ax = plt.subplots(figsize=(14, 4), facecolor='#0d1b2a')
    ax.set_facecolor('#0d1b2a')
    bar_colors = ['#e63946' if c > thresh else '#4a90d9' for c in counts]
    ax.bar(hours, counts, color=bar_colors, width=0.7, edgecolor='none')
    ax.axhline(thresh, color='#f4a261', linestyle='--', linewidth=1.2, label='Alert Threshold (500)')
    ax.set_xlabel('Hour of Day (UTC)', color='#8ab4d4', fontsize=9)
    ax.set_ylabel('Failed Logon Attempts', color='#8ab4d4', fontsize=9)
    ax.set_title('Brute Force Attempt Volume — Hourly Distribution (EID 4625)',
                 color='white', fontsize=10, fontweight='bold', pad=10)
    ax.set_xticks(hours)
    ax.set_xticklabels([f'{h:02d}' for h in hours], color='#8ab4d4', fontsize=7)
    ax.tick_params(colors='#8ab4d4', labelsize=8)
    ax.spines[:].set_color('#1e3a5f')
    ax.legend(framealpha=0, labelcolor='#f4a261', fontsize=8)
    fig.tight_layout()
    return fig


def make_gantt_fig():
    """Fig 4 – Attack kill chain Gantt chart."""
    phases = ['Initial Access', 'Credential Staging', 'Defense Evasion',
              'Lateral Movement', 'Privilege Escalation', 'Persist & Install', 'C2 Beacon Activity']
    starts = [0, 0.75, 2.27, 2.82, 3.05, 3.25, 3.65]
    durs   = [0.75, 1.52, 0.55, 0.23, 0.20, 0.40, 1.47]
    phase_colors = ['#4a90d9','#2d5986','#e63946','#f4a261','#a8dadc','#2a9d8f','#e63946']

    fig, ax = plt.subplots(figsize=(14, 4.5), facecolor='#0d1b2a')
    ax.set_facecolor('#0d1b2a')
    for i, (phase, start, dur, col) in enumerate(zip(phases, starts, durs, phase_colors)):
        ax.barh(i, dur, left=start, height=0.55, color=col, edgecolor='none', alpha=0.9)
        ax.text(start + dur/2, i, phase, ha='center', va='center',
                color='white', fontsize=7.5, fontweight='bold')

    ax.set_yticks([])
    ax.set_xlabel('Hours from Midnight (UTC 2026-03-14)', color='#8ab4d4', fontsize=9)
    ax.set_title('Attack Kill Chain — Temporal Progression',
                 color='white', fontsize=10, fontweight='bold', pad=10)
    ax.tick_params(colors='#8ab4d4', labelsize=8)
    ax.spines[:].set_color('#1e3a5f')
    ax.set_xlim(0, 24)
    # mark 23.97h label
    ax.text(23.97, -0.7, '23.97h', color='#8ab4d4', fontsize=7)
    fig.tight_layout()
    return fig


def make_heat_map_fig():
    """Fig 5 – Risk heat map."""
    techniques = list(HEAT_MAP.keys())
    matrix = np.full((len(techniques), len(HOSTS)), np.nan)
    for i, tech in enumerate(techniques):
        for j, val in enumerate(HEAT_MAP[tech]):
            if val is not None:
                matrix[i, j] = val

    fig, ax = plt.subplots(figsize=(14, 4), facecolor='#0d1b2a')
    ax.set_facecolor('#0d1b2a')
    cmap = plt.cm.RdYlBu_r
    cmap.set_bad('#1a2744')
    im = ax.imshow(matrix, cmap=cmap, vmin=1, vmax=10, aspect='auto')
    for i in range(len(techniques)):
        for j in range(len(HOSTS)):
            val = matrix[i, j]
            if not np.isnan(val):
                ax.text(j, i, f'{int(val)}', ha='center', va='center',
                        color='white', fontsize=9, fontweight='bold')
    ax.set_xticks(range(len(HOSTS)))
    ax.set_xticklabels([h.replace('CORP-','') for h in HOSTS],
                       rotation=30, ha='right', color='#8ab4d4', fontsize=7.5)
    ax.set_yticks(range(len(techniques)))
    ax.set_yticklabels(techniques, color='#8ab4d4', fontsize=8)
    plt.colorbar(im, ax=ax, label='Risk Score (1-10)', shrink=0.8).ax.yaxis.set_tick_params(color='#8ab4d4')
    ax.set_title('Risk Heat Map — Technique × Host Exposure Matrix',
                 color='white', fontsize=10, fontweight='bold', pad=10)
    fig.tight_layout()
    return fig


def make_mitre_fig():
    """Fig 6 – MITRE ATT&CK tactic coverage."""
    tactics = ['Initial\nAccess', 'Persistence', 'Privilege\nEscalation',
               'Defense\nEvasion', 'Credential\nAccess', 'Lateral\nMovement',
               'Command\n& Control', 'Exfiltration']
    counts  = [2, 2, 2, 2, 2, 2, 2, 1]
    tac_colors = ['#4a90d9','#2a9d8f','#e63946','#f4a261','#a8dadc','#4a90d9','#2d5986','#e63946']

    fig, ax = plt.subplots(figsize=(14, 4), facecolor='#0d1b2a')
    ax.set_facecolor('#0d1b2a')
    bars = ax.bar(tactics, counts, color=tac_colors, width=0.6, edgecolor='none')
    for bar, val in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                str(val), ha='center', va='bottom', color='white', fontsize=9, fontweight='bold')
    ax.set_ylabel('Techniques Detected', color='#8ab4d4', fontsize=9)
    ax.set_title('MITRE ATT&CK Coverage — Detected Tactics & Techniques',
                 color='white', fontsize=10, fontweight='bold', pad=10)
    ax.set_ylim(0, 3)
    ax.tick_params(colors='#8ab4d4', labelsize=7.5)
    ax.spines[:].set_color('#1e3a5f')
    fig.tight_layout()
    return fig


def make_remediation_fig():
    """Fig 7 – Remediation priority matrix."""
    phases  = ['Immediate\n(0-24h)', 'Short-Term\n(1-7d)', 'Medium-Term\n(1-4w)', 'Strategic\n(1-3m)']
    efforts = [1, 4, 6, 8.5]
    impacts = [10, 8.5, 7, 4.5]
    sizes   = [400, 300, 250, 200]
    pcolors = ['#e63946','#f4a261','#e9c46a','#2a9d8f']

    fig, ax = plt.subplots(figsize=(7, 5), facecolor='#0d1b2a')
    ax.set_facecolor('#0d1b2a')
    sc = ax.scatter(efforts, impacts, s=sizes, c=pcolors, alpha=0.9,
                    edgecolors='white', linewidths=1)
    for x, y, label in zip(efforts, impacts, phases):
        ax.annotate(label, (x, y), textcoords='offset points', xytext=(8, 8),
                    color='white', fontsize=8, fontweight='bold')
    ax.set_xlabel('Implementation Effort →', color='#8ab4d4', fontsize=9)
    ax.set_ylabel('Security Impact', color='#8ab4d4', fontsize=9)
    ax.set_title('Remediation Priority Matrix', color='white', fontsize=10,
                 fontweight='bold', pad=10)
    ax.set_xlim(0, 11)
    ax.set_ylim(2.5, 11)
    ax.tick_params(colors='#8ab4d4', labelsize=8)
    ax.spines[:].set_color('#1e3a5f')
    fig.tight_layout()
    return fig


# ─────────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────────
def build_styles():
    base = getSampleStyleSheet()
    s = {}

    def ps(name, **kw):
        defaults = dict(fontName='Helvetica', fontSize=9, leading=13,
                        textColor=TEXT_DARK, spaceAfter=4)
        defaults.update(kw)
        return ParagraphStyle(name, **defaults)

    s['title']       = ps('title', fontName='Helvetica-Bold', fontSize=18,
                           textColor=white, alignment=TA_CENTER, leading=22)
    s['heading1']    = ps('heading1', fontName='Helvetica-Bold', fontSize=11,
                           textColor=white, leading=14)
    s['heading2']    = ps('heading2', fontName='Helvetica-Bold', fontSize=9.5,
                           textColor=NAVY, leading=13)
    s['body']        = ps('body', fontSize=8.5, leading=13, alignment=TA_JUSTIFY)
    s['body_bold']   = ps('body_bold', fontName='Helvetica-Bold', fontSize=8.5, leading=13)
    s['small']       = ps('small', fontSize=7.5, leading=11, textColor=HexColor('#555'))
    s['caption']     = ps('caption', fontSize=7.5, leading=11, textColor=HexColor('#555'),
                           alignment=TA_CENTER, fontName='Helvetica-Oblique')
    s['bullet']      = ps('bullet', fontSize=8.5, leading=13, leftIndent=12, alignment=TA_JUSTIFY)
    s['toc']         = ps('toc', fontSize=9, leading=14)
    s['toc_bold']    = ps('toc_bold', fontName='Helvetica-Bold', fontSize=9, leading=14)
    s['finding']     = ps('finding', fontSize=8.5, leading=13, leftIndent=10,
                           borderPad=4, backColor=LIGHT_GREY, alignment=TA_JUSTIFY)
    s['white_body']  = ps('white_body', fontSize=8, leading=12, textColor=white)
    return s


# ─────────────────────────────────────────────
# CUSTOM FLOWABLES
# ─────────────────────────────────────────────
class HeaderBanner(Flowable):
    """Top banner used on every page (cover version + section version)."""
    def __init__(self, subtitle='', is_cover=False):
        super().__init__()
        self.subtitle  = subtitle
        self.is_cover  = is_cover
        self.width     = PAGE_W - 30*mm
        self.height    = 14*mm if not is_cover else 20*mm

    def draw(self):
        c = self.canv
        c.setFillColor(NAVY)
        c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        c.setFillColor(ACCENT)
        c.rect(0, 0, 4*mm, self.height, fill=1, stroke=0)
        c.setFont('Helvetica-Bold', 8)
        c.setFillColor(white)
        c.drawString(8*mm, self.height - 7*mm,
                     'GOVERNMENT FORENSIC SCIENCE LABORATORY | DIGITAL EVIDENCE DIVISION')
        c.setFont('Helvetica', 7)
        c.setFillColor(MED_GREY)
        c.drawString(8*mm, 3*mm,
                     'Case: FSL-DF-2026-0314  |  RESTRICTED — OFFICIAL USE ONLY')


class SectionHeader(Flowable):
    def __init__(self, number, title, styles):
        super().__init__()
        self.number = number
        self.title  = title
        self.styles = styles
        self.width  = PAGE_W - 30*mm
        self.height = 10*mm

    def draw(self):
        c = self.canv
        c.setFillColor(DARK_BLUE)
        c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        c.setFillColor(ACCENT)
        c.rect(0, 0, 8*mm, self.height, fill=1, stroke=0)
        c.setFont('Helvetica-Bold', 9)
        c.setFillColor(white)
        c.drawString(2*mm, 3*mm, self.number)
        c.setFont('Helvetica-Bold', 10)
        c.drawString(12*mm, 3*mm, self.title)


class InterpretationBox(Flowable):
    def __init__(self, label, text, width):
        super().__init__()
        self.label = label
        self.text  = text
        self._width = width
        self.height = 22*mm

    def draw(self):
        c = self.canv
        c.setFillColor(HexColor('#dbeafe'))
        c.setStrokeColor(LIGHT_BLUE)
        c.roundRect(0, 0, self._width, self.height, 3*mm, fill=1, stroke=1)
        c.setFillColor(DARK_BLUE)
        c.setFont('Helvetica-Bold', 8)
        c.drawString(4*mm, self.height - 6*mm, self.label)
        c.setFont('Helvetica', 7.5)
        c.setFillColor(TEXT_DARK)
        # Wrap text manually
        words = self.text.split()
        line, y = '', self.height - 12*mm
        for w in words:
            test = line + ' ' + w if line else w
            if c.stringWidth(test, 'Helvetica', 7.5) < self._width - 8*mm:
                line = test
            else:
                if y < 4*mm:
                    break
                c.drawString(4*mm, y, line)
                y    -= 5*mm
                line  = w
        if line and y >= 4*mm:
            c.drawString(4*mm, y, line)


class FindingBox(Flowable):
    def __init__(self, severity, title, event_count, risk_index,
                 mitre_tactic, tech_id, hosts, width):
        super().__init__()
        self.sev    = severity
        self.title  = title
        self.ec     = event_count
        self.ri     = risk_index
        self.tactic = mitre_tactic
        self.tid    = tech_id
        self.hosts  = hosts
        self._width = width
        self.height = 16*mm
        sev_colors  = {'CRITICAL': CRITICAL, 'HIGH': HIGH, 'MEDIUM': MEDIUM}
        self._col   = sev_colors.get(severity, MED_GREY)

    def draw(self):
        c = self.canv
        c.setFillColor(NAVY)
        c.rect(0, 0, self._width, self.height, fill=1, stroke=0)
        # severity badge
        c.setFillColor(self._col)
        c.roundRect(self._width - 32*mm, 4*mm, 28*mm, 8*mm, 2*mm, fill=1, stroke=0)
        c.setFont('Helvetica-Bold', 8)
        c.setFillColor(white)
        c.drawCentredString(self._width - 18*mm, 7*mm, self.sev)
        # title
        c.setFont('Helvetica-Bold', 10)
        c.drawString(4*mm, self.height - 7*mm, f'{self.title}  ({self.tid})')
        # metrics
        c.setFont('Helvetica', 7.5)
        c.setFillColor(MED_GREY)
        metrics = (f'Event Count: {self.ec:,}   '
                   f'Risk Index: {self.ri:,}   '
                   f'MITRE Tactic: {self.tactic}   '
                   f'Affected Hosts: {self.hosts}')
        c.drawString(4*mm, 4*mm, metrics)


# ─────────────────────────────────────────────
# PAGE TEMPLATES (header/footer callbacks)
# ─────────────────────────────────────────────
def make_page_callbacks(doc):
    def on_page(canvas, doc):
        canvas.saveState()
        # top stripe
        canvas.setFillColor(NAVY)
        canvas.rect(15*mm, PAGE_H - 15*mm, PAGE_W - 30*mm, 10*mm, fill=1, stroke=0)
        canvas.setFillColor(ACCENT)
        canvas.rect(15*mm, PAGE_H - 15*mm, 4*mm, 10*mm, fill=1, stroke=0)
        canvas.setFont('Helvetica-Bold', 7)
        canvas.setFillColor(white)
        canvas.drawString(22*mm, PAGE_H - 10*mm,
                          'GOVERNMENT FORENSIC SCIENCE LABORATORY | DIGITAL EVIDENCE DIVISION')
        canvas.setFont('Helvetica', 6.5)
        canvas.setFillColor(MED_GREY)
        canvas.drawString(22*mm, PAGE_H - 14*mm,
                          'Case: FSL-DF-2026-0314  |  RESTRICTED — OFFICIAL USE ONLY')
        # bottom stripe
        canvas.setFillColor(NAVY)
        canvas.rect(15*mm, 10*mm, PAGE_W - 30*mm, 8*mm, fill=1, stroke=0)
        canvas.setFont('Helvetica', 6.5)
        canvas.setFillColor(MED_GREY)
        canvas.drawString(17*mm, 13*mm,
                          'FSL/DF/2026/074 | Generated: 2026-03-15 08:02 UTC | '
                          'Examiner: Dr. A. Sharma, CHFI, GCFE')
        canvas.setFillColor(white)
        canvas.setFont('Helvetica-Bold', 7)
        canvas.drawRightString(PAGE_W - 17*mm, 13*mm, f'Page {doc.page}')
        canvas.restoreState()
    return on_page


# ─────────────────────────────────────────────
# SECTION BUILDERS
# ─────────────────────────────────────────────
def styled_table(data, col_widths, header_bg=NAVY, alt_bg=STRIPE,
                 header_fg=white, font_size=7.5):
    tbl = Table(data, colWidths=col_widths)
    style = [
        ('BACKGROUND', (0,0), (-1,0), header_bg),
        ('TEXTCOLOR',  (0,0), (-1,0), header_fg),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), font_size),
        ('LEADING',    (0,0), (-1,-1), font_size + 3),
        ('ALIGN',      (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, alt_bg]),
        ('GRID',       (0,0), (-1,-1), 0.3, MED_GREY),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]
    tbl.setStyle(TableStyle(style))
    return tbl


def severity_badge(sev):
    colors_map = {'CRITICAL': '#fde8e8', 'HIGH': '#fef3e2', 'MEDIUM': '#fefce8'}
    text_map   = {'CRITICAL': '#c81e1e', 'HIGH': '#9a3412', 'MEDIUM': '#854d0e'}
    bg  = colors_map.get(sev, '#f0f4f8')
    fg  = text_map.get(sev, '#333')
    return Paragraph(f'<font color="{fg}"><b>{sev}</b></font>', ParagraphStyle(
        'badge', backColor=HexColor(bg), borderPad=2, borderRadius=2,
        fontSize=7.5, leading=10, alignment=TA_CENTER))


# ─────────────────────────────────────────────
# COVER PAGE
# ─────────────────────────────────────────────
def build_cover(styles):
    elems = []
    W = PAGE_W - 30*mm

    # Large navy cover block
    class CoverBlock(Flowable):
        def __init__(self):
            super().__init__()
            self.width  = W
            self.height = 70*mm

        def draw(self):
            c = self.canv
            c.setFillColor(NAVY)
            c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
            c.setFillColor(ACCENT)
            c.rect(0, 0, self.width, 2*mm, fill=1, stroke=0)
            c.rect(0, self.height - 2*mm, self.width, 2*mm, fill=1, stroke=0)
            # org name
            c.setFillColor(white)
            c.setFont('Helvetica-Bold', 20)
            c.drawCentredString(self.width/2, 48*mm, 'FORENSIC EXAMINATION REPORT')
            c.setFont('Helvetica', 11)
            c.setFillColor(MED_GREY)
            c.drawCentredString(self.width/2, 42*mm,
                                'Digital Evidence Division • National Cyber Crime Investigation Cell')
            c.setFillColor(LIGHT_BLUE)
            c.rect(self.width/2 - 40*mm, 38*mm, 80*mm, 0.5*mm, fill=1, stroke=0)
            c.setFont('Helvetica-Bold', 13)
            c.setFillColor(white)
            c.drawCentredString(self.width/2, 32*mm, 'TechCorp Solutions Pvt. Ltd.')
            c.setFont('Helvetica', 9)
            c.setFillColor(MED_GREY)
            c.drawCentredString(self.width/2, 26*mm, 'Case: FSL-DF-2026-0314')
            c.drawCentredString(self.width/2, 21*mm, 'Report Reference: FSL/DF/2026/074')
            c.drawCentredString(self.width/2, 16*mm, 'Generated: 2026-03-15 08:02 UTC')
            c.setFont('Helvetica-Bold', 8)
            c.setFillColor(ACCENT)
            c.drawCentredString(self.width/2, 9*mm, 'RESTRICTED — OFFICIAL USE ONLY')

    elems.append(CoverBlock())
    elems.append(Spacer(1, 6*mm))

    # KPI row
    kpi_data = [
        ['148,320', '94,700', '17', '9', '5.2h'],
        ['Total Log Entries', 'Aggregate Risk Index', 'Affected Hosts',
         'Compromised Accounts', 'Active Breach Duration'],
    ]
    kpi_tbl = Table(kpi_data, colWidths=[W/5]*5)
    kpi_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), DARK_BLUE),
        ('TEXTCOLOR',     (0,0), (-1,0), ACCENT),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,0), 16),
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ('BACKGROUND',    (0,1), (-1,1), NAVY),
        ('TEXTCOLOR',     (0,1), (-1,1), MED_GREY),
        ('FONTSIZE',      (0,1), (-1,1), 7.5),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LINEAFTER',     (0,0), (-2,1), 0.5, HexColor('#2d5986')),
    ]))
    elems.append(kpi_tbl)
    elems.append(Spacer(1, 6*mm))

    # Classification notice
    notice_text = (
        'This report constitutes the official findings of a forensic examination conducted on '
        'digital evidence obtained from the subject organisation\'s enterprise infrastructure. '
        'The examination was conducted in accordance with ISO/IEC 27037:2012 standards for '
        'digital evidence handling, and the findings are presented for judicial and investigative '
        'purposes. Unauthorised disclosure of this document is prohibited under the Information '
        'Technology Act, 2000.'
    )
    elems.append(Paragraph(notice_text,
                           ParagraphStyle('notice', fontSize=8, leading=12,
                                          textColor=HexColor('#555'), alignment=TA_JUSTIFY,
                                          borderPad=6, backColor=LIGHT_GREY, borderWidth=1,
                                          borderColor=MED_GREY)))
    elems.append(PageBreak())
    return elems


# ─────────────────────────────────────────────
# TOC
# ─────────────────────────────────────────────
def build_toc(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('TOC', 'TABLE OF CONTENTS', styles))
    elems.append(Spacer(1, 4*mm))

    toc = [
        ('I',   'Executive Summary', '3'),
        ('II',  'Case Identification & Background', '4'),
        ('III', 'Description of Evidence & Chain of Custody', '4'),
        ('IV',  'Forensic Methodology & Tools', '5'),
        ('V',   'Statistical & Graphical Analysis', '6'),
        ('VI',  'Brute Force Attack — Detailed Analysis', '8'),
        ('VII', 'Log Tampering — Detailed Analysis', '9'),
        ('VIII','Lateral Movement — Detailed Analysis', '10'),
        ('IX',  'Privilege Escalation — Detailed Analysis', '11'),
        ('X',   'Malicious Service Installation — Analysis', '12'),
        ('XI',  'Host Compromise Matrix', '13'),
        ('XII', 'Attack Chain Reconstruction', '14'),
        ('XIII','Indicator of Compromise (IOC) Register', '15'),
        ('XIV', 'Threat Actor Profile & Attribution', '16'),
        ('XV',  'Risk Heat Map — Host × Technique Exposure', '17'),
        ('XVI', 'MITRE ATT&CK Framework Coverage', '18'),
        ('XVII','Remediation Recommendations', '19'),
        ('XVIII','Expert Opinion & Conclusion', '21'),
        ('XIX', 'Annexure A — Forensic Environment Specification', '22'),
        ('XX',  'Annexure B — Extended Event Log Samples', '23'),
        ('XXI', 'Annexure C — Glossary of Terms', '27'),
    ]
    for num, title, page in toc:
        row = Table(
            [[Paragraph(f'<b>{num}</b>', styles['body']),
              Paragraph(title, styles['toc']),
              Paragraph(page, ParagraphStyle('pg', fontSize=9, alignment=TA_RIGHT))]],
            colWidths=[15*mm, W - 30*mm, 15*mm]
        )
        row.setStyle(TableStyle([
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LINEBELOW', (0,0), (-1,0), 0.3, MED_GREY),
        ]))
        elems.append(row)
    elems.append(PageBreak())
    return elems


# ─────────────────────────────────────────────
# MAIN CONTENT SECTIONS
# ─────────────────────────────────────────────
def build_executive_summary(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('I', 'EXECUTIVE SUMMARY', styles))
    elems.append(Spacer(1, 3*mm))

    intro = (
        'On 14 March 2026, automated monitoring systems within the Sentinal-X Digital Forensic '
        'Platform triggered a <b>Critical severity alert</b> upon detecting anomalous patterns '
        'across the enterprise infrastructure of TechCorp Solutions Pvt. Ltd. A total of '
        '<b>148,320 log entries</b> spanning <b>17 hosts</b> were collected and subjected to '
        'rigorous forensic analysis.'
    )
    elems.append(Paragraph(intro, styles['body']))
    elems.append(Spacer(1, 2*mm))

    detail = (
        'The forensic examination conclusively establishes that the organisation was subjected '
        'to a multi-stage <b>Advanced Persistent Threat (APT)-style cyber intrusion</b> lasting '
        'approximately <b>5.2 hours</b>, commencing at approximately <b>23:55 UTC on 13 March 2026</b> '
        'and concluding at <b>05:09 UTC on 14 March 2026</b>. The intrusion followed the classical '
        'Cyber Kill Chain model, progressing through Initial Access, Credential Theft, Defense '
        'Evasion, Lateral Movement, Privilege Escalation, and Persistence phases.'
    )
    elems.append(Paragraph(detail, styles['body']))
    elems.append(Spacer(1, 2*mm))

    findings = [
        ('Finding 1', 'Brute-force credential stuffing against CORP-VPN-01 commenced at 23:58 UTC, '
         'generating 38,440 failed authentication events before achieving successful access at 00:44 UTC.'),
        ('Finding 2', 'Log Tampering (Security Audit Log Cleared) was systematically executed across 5 '
         'hosts within a 12-minute window (02:11–02:22 UTC), confirming deliberate anti-forensic intent.'),
        ('Finding 3', 'Compromised service account svc_backup was used to authenticate across 9 distinct '
         'hosts in 12 minutes — a 680% deviation from established behavioural baseline.'),
        ('Finding 4', 'Privilege escalation via PowerShell with encoded payloads was observed on '
         'CORP-WKSTN-47 and CORP-DC-01, consistent with MITRE ATT&CK T1059.001.'),
        ('Finding 5', 'Two persistence mechanisms were established via malicious services '
         '(WinDefndr32 and svc_upd8) employing name-squatting techniques to evade detection.'),
        ('Finding 6', 'Command-and-Control beaconing to 45.142.212.100 (Russia, AS205100) was '
         'established at 03:33 UTC and active for 53 minutes before network termination.'),
    ]
    for key, val in findings:
        elems.append(Paragraph(f'• <b>{key}:</b> {val}', styles['bullet']))

    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        '<b>Immediate action is required:</b> The affected hosts must be forensically isolated, '
        'credentials rotated, and all identified IOCs blocked at the perimeter. '
        'A full rebuild of compromised systems from verified golden images is mandated.',
        ParagraphStyle('alert', backColor=HexColor('#fde8e8'), borderPad=5, borderRadius=3,
                       borderWidth=1, borderColor=CRITICAL, fontSize=8.5, leading=13,
                       textColor=HexColor('#7f1d1d'))
    ))
    elems.append(PageBreak())
    return elems


def build_case_identification(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('II', 'CASE IDENTIFICATION & BACKGROUND', styles))
    elems.append(Spacer(1, 3*mm))

    ci_data = [
        ['Field', 'Value'],
        ['Laboratory Case Number', 'FSL-DF-2026-0314'],
        ['Investigating Agency', 'National Cyber Crime Investigation Cell'],
        ['Subject Organisation', 'TechCorp Solutions Pvt. Ltd.'],
        ['Date of Evidence Receipt', '2026-03-14'],
        ['Date of Examination', '2026-03-14 to 2026-03-15'],
        ['Subject Assets', '17 Enterprise Workstations & Servers'],
        ['Examination Scope', 'Malicious Pattern Detection, Breach Reconstruction, IOC Extraction'],
        ['Total Log Entries', '148,320'],
        ['Aggregate Risk Score', '94,700'],
        ['Examining Engine', 'Sentinal-X Engine v2.4.1'],
        ['Examining Officer', 'Dr. A. Sharma, CHFI, GCFE'],
        ['Authorising Officer', 'DIG Cybercrime, National Investigation Cell'],
        ['Report Classification', 'RESTRICTED — OFFICIAL USE ONLY'],
    ]
    elems.append(styled_table(ci_data, [70*mm, W - 70*mm]))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'The subject organisation operates a mixed Windows Server 2019/2022 and Windows 11 endpoint '
        'infrastructure comprising a domain controller, file servers, database servers, web servers, '
        'and end-user workstations. The organisation processes sensitive financial and HR data, '
        'elevating the criticality of the observed breach.',
        styles['body']))

    elems.append(Spacer(1, 5*mm))
    elems.append(SectionHeader('III', 'DESCRIPTION OF EVIDENCE & CHAIN OF CUSTODY', styles))
    elems.append(Spacer(1, 3*mm))

    coc_data = [
        ['Exhibit', 'Category', 'Format', 'Integrity', 'Source', 'Remarks'],
        ['E-01', 'Windows Security Logs (EVTX)', 'JSON (parsed)', 'SHA-256 Verified',
         'Sentinal-X Collector', 'Primary evidence corpus'],
        ['E-02', 'Correlation Metadata', 'JSON', 'MD5 Verified',
         'Automated Attribution', 'Event relationship mapping'],
        ['E-03', 'Network Flow Logs', 'PCAP (partial)', 'SHA-256 Verified',
         'Perimeter Firewall', 'C2 traffic identification'],
        ['E-04', 'Registry Hive Snapshots', 'REG/JSON', 'SHA-256 Verified',
         'Live Forensic Acquisition', 'Persistence artifact recovery'],
    ]
    cw = [W/6]*6
    elems.append(styled_table(coc_data, cw, font_size=7))
    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        'Chain of custody was maintained throughout: all exhibits were acquired using write-blocked '
        'hardware (Tableau TX1), hashed immediately upon acquisition, and stored in encrypted '
        'forensic containers (AES-256). Access log maintained per ISO/IEC 27037:2012, Clause 7.3.',
        styles['body']))
    elems.append(PageBreak())
    return elems


def build_methodology(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('IV', 'FORENSIC METHODOLOGY & TOOLS', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'The examination was conducted following internationally recognised digital forensic '
        'standards. The procedural framework combines signature-based detection with unsupervised '
        'machine learning to ensure comprehensive coverage of both known and novel attack patterns.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    methods = [
        ('Evidence Acquisition & Integrity Verification',
         'Raw EVTX log data was extracted via Windows Event Forwarding (WEF) and verified using '
         'SHA-256 hashing. All original exhibits were write-protected prior to processing. Forensic '
         'working copies were created for analysis, maintaining original evidence integrity per '
         'ISO/IEC 27037 Clause 7.3.'),
        ('Data Normalisation & Parsing',
         'Raw CSV/EVTX data was mapped to standardised forensic fields using Sentinal-X '
         'normalisation pipeline v2.4.1. Event timestamps were normalised to UTC. Unicode encoding '
         'issues were resolved during ingestion. Final normalised dataset: 148,320 events across '
         '47 field types.'),
        ('Signature-Based Detection',
         'A library of 2,847 forensic signatures was applied against the normalised dataset, '
         'targeting known Windows event patterns associated with MITRE ATT&CK techniques. Signatures '
         'include EID-based rules, temporal correlation rules, and cross-host behavioural signatures.'),
        ('Behavioural Baseline Analysis',
         '30-day historical baseline was established per user account, host, and service. Statistical '
         'deviation thresholds (>3σ from mean) were applied to identify anomalous activity. '
         'svc_backup lateral movement (680% above baseline) and brute force volume (>430 '
         'attempts/min) were identified through this mechanism.'),
        ('Unsupervised Machine Learning (Isolation Forest)',
         'sklearn Isolation Forest (contamination=0.05, n_estimators=200) was applied to the full '
         'event feature matrix to identify anomalies beyond signature coverage. This technique '
         'confirmed all 5 primary finding categories and identified 3 secondary anomalies.'),
        ('Timeline Synthesis & Attack Chain Reconstruction',
         'Chronological event sequencing was performed across all hosts to reconstruct the complete '
         'attack timeline. Cross-host event correlation (±5 minute windows) identified the lateral '
         'movement propagation path and confirmed the kill chain progression.'),
        ('IOC Extraction & Threat Intelligence Enrichment',
         'Indicators of Compromise (IPs, file hashes, domain names, registry keys) were extracted '
         'and enriched against VirusTotal, Shodan, and internal threat intelligence feeds. Two '
         'external IPs and two file hashes returned confirmed malicious verdicts.'),
    ]
    for heading, body in methods:
        meth_data = [[Paragraph(f'<b>{heading}</b>',
                                ParagraphStyle('mh', fontName='Helvetica-Bold', fontSize=8,
                                               textColor=DARK_BLUE)),
                      Paragraph(body, styles['body'])]]
        mt = Table(meth_data, colWidths=[55*mm, W - 55*mm])
        mt.setStyle(TableStyle([
            ('VALIGN',  (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LINEBELOW', (0,0), (-1,0), 0.3, MED_GREY),
        ]))
        elems.append(mt)

    elems.append(Spacer(1, 3*mm))
    tools_data = [
        ['Tool', 'Version', 'Category', 'Forensic Purpose'],
        ['Sentinal-X Core', 'v2.4.1', 'Correlation Engine', 'Primary log correlation & alerting'],
        ['sklearn Isolation Forest', '1.4.2', 'ML / Anomaly', 'Unsupervised anomaly validation'],
        ['Matplotlib / Seaborn', '3.10', 'Visualisation', 'Evidence chart generation'],
        ['ReportLab Platypus', '4.4', 'Report Gen', 'Judicial report formatting'],
        ['Pandas / NumPy', '2.2', 'Data Analysis', 'Statistical normalisation'],
        ['Tableau TX1 (HW)', '—', 'Acquisition', 'Write-blocked evidence acquisition'],
        ['VirusTotal API', 'v3', 'TI Enrichment', 'Hash and IP reputation lookup'],
        ['Shodan API', 'v1', 'TI Enrichment', 'External IP intelligence'],
    ]
    cw = [55*mm, 20*mm, 35*mm, W - 110*mm]
    elems.append(styled_table(tools_data, cw, font_size=7.5))
    elems.append(PageBreak())
    return elems


def build_statistical_analysis(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('V', 'STATISTICAL & GRAPHICAL ANALYSIS', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'Comprehensive statistical processing of Exhibits E-01 through E-04 reveals a high-risk '
        'environment with clear indicators of a coordinated, multi-stage cyber intrusion. The '
        'following analytical figures present the threat landscape across four dimensions: event '
        'frequency, risk distribution, temporal activity, and host exposure.',
        styles['body']))
    elems.append(Spacer(1, 3*mm))

    # Fig 1
    fig1 = make_dashboard_fig()
    elems.append(fig_to_image(fig1, W, 80*mm))
    elems.append(Paragraph(
        'Fig. 1 — Three-panel threat intelligence dashboard derived from Exhibits E-01 and E-02.',
        styles['caption']))
    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        '<b>Fig. 1 Interpretation:</b> The horizontal bar chart confirms Brute Force as the '
        'highest-volume technique (38,440 events), consistent with automated credential-stuffing '
        'tooling. The risk-score donut reveals that Log Tampering accounts for the largest share '
        '(30.5%) despite lower event count, confirming high-value anti-forensic activity. The '
        'bubble scatter positions Log Tampering and Lateral Movement in the critical upper-right '
        'quadrant — the primary indicators of compromise.',
        ParagraphStyle('interp', backColor=HexColor('#dbeafe'), borderPad=5,
                       fontSize=8, leading=12, alignment=TA_JUSTIFY)))
    elems.append(Spacer(1, 4*mm))

    # Fig 2
    fig2 = make_timeline_fig()
    elems.append(fig_to_image(fig2, W, 65*mm))
    elems.append(Paragraph(
        'Fig. 2 — 24-hour event distribution by technique across six 4-hour windows.',
        styles['caption']))
    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        '<b>Fig. 2 Interpretation:</b> Attack activity peaks during the 00:00–04:00 UTC window, '
        'consistent with threat actors exploiting reduced monitoring periods. Brute Force activity '
        'begins prior to midnight, followed by Log Tampering and Lateral Movement post-02:00, '
        'confirming the progressive kill chain execution order: Initial Access → Defense Evasion '
        '→ Lateral Movement.',
        ParagraphStyle('interp2', backColor=HexColor('#dbeafe'), borderPad=5,
                       fontSize=8, leading=12, alignment=TA_JUSTIFY)))
    elems.append(PageBreak())

    # Fig 3
    fig3 = make_brute_force_fig()
    elems.append(fig_to_image(fig3, W, 65*mm))
    elems.append(Paragraph(
        'Fig. 3 — Hourly brute-force attempt distribution across 2026-03-13/14 (EID 4625). '
        'Red bars exceed 500-attempt alert threshold.',
        styles['caption']))
    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        '<b>Fig. 3 Interpretation:</b> Failed logon attempts spike sharply at 00:00–02:00 UTC, '
        'with a peak rate of approximately 1,200 attempts/hour at 01:00 UTC. The pattern is '
        'consistent with automated credential-stuffing tooling (not manual brute-force), as the '
        'attempt rate is sustained and rhythmic. The successful authentication event at 00:44 UTC '
        '(not shown) occurs after a brief lull, suggesting the adversary paused to avoid account '
        'lockout before attempting the final valid credential.',
        ParagraphStyle('interp3', backColor=HexColor('#dbeafe'), borderPad=5,
                       fontSize=8, leading=12, alignment=TA_JUSTIFY)))
    elems.append(Spacer(1, 4*mm))

    # Statistical summary table
    elems.append(Paragraph('<b>Statistical Summary — Detected Anomaly Categories</b>',
                            styles['heading2']))
    elems.append(Spacer(1, 2*mm))
    summary_data = [
        ['Technique', 'EID', 'Event Count', 'Risk Score', 'Severity', 'MITRE Tactic', 'Technique ID'],
    ]
    for i in range(len(TECHNIQUES)):
        summary_data.append([
            TECHNIQUES[i], EIDS[i], f'{EVENT_COUNTS[i]:,}', f'{RISK_SCORES[i]:,}',
            SEVERITIES[i], MITRE_TACTICS[i], TECHNIQUE_IDS[i]
        ])
    cw = [40*mm, 13*mm, 22*mm, 22*mm, 20*mm, 35*mm, 22*mm]
    sev_rows = {'CRITICAL': CRITICAL, 'HIGH': HIGH, 'MEDIUM': MEDIUM}
    base_style = [
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('TEXTCOLOR',  (0,0), (-1,0), white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 7.5),
        ('LEADING',    (0,0), (-1,-1), 10.5),
        ('ALIGN',      (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, STRIPE]),
        ('GRID',       (0,0), (-1,-1), 0.3, MED_GREY),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]
    for row_i, sev in enumerate(SEVERITIES, start=1):
        col = sev_rows.get(sev, MED_GREY)
        base_style.append(('TEXTCOLOR', (4, row_i), (4, row_i), col))
        base_style.append(('FONTNAME',  (4, row_i), (4, row_i), 'Helvetica-Bold'))
    st = Table(summary_data, colWidths=cw)
    st.setStyle(TableStyle(base_style))
    elems.append(st)
    elems.append(PageBreak())
    return elems


# ─────────────────────────────────────────────
# AI / Markdown → ReportLab (shared by scan PDF + finding narratives)
# ─────────────────────────────────────────────
def _md_block_to_para_xml(block: str) -> str:
    """Escape XML, then turn **bold** into <b>…</b>."""
    t = block.strip()
    if not t:
        return ''
    e = escape(t)
    return re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', e)


def _clean_md_title(fragment: str) -> str:
    s = fragment.strip()
    s = re.sub(r'^#+\s*', '', s)
    s = re.sub(r'^[■\u25a0●\-\s]+', '', s)
    return s.strip()


def _line_is_undetermined_only(line: str) -> bool:
    plain = re.sub(r'[*_`]', '', line).strip().lower()
    if not plain:
        return True
    return bool(re.match(r'^status:?\s*undetermined\.?$', plain))


def _should_skip_undetermined_section(body_lines: list[str]) -> bool:
    """Drop AI subsections that only say Status: Undetermined (no usable detail)."""
    non_empty = [ln.strip() for ln in body_lines if ln.strip()]
    if not non_empty:
        return True
    return all(_line_is_undetermined_only(ln) for ln in non_empty)


def _split_ai_briefing_sections(text: str):
    """
    (level, title_or_none, raw_body_lines). level 0 = preamble before any # heading.
    """
    lines = text.replace('\r\n', '\n').split('\n')
    sections: list[tuple[int, str | None, list[str]]] = []
    preamble: list[str] = []
    i = 0
    n = len(lines)

    def flush_preamble():
        if any(x.strip() for x in preamble):
            sections.append((0, None, preamble[:]))
        preamble.clear()

    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped:
            preamble.append(raw)
            i += 1
            continue
        m = re.match(r'^(#{1,3})\s+(.*)$', stripped)
        if not m:
            preamble.append(raw)
            i += 1
            continue
        flush_preamble()
        level = len(m.group(1))
        title = _clean_md_title(m.group(2))
        i += 1
        body: list[str] = []
        while i < n:
            s2 = lines[i].strip()
            if s2 and re.match(r'^#{1,3}\s+', s2):
                break
            body.append(lines[i])
            i += 1
        sections.append((level, title, body))

    flush_preamble()
    return sections


def _render_body_lines_as_flowables(body_lines: list[str], styles: dict) -> list:
    """Turn body lines into Paragraphs; merge plain lines, bullets separate."""
    flowables = []
    body = styles['body']
    bullet = styles['bullet']
    buf: list[str] = []

    def flush_buf():
        if not buf:
            return
        para = '\n'.join(buf).strip()
        buf.clear()
        if not para:
            return
        xml = _md_block_to_para_xml(para).replace('\n', '<br/>')
        flowables.append(Paragraph(xml, body))

    for raw in body_lines:
        stripped = raw.strip()
        if not stripped:
            flush_buf()
            continue
        if re.match(r'^[-*]\s+', stripped):
            flush_buf()
            content = re.sub(r'^[-*]\s+', '', stripped)
            xml = _md_block_to_para_xml(content)
            flowables.append(Paragraph(f'• {xml}', bullet))
        elif re.match(r'^\d+\.\s+', stripped):
            flush_buf()
            content = re.sub(r'^\d+\.\s+', '', stripped)
            xml = _md_block_to_para_xml(content)
            flowables.append(Paragraph(f'• {xml}', bullet))
        else:
            buf.append(stripped)
    flush_buf()
    return flowables


def _scan_ai_briefing_flowables(text: str, styles: dict) -> list:
    """Executive / scan-level AI text: no raw # or ** in PDF; skip empty/undetermined blocks."""
    if not text or not str(text).strip():
        return [Paragraph('<i>No executive briefing stored.</i>', styles['body'])]
    sections = _split_ai_briefing_sections(text)
    out: list = []
    body_style = styles['body']
    h2 = styles['heading2']
    bb = styles['body_bold']
    for level, title, body_lines in sections:
        if level == 0:
            bl = list(body_lines)
            while bl and not bl[0].strip():
                bl.pop(0)
            while bl and not bl[-1].strip():
                bl.pop()
            if not any(x.strip() for x in bl):
                continue
            out.extend(_render_body_lines_as_flowables(bl, styles))
            continue
        if title and _should_skip_undetermined_section(body_lines):
            continue
        t_xml = _md_block_to_para_xml(title or '')
        if level == 1:
            out.append(Spacer(1, 2 * mm))
            out.append(Paragraph(t_xml, h2))
        elif level == 2:
            out.append(Spacer(1, 1.5 * mm))
            out.append(Paragraph(t_xml, h2))
        else:
            out.append(Spacer(1, 1 * mm))
            out.append(Paragraph(t_xml, bb))
        out.extend(_render_body_lines_as_flowables(body_lines, styles))
    if not out:
        return [Paragraph('<i>No executive briefing stored.</i>', body_style)]
    return out


def _forensic_analysis_flowables(analysis_text, styles: dict) -> list:
    """Category ai_summary: same markdown handling as executive body."""
    if not (analysis_text or '').strip():
        return [
            Paragraph('<b>Forensic Analysis:</b>', styles['body_bold']),
            Spacer(1, 1 * mm),
            Paragraph('<i>No narrative stored.</i>', styles['body']),
        ]
    lines = analysis_text.replace('\r\n', '\n').split('\n')
    out = [
        Paragraph('<b>Forensic Analysis:</b>', styles['body_bold']),
        Spacer(1, 1 * mm),
    ]
    out.extend(_render_body_lines_as_flowables(lines, styles))
    return out


def build_finding_section(num, roman, title, eid, count, risk, tactic, tid, hosts_str,
                           severity, analysis_text, log_rows, styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader(roman, title.upper(), styles))
    elems.append(Spacer(1, 2*mm))
    elems.append(FindingBox(severity, title, count, risk, tactic, tid, hosts_str, W))
    elems.append(Spacer(1, 2*mm))

    # affected hosts line
    elems.append(
        Paragraph(
            f'<b>Affected Hosts:</b> {escape(str(hosts_str))}',
            styles['body_bold'],
        )
    )
    elems.append(Spacer(1, 1 * mm))
    elems.extend(_forensic_analysis_flowables(analysis_text, styles))
    elems.append(Spacer(1, 2 * mm))

    # event log table
    log_data = [['Timestamp', 'Host', 'User', 'EID', 'Event Detail']] + log_rows
    cw = [42*mm, 30*mm, 22*mm, 12*mm, W - 106*mm]
    elems.append(styled_table(log_data, cw, font_size=7))
    elems.append(Spacer(1, 4*mm))
    return elems


def build_detailed_findings(styles):
    elems = []

    # VI Brute Force
    elems += build_finding_section(
        6, 'VI', 'Brute Force Attack — Detailed Analysis',
        '4625', 38440, 19200, 'Credential Access', 'T1110.003',
        'CORP-VPN-01, CORP-MAIL-01', 'HIGH',
        '38,440 failed logon events (EID 4625) were recorded against CORP-VPN-01 and CORP-MAIL-01 '
        'over a 47-minute window. The attempt rate peaked at 1,200/hour at 01:00 UTC, consistent '
        'with the Hydra or Medusa credential-stuffing toolset operating against the Windows '
        'NLA/RDP service. Source IPs 185.220.101.47 (known Tor exit node) and 45.142.212.100 '
        '(Russian hosting) were the primary origination points, suggesting the adversary used '
        'anonymisation infrastructure. Successful authentication (EID 4624) was achieved at '
        '00:44 UTC for user "admin" — the credential was likely obtained from a prior data breach '
        'or phishing campaign, with the brute-force phase serving to identify the valid username '
        'format. No MFA was enforced on the VPN gateway, enabling direct credential reuse.',
        [
            ['2026-03-13 23:58:01', 'CORP-VPN-01', 'admin', '4625', 'Account lockout threshold nearing'],
            ['2026-03-14 00:04:17', 'CORP-VPN-01', 'svc_backup', '4625', 'Multiple failures'],
            ['2026-03-14 00:09:42', 'CORP-MAIL-01', 'jdoe', '4625', 'Repeated authentication failures'],
            ['2026-03-14 00:44:58', 'CORP-VPN-01', 'admin', '4624', 'Successful logon post-brute-force'],
        ], styles)

    # VII Log Tampering
    elems += build_finding_section(
        7, 'VII', 'Log Tampering — Detailed Analysis',
        '1102', 4821, 28900, 'Defense Evasion', 'T1070.001',
        'CORP-DC-01, CORP-WEB-03, CORP-FS-02, CORP-WKSTN-47, CORP-DB-01', 'CRITICAL',
        'Systematic deletion of Windows Security Event Logs (EID 1102 — "The audit log was '
        'cleared") was recorded across 5 hosts within a 12-minute window (02:11–02:22 UTC). '
        'The targeted hosts correspond precisely to hosts accessed during the lateral movement '
        'phase, confirming that log clearing was executed immediately after lateral pivot to each '
        'host. This temporal correlation (average delay of 2.4 minutes between lateral movement '
        'and log clearing on each host) is characteristic of an automated post-exploitation script. '
        'Despite this, forensic artefacts were recovered from backup event log stores and Windows '
        'Event Forwarding infrastructure, enabling full reconstruction of the attack chain.',
        [
            ['2026-03-14 02:11:43', 'CORP-DC-01', 'SYSTEM', '1102', 'Security Audit Log Cleared'],
            ['2026-03-14 02:13:17', 'CORP-WEB-03', 'SYSTEM', '1102', 'Security Audit Log Cleared'],
            ['2026-03-14 02:14:05', 'CORP-FS-02', 'SYSTEM', '1102', 'Security Audit Log Cleared'],
            ['2026-03-14 02:18:33', 'CORP-WKSTN-47', 'SYSTEM', '1102', 'Security Audit Log Cleared'],
            ['2026-03-14 02:22:41', 'CORP-DB-01', 'SYSTEM', '1102', 'Security Audit Log Cleared'],
        ], styles)

    # VIII Lateral Movement
    elems += build_finding_section(
        8, 'VIII', 'Lateral Movement — Detailed Analysis',
        '4624', 2104, 24600, 'Lateral Movement', 'T1021.001',
        'CORP-FS-02, CORP-DB-01, CORP-WKSTN-47, CORP-HR-01, CORP-FIN-01', 'CRITICAL',
        'Compromised service account "svc_backup" authenticated to 9 distinct hosts via network '
        'logon (Type 3) within a 12-minute window between 02:44 and 02:56 UTC. The baseline '
        'authentication frequency for svc_backup was established at 1–2 hosts/hour during '
        'scheduled backup windows (03:00–04:00 UTC, Monday–Friday). The observed pattern of '
        '9 hosts in 12 minutes represents a 680% deviation from this baseline. The propagation '
        'path (VPN → DC → FS-02 → DB-01 → HR-01 → FIN-01) follows a deliberate target '
        'prioritisation strategy, with high-value data repositories accessed first. Pass-the-Hash '
        '(PtH) or Pass-the-Ticket (PtT) technique is suspected given that no corresponding '
        'credential prompts were observed prior to the network logon events.',
        [
            ['2026-03-14 02:45:09', 'CORP-FS-02', 'svc_backup', '4624', 'Logon Type 3 - Network'],
            ['2026-03-14 02:46:22', 'CORP-DB-01', 'svc_backup', '4624', 'Logon Type 3 - Network'],
            ['2026-03-14 02:47:55', 'CORP-HR-01', 'svc_backup', '4624', 'Logon Type 3 - Network'],
            ['2026-03-14 02:51:03', 'CORP-FIN-01', 'svc_backup', '4624', 'Logon Type 3 - Network'],
        ], styles)

    # IX Privilege Escalation
    elems += build_finding_section(
        9, 'IX', 'Privilege Escalation — Detailed Analysis',
        '4688', 873, 18700, 'Privilege Escalation', 'T1059.001',
        'CORP-WKSTN-47, CORP-DC-01', 'HIGH',
        'User account "jdoe" generated 873 abnormal process creation events (EID 4688) on '
        'CORP-WKSTN-47 and CORP-DC-01 between 03:02 and 03:22 UTC. Key indicators include: '
        '(1) cmd.exe spawned from non-interactive session (lsass.exe parent process) — consistent '
        'with credential dumping via Mimikatz sekurlsa::logonpasswords; (2) powershell.exe '
        'executed with -EncodedCommand parameter containing Base64 payload (decoded: '
        'Invoke-WebRequest to download svhost32.exe from 45.142.212.100); (3) net.exe executed '
        'with "user /add" and "localgroup administrators /add" arguments, creating a backdoor '
        'administrator account "helpdesk99"; (4) whoami.exe and systeminfo.exe executed '
        '(reconnaissance commands). The jdoe account was originally a standard user — the '
        'escalation to Domain Admin privileges was achieved via UAC bypass on CORP-DC-01.',
        [
            ['2026-03-14 03:02:11', 'CORP-WKSTN-47', 'jdoe', '4688', 'cmd.exe spawned from non-interactive session'],
            ['2026-03-14 03:04:33', 'CORP-WKSTN-47', 'jdoe', '4688', 'powershell.exe with encoded payload'],
            ['2026-03-14 03:11:47', 'CORP-DC-01', 'jdoe', '4688', 'net.exe user /add executed'],
        ], styles)

    # X Malicious Service
    elems += build_finding_section(
        10, 'X', 'Malicious Service Installation — Analysis',
        '7045', 312, 3300, 'Persistence', 'T1543.003',
        'CORP-WKSTN-47, CORP-FS-02', 'MEDIUM',
        '312 service installation events (EID 7045) were recorded across CORP-WKSTN-47 and '
        'CORP-FS-02. Two distinct malicious services were identified: (1) "WinDefndr32" — '
        'installed from C:\\Windows\\Temp\\svhost32.exe (SHA-256: a3f2c1d9e4b7...), a known '
        'Remote Access Trojan (RAT) dropper confirmed malicious by VirusTotal (68/72 vendors). '
        'The service name employs typosquatting of "Windows Defender" to evade administrator '
        'review. (2) "svc_upd8" — installed from C:\\ProgramData\\upd8.ps1 (SHA-256: '
        '7e1d4a8b2c6f...), a PowerShell-based C2 beacon communicating with update-win32.ru via '
        'HTTPS on port 443. Both services were configured for automatic start, ensuring '
        'persistence across reboots.',
        [
            ['2026-03-14 03:14:55', 'CORP-WKSTN-47', 'SYSTEM', '7045', "Service 'WinDefndr32' installed"],
            ['2026-03-14 03:16:08', 'CORP-FS-02', 'SYSTEM', '7045', "Service 'svc_upd8' installed"],
        ], styles)

    elems.append(PageBreak())
    return elems


def build_host_compromise_matrix(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('XI', 'HOST COMPROMISE MATRIX', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'The following matrix summarises the compromise status of each host identified within '
        'the scope of the forensic examination. Severity is based on the aggregate risk of '
        'confirmed techniques observed on each host.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    hcm_data = [
        ['Hostname', 'Role', 'OS', 'Severity', 'Techniques Observed', 'Action Required'],
        ['CORP-DC-01', 'Domain Controller', 'Windows Server 2022', 'CRITICAL',
         'Log Tampering, Privilege Escalation', 'ISOLATE IMMEDIATELY — Full Rebuild Required'],
        ['CORP-VPN-01', 'VPN Gateway', 'Windows Server 2019', 'CRITICAL',
         'Brute Force, Initial Access', 'ISOLATE IMMEDIATELY — Full Rebuild Required'],
        ['CORP-FS-02', 'File Server', 'Windows Server 2019', 'HIGH',
         'Log Tampering, Lateral Movement, Svc Install', 'Isolate — Forensic Imaging Then Rebuild'],
        ['CORP-DB-01', 'Database Server', 'Windows Server 2022', 'HIGH',
         'Log Tampering, Lateral Movement', 'Isolate — Forensic Imaging Then Rebuild'],
        ['CORP-WEB-03', 'Web Server', 'Windows Server 2019', 'HIGH',
         'Log Tampering', 'Isolate — Forensic Imaging Then Rebuild'],
        ['CORP-WKSTN-47', 'Workstation', 'Windows 11 Pro', 'HIGH',
         'Privilege Escalation, Svc Install, Lateral Movement', 'Isolate — Forensic Imaging Then Rebuild'],
        ['CORP-HR-01', 'HR Workstation', 'Windows 11 Pro', 'MEDIUM',
         'Lateral Movement', 'Monitor — Credential Rotation Required'],
        ['CORP-FIN-01', 'Finance Workstation', 'Windows 11 Pro', 'MEDIUM',
         'Lateral Movement', 'Monitor — Credential Rotation Required'],
        ['CORP-MAIL-01', 'Mail Server', 'Windows Server 2019', 'MEDIUM',
         'Brute Force (targeted)', 'Monitor — Credential Rotation Required'],
    ]
    cw = [32*mm, 28*mm, 32*mm, 20*mm, 45*mm, W - 157*mm]
    sev_map = {'CRITICAL': CRITICAL, 'HIGH': HIGH, 'MEDIUM': MEDIUM}
    hcm_style = [
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('TEXTCOLOR',  (0,0), (-1,0), white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 7),
        ('LEADING',    (0,0), (-1,-1), 10),
        ('ALIGN',      (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, STRIPE]),
        ('GRID',       (0,0), (-1,-1), 0.3, MED_GREY),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]
    for row_i, row in enumerate(hcm_data[1:], start=1):
        sev = row[3]
        col = sev_map.get(sev, MED_GREY)
        hcm_style += [
            ('TEXTCOLOR', (3, row_i), (3, row_i), col),
            ('FONTNAME',  (3, row_i), (3, row_i), 'Helvetica-Bold'),
        ]
    tbl = Table(hcm_data, colWidths=cw)
    tbl.setStyle(TableStyle(hcm_style))
    elems.append(tbl)
    elems.append(PageBreak())
    return elems


def build_attack_chain(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('XII', 'ATTACK CHAIN RECONSTRUCTION', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'The following reconstruction synthesises all forensic findings into a unified attack '
        'narrative. Events are correlated across hosts and time to establish the complete '
        'adversary kill chain.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    fig4 = make_gantt_fig()
    elems.append(fig_to_image(fig4, W, 70*mm))
    elems.append(Paragraph(
        'Fig. 4 — Attack kill chain temporal progression (Gantt) across UTC hours.',
        styles['caption']))
    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        '<b>Kill Chain Analysis:</b> The adversary\'s operational timeline spans 5.2 hours across '
        '7 distinct phases. Initial Access was achieved via credential stuffing (23:58–00:44 UTC). '
        'A 95-minute dwell period (00:44–02:19 UTC) preceded active exploitation, suggesting a '
        'reconnaissance phase. Defense Evasion (log clearing) commenced at 02:11 UTC immediately '
        'before lateral movement at 02:44, confirming a planned sequence. C2 beaconing at 03:33 '
        'UTC indicates data exfiltration may have commenced.',
        ParagraphStyle('interp4', backColor=HexColor('#dbeafe'), borderPad=5,
                       fontSize=8, leading=12, alignment=TA_JUSTIFY)))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph('<b>Lateral Movement Propagation:</b>', styles['body_bold']))
    elems.append(Paragraph(
        'The compromised svc_backup account pivoted from the VPN gateway (initial access point) '
        'through the Domain Controller to access file, database, HR and finance servers. Each hop '
        'is evidenced by Type 3 network logon events (EID 4624) within the 02:44–02:56 UTC window.',
        styles['body']))
    elems.append(PageBreak())
    return elems


def build_ioc_register(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('XIII', 'INDICATOR OF COMPROMISE (IOC) REGISTER', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'The following Indicators of Compromise were extracted from forensic analysis of all '
        'exhibits and enriched via external threat intelligence feeds. All IOCs should be '
        'actioned immediately by the incident response team.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    ioc_data = [
        ['Type', 'Indicator', 'Description', 'Severity', 'First Seen', 'Context'],
        ['IP', '45.142.212.100', 'External C2 Server', 'HIGH', '2026-03-14 01:14', 'Geo: RU, ASN: AS205100'],
        ['IP', '185.220.101.47', 'TOR Exit Node', 'HIGH', '2026-03-13 23:55', 'Repeated VPN auth attempts'],
        ['HASH', 'a3f2c1d9e4b7...', 'WinDefndr32.exe', 'CRITICAL', '2026-03-14 03:14', 'SHA-256; known RAT dropper'],
        ['HASH', '7e1d4a8b2c6f...', 'svc_upd8.exe', 'HIGH', '2026-03-14 03:16', 'SHA-256; C2 beacon binary'],
        ['Domain', 'update-win32.ru', 'C2 Domain', 'CRITICAL', '2026-03-14 03:20', 'DNS query from CORP-WKSTN-47'],
        ['Account', 'svc_backup', 'Compromised SVC Acct', 'CRITICAL', '2026-03-14 02:44', 'Used for lateral movement'],
        ['Account', 'jdoe', 'Compromised User Acct', 'HIGH', '2026-03-14 03:02', 'Privilege escalation vector'],
        ['Registry', r'HKLM\...\WinDefndr32', 'Persistence Key', 'HIGH', '2026-03-14 03:15', 'Autorun entry created'],
        ['File', r'C:\Windows\Temp\svhost32.exe', 'Dropper Binary', 'CRITICAL', '2026-03-14 03:14', 'Masquerading as svchost'],
        ['File', r'C:\ProgramData\upd8.ps1', 'PowerShell Payload', 'HIGH', '2026-03-14 03:05', 'Encoded PS1 downloader'],
    ]
    cw = [18*mm, 38*mm, 35*mm, 18*mm, 27*mm, W - 136*mm]
    sev_map = {'CRITICAL': CRITICAL, 'HIGH': HIGH, 'MEDIUM': MEDIUM}
    ioc_style = [
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('TEXTCOLOR',  (0,0), (-1,0), white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 7),
        ('LEADING',    (0,0), (-1,-1), 10),
        ('ALIGN',      (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, STRIPE]),
        ('GRID',       (0,0), (-1,-1), 0.3, MED_GREY),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]
    for row_i, row in enumerate(ioc_data[1:], start=1):
        sev = row[3]
        col = sev_map.get(sev, MED_GREY)
        ioc_style += [
            ('TEXTCOLOR', (3, row_i), (3, row_i), col),
            ('FONTNAME',  (3, row_i), (3, row_i), 'Helvetica-Bold'),
        ]
    tbl = Table(ioc_data, colWidths=cw)
    tbl.setStyle(TableStyle(ioc_style))
    elems.append(tbl)
    elems.append(PageBreak())
    return elems


def build_threat_actor(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('XIV', 'THREAT ACTOR PROFILE & ATTRIBUTION', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'Based on the totality of forensic evidence, the following threat actor profile has been '
        'constructed. Attribution confidence levels are assessed per the MITRE ATT&CK attribution '
        'methodology. This profile is indicative rather than definitive and is provided to support '
        'law enforcement investigation.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    attr_data = [
        ['Attribute', 'Assessment'],
        ['Attribution Confidence', 'MEDIUM (65%) — Technical indicators sufficient; no human intelligence corroboration'],
        ['Suspected Origin', 'Eastern Europe (Russia/Ukraine region) — IP geolocation, C2 domain registration (.ru TLD)'],
        ['Actor Category', 'Financially Motivated Threat Actor — consistent with ransomware precursor TTPs'],
        ['Sophistication Level', 'MEDIUM-HIGH — Custom tooling, LOLBins usage, anti-forensic measures'],
        ['Primary Objectives', 'Data Exfiltration and/or Ransomware Deployment (C2 established prior to exfil)'],
        ['TTP Overlap', 'Partial overlap with FIN7 and APT41 documented techniques (ATT&CK Navigator)'],
        ['Tooling Identified', 'Mimikatz (credential dumping), custom RAT (WinDefndr32.exe), PS1 downloader'],
        ['Infrastructure', 'Hosted on bulletproof hosting (AS205100), TOR exit nodes for initial access obfuscation'],
        ['Operational Pattern', 'Off-hours operation (00:00–05:00 UTC), automated phases, minimal manual interaction'],
        ['Recommended Escalation', 'CERT-In, NCIIPC notification recommended; law enforcement referral warranted'],
    ]
    elems.append(styled_table(attr_data, [55*mm, W - 55*mm]))
    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        'The adversary demonstrated operational security awareness through: (1) use of '
        'anonymisation infrastructure for initial access, (2) immediate log clearing post-lateral '
        'movement, (3) use of legitimate service account credentials to blend with normal traffic, '
        '(4) C2 communication over HTTPS port 443 using legitimate-looking domain names.',
        styles['body']))
    elems.append(PageBreak())
    return elems


def build_risk_heat_map(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('XV', 'RISK HEAT MAP — HOST × TECHNIQUE EXPOSURE', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'The risk heat map below quantifies the exposure of each host to each detected threat '
        'technique, using a 1–10 normalised risk score. Cells are colour-coded from low risk '
        '(blue) through amber to critical (red). Empty cells indicate no confirmed exposure.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    fig5 = make_heat_map_fig()
    elems.append(fig_to_image(fig5, W, 70*mm))
    elems.append(Paragraph(
        'Fig. 5 — Normalised risk heat map: threat technique × host exposure matrix.',
        styles['caption']))
    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        '<b>Heat Map Interpretation:</b> CORP-DC-01 and CORP-WKSTN-47 exhibit the broadest '
        'technique exposure, confirming their status as the primary and secondary compromise '
        'pivots respectively. CORP-FS-02 and CORP-DB-01 show high lateral movement exposure, '
        'consistent with their roles as high-value data repositories.',
        ParagraphStyle('interp5', backColor=HexColor('#dbeafe'), borderPad=5,
                       fontSize=8, leading=12, alignment=TA_JUSTIFY)))
    elems.append(PageBreak())
    return elems


def build_mitre(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('XVI', 'MITRE ATT&CK FRAMEWORK COVERAGE', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'The following table maps all detected forensic findings to the MITRE ATT&CK Enterprise '
        'Framework (v14). Coverage spans 8 tactical categories and 16 individual techniques, '
        'confirming the multi-stage, full kill-chain nature of the intrusion.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    fig6 = make_mitre_fig()
    elems.append(fig_to_image(fig6, W, 65*mm))
    elems.append(Paragraph(
        'Fig. 6 — MITRE ATT&CK tactic coverage — techniques detected per tactic.',
        styles['caption']))
    elems.append(Spacer(1, 3*mm))

    mitre_data = [
        ['Tactic', 'Technique ID & Name', 'Confidence', 'Evidence Source'],
        ['TA0001 Initial Access', 'T1078 Valid Accounts', 'HIGH', 'E-01: EID 4624 post-brute-force'],
        ['', 'T1133 External Remote Services', 'MEDIUM', 'E-01: VPN gateway logon events'],
        ['TA0003 Persistence', 'T1543.003 Windows Service', 'MEDIUM', 'E-01: EID 7045; E-04: Registry hive'],
        ['', 'T1547.001 Registry Run Keys', 'MEDIUM', 'E-04: HKLM Run key artifact'],
        ['TA0004 Privilege Escalation', 'T1059.001 PowerShell', 'MEDIUM', 'E-01: EID 4688 PowerShell events'],
        ['', 'T1548.002 UAC Bypass', 'MEDIUM', 'E-01: UAC bypass process chain'],
        ['TA0005 Defense Evasion', 'T1070.001 Clear Windows Event Logs', 'HIGH', 'E-01: EID 1102 across 5 hosts'],
        ['', 'T1027 Obfuscated Files', 'HIGH', 'E-01: Base64 encoded PS1 payload'],
        ['TA0006 Credential Access', 'T1110.003 Password Spraying', 'MEDIUM', 'E-01: 38,440 EID 4625 events'],
        ['', 'T1003 OS Credential Dumping', 'MEDIUM', 'E-01: lsass.exe access pattern'],
        ['TA0008 Lateral Movement', 'T1021.001 Remote Desktop Protocol', 'HIGH', 'E-01: RDP logon Type 10 events'],
        ['', 'T1021.002 SMB/Windows Admin Shares', 'HIGH', 'E-01: SMB Type 3 logon events'],
        ['TA0011 Command & Control', 'T1071.001 Web Protocols', 'HIGH', 'E-03: HTTPS traffic to 45.142.212.100'],
        ['', 'T1095 Non-Application Layer Protocol', 'MEDIUM', 'E-03: Non-standard protocol beacon'],
        ['TA0010 Exfiltration', 'T1041 Exfiltration Over C2 Channel', 'MEDIUM', 'E-03: Outbound data transfer detected'],
    ]
    cw = [42*mm, 55*mm, 22*mm, W - 119*mm]
    elems.append(styled_table(mitre_data, cw, font_size=7.5))
    elems.append(PageBreak())
    return elems


def build_remediation(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('XVII', 'REMEDIATION RECOMMENDATIONS', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'The following recommendations are prioritised by urgency and security impact. Immediate '
        'actions address confirmed active threats; subsequent phases address systemic security '
        'gaps that enabled the intrusion.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    fig7 = make_remediation_fig()
    elems.append(fig_to_image(fig7, 100*mm, 75*mm))
    elems.append(Paragraph(
        'Fig. 7 — Remediation priority matrix: effort vs impact.',
        styles['caption']))
    elems.append(Spacer(1, 3*mm))

    phases = [
        ('IMMEDIATE (0–24 hrs)', CRITICAL, [
            'Isolate CORP-DC-01, CORP-VPN-01, CORP-WKSTN-47, CORP-FS-02, CORP-DB-01 from network.',
            'Rotate ALL service account credentials, especially svc_backup and privileged accounts.',
            'Revoke and reissue Kerberos tickets (krbtgt double-reset) to eliminate potential Golden Ticket.',
            'Block external IPs 45.142.212.100 and 185.220.101.47 at perimeter firewall.',
            'Quarantine and submit WinDefndr32.exe and svc_upd8.exe hashes to AV vendor.',
        ]),
        ('SHORT-TERM (1–7 days)', HIGH, [
            'Rebuild compromised hosts from verified golden images; do not remediate in place.',
            'Enable PowerShell ScriptBlock logging (GPO) and forward to SIEM.',
            'Deploy Privileged Access Workstations (PAW) for all Domain Admin activities.',
            'Implement LAPS (Local Administrator Password Solution) on all workstations.',
            'Conduct full Active Directory audit — identify all accounts created after 2026-03-14 00:00.',
            'Review and tighten VPN MFA — enforce hardware token or FIDO2 for all remote access.',
        ]),
        ('MEDIUM-TERM (1–4 weeks)', MEDIUM, [
            'Deploy EDR solution with real-time process tree monitoring across all endpoints.',
            'Implement network segmentation to prevent lateral movement between OT/IT zones.',
            'Enable Windows Event Forwarding (WEF) with centralised SIEM retention of ≥180 days.',
            'Conduct phishing simulation and security awareness training for all staff.',
            'Perform full vulnerability scan; patch all critical CVEs within SLA.',
        ]),
        ('STRATEGIC (1–3 months)', LOW, [
            'Implement Zero Trust Architecture with identity-centric access controls.',
            'Establish a formal Incident Response Plan with defined runbooks per attack scenario.',
            'Integrate Threat Intelligence feeds into SIEM for IOC matching.',
            'Conduct red team exercise against rebuilt infrastructure to validate controls.',
        ]),
    ]

    for phase_title, col, items in phases:
        header_tbl = Table(
            [[Paragraph(f'<b>{phase_title}</b>',
                        ParagraphStyle('ph', fontName='Helvetica-Bold', fontSize=9,
                                       textColor=white))]],
            colWidths=[W])
        header_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), col),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
        ]))
        elems.append(header_tbl)
        for item in items:
            elems.append(Paragraph(f'• {item}', styles['bullet']))
        elems.append(Spacer(1, 2*mm))

    elems.append(PageBreak())
    return elems


def build_conclusion(styles):
    W = PAGE_W - 30*mm
    elems = []
    elems.append(SectionHeader('XVIII', 'EXPERT OPINION & CONCLUSION', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph(
        'Based on the forensic analysis of Exhibits E-01 through E-04, it is the professional '
        'opinion of the examining engine and the certifying officer that the subject infrastructure '
        'of TechCorp Solutions Pvt. Ltd. was subjected to a <b>Critical Severity multi-stage cyber '
        'intrusion</b> during the period 2026-03-13 23:55 UTC to 2026-03-14 05:09 UTC.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    conclusions = [
        'The intrusion was deliberate, coordinated, and technically sophisticated, employing '
        'automated tooling for initial access and post-exploitation phases.',
        'Evidence of anti-forensic activity (systematic log clearing across 5 hosts) confirms '
        'the adversary was aware of and actively attempting to evade forensic investigation.',
        'The full attack chain has been reconstructed with HIGH confidence: Brute Force → '
        'Lateral Movement → Privilege Escalation → Persistence → C2 Beaconing.',
        'The aggregate Risk Index of 94,700 — calculated across 148,320 log entries using '
        'MITRE ATT&CK-weighted scoring — classifies this incident as a Critical-severity breach.',
        'Data exfiltration cannot be ruled out: C2 beacon activity was confirmed for 53 minutes '
        'prior to network isolation, with outbound data transfer detected in Exhibit E-03.',
        'The subject organisation is strongly advised to notify relevant regulatory bodies '
        '(CERT-In under IT Act Section 70B, NCIIPC for critical infrastructure entities) '
        'within the mandated 6-hour reporting window.',
    ]
    for c in conclusions:
        elems.append(Paragraph(f'• {c}', styles['bullet']))

    elems.append(Spacer(1, 5*mm))
    elems.append(Paragraph(
        'This report has been prepared in accordance with the standards of digital forensic '
        'practice and is submitted as an official forensic examination report for investigative '
        'and judicial purposes. The findings are based solely on the digital evidence provided '
        'and are limited to the scope defined in Section II.',
        styles['body']))

    elems.append(Spacer(1, 10*mm))

    # Signature block
    sig_data = [
        [Paragraph('__________________________________', styles['body']),
         Paragraph('__________________________________', styles['body'])],
        [Paragraph('<b>Dr. A. Sharma, CHFI, GCFE</b>', styles['body_bold']),
         Paragraph('<b>DIG Cybercrime, National Investigation Cell</b>', styles['body_bold'])],
        [Paragraph('Examining Officer', styles['small']),
         Paragraph('Authorising Officer', styles['small'])],
        [Paragraph('Digital Evidence Division', styles['small']),
         Paragraph('National Cyber Crime Investigation Cell', styles['small'])],
        [Paragraph('Date: 2026-03-15', styles['small']),
         Paragraph('Date: 2026-03-15', styles['small'])],
    ]
    sig_tbl = Table(sig_data, colWidths=[W/2, W/2])
    sig_tbl.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
    ]))
    elems.append(sig_tbl)
    elems.append(PageBreak())
    return elems


def build_annexures(styles):
    W = PAGE_W - 30*mm
    elems = []

    # Annexure A
    elems.append(SectionHeader('XIX', 'ANNEXURE A — FORENSIC ENVIRONMENT SPECIFICATION', styles))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph('<b>A.1 Hardware Forensic Environment</b>', styles['heading2']))
    hw_data = [
        ['Component', 'Specification', 'Purpose'],
        ['Forensic Workstation', 'Intel Xeon W-3375, 128GB ECC RAM, 8TB NVMe RAID', 'Primary analysis platform'],
        ['Write Blocker', 'Tableau TX1 Forensic Imager', 'Evidence acquisition'],
        ['Storage', 'AES-256 encrypted NAS (48TB usable)', 'Evidence storage'],
        ['Network', 'Air-gapped analysis network', 'Isolated investigation environment'],
    ]
    elems.append(styled_table(hw_data, [40*mm, 90*mm, W - 130*mm]))
    elems.append(Spacer(1, 3*mm))
    elems.append(Paragraph('<b>A.2 Software Tools & Versions</b>', styles['heading2']))
    sw_data = [
        ['Tool', 'Version', 'Vendor', 'Forensic Role', 'Validation'],
        ['Sentinal-X Core', 'v2.4.1', 'Sentinal Labs', 'Log correlation', 'ISO 17025 validated'],
        ['sklearn Isolation Forest', '1.4.2', 'scikit-learn.org', 'Anomaly detection', 'Academic peer-reviewed'],
        ['Matplotlib', '3.10.8', 'Matplotlib Project', 'Visualisation', 'Open source'],
        ['ReportLab', '4.4.10', 'ReportLab Inc.', 'Report generation', 'Commercial'],
        ['Pandas', '3.0.1', 'NumFOCUS', 'Data manipulation', 'Open source'],
        ['NumPy', '2.4.2', 'NumFOCUS', 'Statistical computation', 'Open source'],
        ['Tableau TX1', 'Firmware 7.2', 'Tableau (OpenText)', 'Write blocking', 'NIST-validated'],
        ['VirusTotal API', 'v3', 'Google', 'Threat intelligence', 'External service'],
        ['Shodan API', 'v1.31', 'Shodan.io', 'IP intelligence', 'External service'],
    ]
    cw = [38*mm, 22*mm, 32*mm, 30*mm, W - 122*mm]
    elems.append(styled_table(sw_data, cw, font_size=7.5))
    elems.append(PageBreak())

    # Annexure B
    elems.append(SectionHeader('XX', 'ANNEXURE B — EXTENDED EVENT LOG SAMPLES', styles))
    elems.append(Spacer(1, 2*mm))
    elems.append(Paragraph(
        'The following tables present extended samples of raw event log data extracted from '
        'Exhibit E-01. These samples are representative of the detected anomaly categories '
        'and are provided for judicial reference and independent verification purposes.',
        styles['body']))
    elems.append(Spacer(1, 2*mm))

    log_headers = ['#', 'Timestamp (UTC)', 'EID', 'Host', 'User', 'Risk Score', 'Detail']

    batches = [
        ('B.1 — Brute Force Events (EID 4625) — Sample Batch', [
            ['1','2026-03-14 00:02:00','4625','CORP-VPN-01','admin','9056','Account failed to log on; Sub Status: 0xC000006A'],
            ['2','2026-03-14 00:09:00','4625','CORP-VPN-01','svc_backup','6052','Account failed to log on; Sub Status: 0xC000006D'],
            ['3','2026-03-14 00:18:00','4625','CORP-VPN-01','jdoe','1289','Security Audit Log was cleared by SYSTEM'],
            ['4','2026-03-14 00:23:00','4625','CORP-VPN-01','admin','4825','Network logon; Logon Type: 3; Process: NtLmSsp'],
            ['5','2026-03-14 00:32:00','4625','CORP-VPN-01','svc_backup','5329','Process created: powershell.exe -EncodedCommand'],
            ['6','2026-03-14 00:37:00','4625','CORP-VPN-01','admin','9985','Service installed: WinDefndr32; ImagePath: C:\\Windows\\Temp\\svhost32.exe'],
            ['7','2026-03-14 00:44:00','4625','CORP-MAIL-01','jdoe','4681','Network logon; Logon Type: 3; Workstation: CORP-WKSTN-47'],
            ['8','2026-03-14 00:53:00','4625','CORP-MAIL-01','admin','1863','Account failed to log on; Sub Status: 0xC0000064'],
        ]),
        ('B.2 — Log Tampering Events (EID 1102) — Sample Batch', [
            ['1','2026-03-14 00:01:00','1102','CORP-DC-01','SYSTEM','5143','Account failed to log on; Sub Status: 0xC000006A'],
            ['2','2026-03-14 00:09:00','1102','CORP-WEB-03','SYSTEM','9811','Account failed to log on; Sub Status: 0xC000006D'],
            ['3','2026-03-14 00:19:00','1102','CORP-FS-02','SYSTEM','6224','Security Audit Log was cleared by SYSTEM'],
            ['4','2026-03-14 00:26:00','1102','CORP-WKSTN-47','SYSTEM','1622','Network logon; Logon Type: 3; Process: NtLmSsp'],
            ['5','2026-03-14 00:29:00','1102','CORP-DB-01','SYSTEM','8874','Process created: powershell.exe -EncodedCommand'],
        ]),
        ('B.3 — Lateral Movement Events (EID 4624) — Sample Batch', [
            ['1','2026-03-14 00:05:00','4624','CORP-FS-02','svc_backup','3168','Account failed to log on; Sub Status: 0xC000006A'],
            ['2','2026-03-14 00:08:00','4624','CORP-DB-01','svc_backup','2820','Account failed to log on; Sub Status: 0xC000006D'],
            ['3','2026-03-14 00:16:00','4624','CORP-HR-01','svc_backup','4042','Security Audit Log was cleared by SYSTEM'],
            ['4','2026-03-14 00:25:00','4624','CORP-FIN-01','svc_backup','2637','Network logon; Logon Type: 3; Process: NtLmSsp'],
            ['5','2026-03-14 00:30:00','4624','CORP-WKSTN-47','svc_backup','4408','Process created: powershell.exe -EncodedCommand'],
            ['6','2026-03-14 00:38:00','4624','CORP-DC-01','svc_backup','3017','Service installed: WinDefndr32; ImagePath: C:\\Windows\\Temp\\svhost32.exe'],
        ]),
        ('B.4 — Privilege Escalation Events (EID 4688) — Sample Batch', [
            ['1','2026-03-14 00:05:00','4688','CORP-WKSTN-47','jdoe','878','Account failed to log on; Sub Status: 0xC000006A'],
            ['2','2026-03-14 00:12:00','4688','CORP-WKSTN-47','jdoe','6183','Account failed to log on; Sub Status: 0xC000006D'],
            ['3','2026-03-14 00:18:00','4688','CORP-WKSTN-47','jdoe','8894','Security Audit Log was cleared by SYSTEM'],
            ['4','2026-03-14 00:23:00','4688','CORP-DC-01','jdoe','9108','Network logon; Logon Type: 3; Process: NtLmSsp'],
            ['5','2026-03-14 00:29:00','4688','CORP-DC-01','jdoe','2428','Process created: powershell.exe -EncodedCommand'],
        ]),
        ('B.5 — Malicious Service Install Events (EID 7045) — Sample Batch', [
            ['1','2026-03-14 00:01:00','7045','CORP-WKSTN-47','SYSTEM','4558','Account failed to log on; Sub Status: 0xC000006A'],
            ['2','2026-03-14 00:11:00','7045','CORP-WKSTN-47','SYSTEM','7323','Account failed to log on; Sub Status: 0xC000006D'],
            ['3','2026-03-14 00:18:00','7045','CORP-FS-02','SYSTEM','5201','Security Audit Log was cleared by SYSTEM'],
        ]),
    ]
    cw = [8*mm, 35*mm, 12*mm, 28*mm, 20*mm, 18*mm, W - 121*mm]
    for batch_title, rows in batches:
        elems.append(Paragraph(f'<b>{batch_title}</b>', styles['heading2']))
        elems.append(Spacer(1, 1*mm))
        tbl = styled_table([log_headers] + rows, cw, font_size=6.5)
        elems.append(tbl)
        elems.append(Spacer(1, 3*mm))

    elems.append(PageBreak())

    # Annexure C
    elems.append(SectionHeader('XXI', 'ANNEXURE C — GLOSSARY OF TERMS', styles))
    elems.append(Spacer(1, 3*mm))

    glossary = [
        ['Term / Acronym', 'Definition'],
        ['APT', 'Advanced Persistent Threat — a sophisticated, long-term cyberattack campaign.'],
        ['EVTX', 'Windows XML Event Log format used by the Windows Security Event subsystem.'],
        ['EID 1102', 'Windows Security Event ID 1102 — "The audit log was cleared." Key anti-forensic indicator.'],
        ['EID 4624', 'Successful account logon. Used to track lateral movement via network logons.'],
        ['EID 4625', 'Failed account logon. Bulk occurrences indicate brute-force or credential-stuffing attacks.'],
        ['EID 4688', 'A new process was created. Monitored for anomalous parent-child process relationships.'],
        ['EID 7045', 'A new service was installed. Key indicator of persistence mechanism installation.'],
        ['IOC', 'Indicator of Compromise — an artifact indicating a system has been compromised.'],
        ['Isolation Forest', 'Unsupervised ML algorithm that isolates anomalies through random feature partitioning.'],
        ['Kill Chain', 'Sequential model: Recon → Weaponise → Deliver → Exploit → Install → C2 → Actions.'],
        ['Lateral Movement', 'Techniques adversaries use to progressively move through a network post-compromise.'],
        ['LOLBins', 'Living-off-the-Land Binaries — legitimate system tools abused for malicious purposes.'],
        ['MITRE ATT&CK', 'Globally accessible knowledge base of adversary tactics and techniques (enterprise).'],
        ['MFA', 'Multi-Factor Authentication — additional authentication beyond username/password.'],
        ['NCIIPC', 'National Critical Information Infrastructure Protection Centre (India).'],
        ['NLA', 'Network Level Authentication — pre-authentication for RDP sessions.'],
        ['Pass-the-Hash', 'Technique using captured password hash to authenticate without knowing plaintext.'],
        ['Persistence', 'Adversary techniques to maintain access across reboots and credential changes.'],
        ['SIEM', 'Security Information and Event Management — centralised log collection and analysis.'],
        ['TOR', 'The Onion Router — anonymisation network frequently used to obscure attack origins.'],
        ['T1070.001', 'MITRE ATT&CK technique: Clear Windows Event Logs (Defense Evasion sub-technique).'],
        ['T1110.003', 'MITRE ATT&CK technique: Password Spraying (Credential Access sub-technique).'],
        ['T1543.003', 'MITRE ATT&CK technique: Windows Service creation (Persistence sub-technique).'],
        ['UAC', 'User Account Control — Windows security feature prompting for elevated privilege approval.'],
        ['WEF', 'Windows Event Forwarding — centralised collection of Windows events from endpoints.'],
        ['Zero Trust', 'Security model requiring verification of every user/device regardless of network location.'],
    ]
    elems.append(styled_table(glossary, [40*mm, W - 40*mm]))
    return elems


# ─────────────────────────────────────────────
# SCAN-BACKED PDF (DB + ai_summary; same section layout as detailed findings mock)
# ─────────────────────────────────────────────
def _scan_pdf_int_to_roman(n: int) -> str:
    if n <= 0:
        return ''
    vals = [
        (1000, 'M'), (900, 'CM'), (500, 'D'), (400, 'CD'),
        (100, 'C'), (90, 'XC'), (50, 'L'), (40, 'XL'),
        (10, 'X'), (9, 'IX'), (5, 'V'), (4, 'IV'), (1, 'I'),
    ]
    num = n
    out = []
    for v, s in vals:
        while num >= v:
            out.append(s)
            num -= v
    return ''.join(out)


def _scan_severity_label(risk_score) -> str:
    if risk_score is None:
        return 'MEDIUM'
    rs = int(risk_score)
    if rs >= 85:
        return 'CRITICAL'
    if rs >= 55:
        return 'HIGH'
    if rs >= 25:
        return 'MEDIUM'
    return 'LOW'


def build_scan_pdf(output_path: str, scan_id: str):
    """
    Build a PDF for a persisted scan: Section I = scan.ai_briefing; sections VI+ mimic
    build_detailed_findings using category rows + forensic_analysis from ai_summary.
    Returns output_path, or None if the scan is missing.
    """
    from sqlalchemy import func, desc
    from database import SessionLocal
    from db_models import Scan, AnomalyCategory, AnomalousEvent

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            return None

        briefing = (scan.ai_briefing or "").strip()
        if not briefing or "[AI briefing: empty or unavailable.]" in briefing:
            # Trigger lazy generation if missing
            from ai_intelligence import SecurityAI
            ai = SecurityAI()
            try:
                briefing = ai.regenerate_executive_briefing_from_db(str(scan.scan_id))
                if briefing and str(briefing).strip():
                    scan.ai_briefing = briefing
                    db.commit()
            except Exception as e:
                print(f"⚠️ PDF lazy-briefing failed: {e}")
                briefing = "[AI briefing could not be generated at this time.]"

        cats = (
            db.query(AnomalyCategory)
            .filter(
                AnomalyCategory.scan_id == scan.scan_id,
                AnomalyCategory.category_name != 'Normal',
            )
            .order_by(AnomalyCategory.event_count.desc())
            .all()
        )

        styles = build_styles()
        story = []
        story.append(SectionHeader('I', 'EXECUTIVE SUMMARY', styles))
        story.append(Spacer(1, 3 * mm))
        story.extend(_scan_ai_briefing_flowables(briefing, styles))
        story.append(PageBreak())

        if not cats:
            story.append(
                Paragraph(
                    '<i>No non-Normal threat categories for this scan.</i>',
                    styles['body'])
            )
        else:
            for idx, cat in enumerate(cats):
                roman = _scan_pdf_int_to_roman(6 + idx)
                title = f'{cat.category_name} — Detailed Analysis'
                tid = cat.mitre_id or '—'
                tactic = cat.tactic or '—'
                sev = _scan_severity_label(cat.risk_score)
                cnt = func.count().label('cnt')
                top = (
                    db.query(AnomalousEvent.windows_event_id, cnt)
                    .filter(
                        AnomalousEvent.category_id == cat.category_id,
                        AnomalousEvent.windows_event_id.isnot(None),
                    )
                    .group_by(AnomalousEvent.windows_event_id)
                    .order_by(desc(cnt))
                    .first()
                )
                primary_eid = str(top[0]) if top else '—'
                rows_h = (
                    db.query(AnomalousEvent.computer)
                    .filter(AnomalousEvent.category_id == cat.category_id)
                    .distinct()
                    .limit(16)
                    .all()
                )
                hosts_str = ', '.join(r[0] for r in rows_h if r[0]) or '—'
                analysis = (cat.ai_summary or 'No AI summary for this category.').strip()
                evs = (
                    db.query(AnomalousEvent)
                    .filter(AnomalousEvent.category_id == cat.category_id)
                    .order_by(AnomalousEvent.time_logged)
                    .limit(10)
                    .all()
                )
                log_rows = []
                for e in evs:
                    ts = (
                        e.time_logged.strftime('%Y-%m-%d %H:%M:%S')
                        if e.time_logged
                        else '—'
                    )
                    er = str(e.windows_event_id) if e.windows_event_id is not None else '—'
                    det = (e.task_category or '—')[:80]
                    log_rows.append(
                        [ts, e.computer or '—', e.user_account or '—', er, det])

                story += build_finding_section(
                    6 + idx,
                    roman,
                    title,
                    primary_eid,
                    cat.event_count,
                    cat.risk_score,
                    tactic,
                    tid,
                    hosts_str,
                    sev,
                    analysis,
                    log_rows,
                    styles,
                )

        safe_name = (scan.file_name or 'scan').replace('\n', ' ')[:80]
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=18 * mm,
            bottomMargin=20 * mm,
            title=f'Forensic — {safe_name}',
            author='DSCIML Forensic Engine',
            subject=str(scan.scan_id),
        )
        on_page = make_page_callbacks(doc)
        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
        return output_path
    finally:
        db.close()


# ─────────────────────────────────────────────
# MAIN BUILDER
# ─────────────────────────────────────────────
def build_report(output_path='forensic_report_FSL_DF_2026_0314.pdf'):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=15*mm,
        rightMargin=15*mm,
        topMargin=18*mm,
        bottomMargin=20*mm,
        title='Forensic Examination Report FSL-DF-2026-0314',
        author='Dr. A. Sharma, CHFI, GCFE',
        subject='Digital Evidence Division — TechCorp Solutions Pvt. Ltd.',
    )

    on_page = make_page_callbacks(doc)
    styles  = build_styles()

    story = []
    story += build_cover(styles)
    story += build_toc(styles)
    story += build_executive_summary(styles)
    story += build_case_identification(styles)
    story += build_methodology(styles)
    story += build_statistical_analysis(styles)
    story += build_detailed_findings(styles)
    story += build_host_compromise_matrix(styles)
    story += build_attack_chain(styles)
    story += build_ioc_register(styles)
    story += build_threat_actor(styles)
    story += build_risk_heat_map(styles)
    story += build_mitre(styles)
    story += build_remediation(styles)
    story += build_conclusion(styles)
    story += build_annexures(styles)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f'✓ Report generated: {output_path}')
    return output_path


if __name__ == '__main__':
    build_report('/mnt/user-data/outputs/forensic_report_FSL_DF_2026_0314.pdf')
