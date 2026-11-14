#!/usr/bin/env python3
"""
Generates Terminal_Breach_Technical_Report.docx — a thesis-style technical report.

The body is rendered from REPORT.md, so the Markdown report and the Word
document can never drift apart. Edit REPORT.md, then run:

    python3 gen_report.py            (needs: pip install python-docx)

REPORT.md is looked up next to this script, then one directory up (the repo
keeps sources in src/ and documents at the root). The .docx is written next
to REPORT.md.
"""

from docx import Document
from docx.shared import Pt, Inches, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy
import os
import re

doc = Document()

# ── Page margins ──────────────────────────────────────────────────────────────
for section in doc.sections:
    section.top_margin    = Cm(2.54)
    section.bottom_margin = Cm(2.54)
    section.left_margin   = Cm(3.17)
    section.right_margin  = Cm(2.54)

# ── Styles ────────────────────────────────────────────────────────────────────
styles = doc.styles

def set_style(style_name, font_name, size_pt, bold=False, colour=None,
              space_before=0, space_after=0, alignment=WD_ALIGN_PARAGRAPH.LEFT,
              line_spacing=None):
    try:
        s = styles[style_name]
    except KeyError:
        s = styles.add_style(style_name, 1)
    f = s.font
    f.name  = font_name
    f.size  = Pt(size_pt)
    f.bold  = bold
    if colour:
        f.color.rgb = RGBColor(*colour)
    pf = s.paragraph_format
    pf.space_before = Pt(space_before)
    pf.space_after  = Pt(space_after)
    pf.alignment    = alignment
    if line_spacing:
        pf.line_spacing_rule = WD_LINE_SPACING.EXACTLY
        pf.line_spacing = Pt(line_spacing)
    return s

DARK  = (30, 30, 30)
BLUE  = (31, 73, 125)
LGREY = (100, 100, 100)
BLACK = (0, 0, 0)

# Body
body = styles['Normal']
body.font.name = 'Times New Roman'
body.font.size = Pt(12)
body.font.color.rgb = RGBColor(*DARK)
body.paragraph_format.space_after  = Pt(6)
body.paragraph_format.line_spacing_rule = WD_LINE_SPACING.MULTIPLE
body.paragraph_format.line_spacing = 1.15

# Headings
h1 = styles['Heading 1']
h1.font.name  = 'Times New Roman'
h1.font.size  = Pt(16)
h1.font.bold  = True
h1.font.color.rgb = RGBColor(*BLUE)
h1.paragraph_format.space_before = Pt(18)
h1.paragraph_format.space_after  = Pt(6)

h2 = styles['Heading 2']
h2.font.name  = 'Times New Roman'
h2.font.size  = Pt(13)
h2.font.bold  = True
h2.font.color.rgb = RGBColor(*BLUE)
h2.paragraph_format.space_before = Pt(14)
h2.paragraph_format.space_after  = Pt(4)

h3 = styles['Heading 3']
h3.font.name  = 'Times New Roman'
h3.font.size  = Pt(12)
h3.font.bold  = True
h3.font.color.rgb = RGBColor(*DARK)
h3.paragraph_format.space_before = Pt(10)
h3.paragraph_format.space_after  = Pt(3)

# Caption style
set_style('Caption', 'Times New Roman', 10, bold=False, colour=LGREY,
          space_before=2, space_after=8, alignment=WD_ALIGN_PARAGRAPH.CENTER)

# Code style
set_style('Code', 'Courier New', 9, bold=False, colour=(50, 50, 50),
          space_before=4, space_after=4, line_spacing=12)

# ── Helpers ───────────────────────────────────────────────────────────────────

def add_heading(text, level):
    p = doc.add_heading(text, level=level)
    return p

def add_body(text):
    p = doc.add_paragraph(text)
    p.style = styles['Normal']
    return p

def add_code(text):
    for line in text.split('\n'):
        p = doc.add_paragraph(line if line else ' ')
        p.style = styles['Code']
        # Light grey background via paragraph shading
        pPr = p._p.get_or_add_pPr()
        shd = OxmlElement('w:shd')
        shd.set(qn('w:val'), 'clear')
        shd.set(qn('w:color'), 'auto')
        shd.set(qn('w:fill'), 'F3F3F3')
        pPr.append(shd)

def add_caption(text):
    p = doc.add_paragraph(text)
    p.style = styles['Caption']

def add_table(headers, rows, col_widths=None):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = 'Table Grid'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    # Header row
    hdr = table.rows[0]
    for i, h in enumerate(headers):
        cell = hdr.cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        cell.paragraphs[0].runs[0].font.size = Pt(10)
        cell.paragraphs[0].runs[0].font.name = 'Times New Roman'
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        # Header background
        tcPr = cell._tc.get_or_add_tcPr()
        shd  = OxmlElement('w:shd')
        shd.set(qn('w:val'), 'clear')
        shd.set(qn('w:color'), 'auto')
        shd.set(qn('w:fill'), '1F497D')
        tcPr.append(shd)
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)

    # Data rows
    for ri, row_data in enumerate(rows):
        row = table.add_row()
        for ci, val in enumerate(row_data):
            cell = row.cells[ci]
            cell.text = val
            cell.paragraphs[0].runs[0].font.size = Pt(9.5)
            cell.paragraphs[0].runs[0].font.name = 'Times New Roman'
            if ri % 2 == 1:
                tcPr = cell._tc.get_or_add_tcPr()
                shd  = OxmlElement('w:shd')
                shd.set(qn('w:val'), 'clear')
                shd.set(qn('w:color'), 'auto')
                shd.set(qn('w:fill'), 'EEF3FA')
                tcPr.append(shd)

    # Column widths
    if col_widths:
        for i, w in enumerate(col_widths):
            for cell in table.columns[i].cells:
                cell.width = Inches(w)

    doc.add_paragraph()  # spacer after table
    return table

def page_break():
    doc.add_page_break()


# ═════════════════════════════════════════════════════════════════════════════
# COVER PAGE
# ═════════════════════════════════════════════════════════════════════════════

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_before = Pt(60)
run = p.add_run('TERMINAL BREACH')
run.font.name  = 'Times New Roman'
run.font.size  = Pt(28)
run.font.bold  = True
run.font.color.rgb = RGBColor(*BLUE)

p2 = doc.add_paragraph()
p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
run2 = p2.add_run('Version 4.0 — The Lazarus Protocol')
run2.font.name  = 'Times New Roman'
run2.font.size  = Pt(16)
run2.font.color.rgb = RGBColor(*LGREY)

doc.add_paragraph()

p3 = doc.add_paragraph()
p3.alignment = WD_ALIGN_PARAGRAPH.CENTER
run3 = p3.add_run('Technical Design and Implementation Report')
run3.font.name  = 'Times New Roman'
run3.font.size  = Pt(18)
run3.font.bold  = True
run3.font.color.rgb = RGBColor(*DARK)

doc.add_paragraph()
doc.add_paragraph()

for line in [
    'Prepared by: Ani',
    'Course: CMPT — Systems Programming',
    'Institution: Simon Fraser University',
    'Date: November 13, 2026',
]:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(line)
    run.font.name = 'Times New Roman'
    run.font.size = Pt(12)
    run.font.color.rgb = RGBColor(*DARK)

page_break()


# ═════════════════════════════════════════════════════════════════════════════
# BODY — rendered from REPORT.md
# ═════════════════════════════════════════════════════════════════════════════

here = os.path.dirname(os.path.abspath(__file__))
md_path = next((c for c in (os.path.join(here, 'REPORT.md'),
                            os.path.join(here, '..', 'REPORT.md')) if os.path.exists(c)), None)
if not md_path:
    raise SystemExit('REPORT.md not found next to gen_report.py or one level up.')
md_path = os.path.abspath(md_path)
lines = open(md_path, encoding='utf-8').read().splitlines()

INLINE = re.compile(r'(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)')

def add_rich(par, text, size=None):
    """Adds text to a paragraph honouring **bold**, *italic* and `code`."""
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith('**') and part.endswith('**'):
            r = par.add_run(part[2:-2]); r.bold = True
        elif part.startswith('`') and part.endswith('`'):
            r = par.add_run(part[1:-1]); r.font.name = 'Courier New'
            r.font.size = Pt(size - 1 if size else 10.5)
            continue
        elif part.startswith('*') and part.endswith('*') and len(part) > 2:
            r = par.add_run(part[1:-1]); r.italic = True
        else:
            r = par.add_run(part)
        if size:
            r.font.size = Pt(size)

def strip_md(text):
    return re.sub(r'\*\*|`', '', text)

def add_md_table(rows):
    header = [strip_md(c) for c in rows[0]]
    table = add_table(header, [[''] * len(header) for _ in rows[1:]])
    for ri, row in enumerate(rows[1:], start=1):
        for ci, val in enumerate(row[:len(header)]):
            cell = table.rows[ri].cells[ci]
            par = cell.paragraphs[0]
            for r in list(par.runs):
                r._r.getparent().remove(r._r)
            add_rich(par, val, size=9.5)
            for r in par.runs:
                if r.font.name != 'Courier New':
                    r.font.name = 'Times New Roman'

def split_row(line):
    return [c.strip() for c in line.strip().strip('|').split('|')]

# Table of contents: a real Word TOC field. Word fills in page numbers when the
# document is opened (updateFields is set below) or via right-click → Update.
add_heading('Table of Contents', 1)
p = doc.add_paragraph()
fld_begin = OxmlElement('w:fldChar'); fld_begin.set(qn('w:fldCharType'), 'begin')
instr = OxmlElement('w:instrText'); instr.set(qn('xml:space'), 'preserve')
instr.text = 'TOC \\o "1-2" \\h \\z \\u'
fld_sep = OxmlElement('w:fldChar'); fld_sep.set(qn('w:fldCharType'), 'separate')
placeholder = OxmlElement('w:t'); placeholder.text = 'Right-click and choose "Update Field" to build the table of contents.'
fld_end = OxmlElement('w:fldChar'); fld_end.set(qn('w:fldCharType'), 'end')
run = p.add_run()
for el in (fld_begin, instr, fld_sep, placeholder, fld_end):
    run._r.append(el)
settings = doc.settings.element
upd = OxmlElement('w:updateFields'); upd.set(qn('w:val'), 'true')
settings.append(upd)
page_break()

sec = 0
sub = 0
i = 0
first_h2 = True
while i < len(lines):
    line = lines[i]
    if line.startswith('# '):                       # document title: on cover already
        i += 1; continue
    if line.startswith('## '):
        title = line[3:].strip()
        if not first_h2:
            page_break() if title in ('Level Reference', 'Defects Fixed in v4.0') else None
        first_h2 = False
        sec += 1; sub = 0
        add_heading(f'{sec}.  {title}', 1)
        i += 1; continue
    if line.startswith('### '):
        sub += 1
        add_heading(f'{sec}.{sub}  {line[4:].strip()}', 2)
        i += 1; continue
    if line.startswith('```'):
        block = []
        i += 1
        while i < len(lines) and not lines[i].startswith('```'):
            block.append(lines[i]); i += 1
        add_code('\n'.join(block))
        i += 1; continue
    if line.startswith('|'):
        rows = []
        while i < len(lines) and lines[i].startswith('|'):
            if not re.match(r'^\|[\s:|-]+\|$', lines[i]):
                rows.append(split_row(lines[i]))
            i += 1
        add_md_table(rows)
        continue
    if re.match(r'^(\s*)[-*] ', line) or re.match(r'^\d+\. ', line):
        numbered = bool(re.match(r'^\d+\. ', line))
        text = re.sub(r'^(\s*)([-*]|\d+\.) ', '', line)
        par = doc.add_paragraph(style='List Number' if numbered else 'List Bullet')
        add_rich(par, text)
        i += 1; continue
    if line.strip() in ('---', ''):
        i += 1; continue
    # paragraph: join consecutive text lines
    para = [line.strip()]
    i += 1
    while i < len(lines) and lines[i].strip() and not re.match(r'^(#|```|\||---|\s*[-*] |\d+\. )', lines[i]):
        para.append(lines[i].strip()); i += 1
    text = ' '.join(para)
    if text.startswith('*') and text.endswith('*') and not text.startswith('**'):
        p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(text.strip('*')); r.italic = True
        r.font.size = Pt(10); r.font.color.rgb = RGBColor(*LGREY)
    else:
        add_rich(doc.add_paragraph(style='Normal'), text)

# ── Save ─────────────────────────────────────────────────────────────────────
output_path = os.path.join(os.path.dirname(md_path), 'Terminal_Breach_Technical_Report.docx')
doc.save(output_path)
print(f'Rendered {md_path} -> {output_path} ({sec} sections)')
