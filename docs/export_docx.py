"""
docs/export_docx.py
Exports docs/FINAL_REPORT.md to docs/FINAL_REPORT.docx using python-docx.
Preserves headings, tables, formatted text (bold, code, italics), code blocks,
and embeds evaluation figures.
"""

import os
import re
from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

REPO_ROOT = Path(__file__).resolve().parent.parent
MD_PATH = REPO_ROOT / "docs" / "FINAL_REPORT.md"
DOCX_PATH = REPO_ROOT / "docs" / "FINAL_REPORT.docx"

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def add_formatted_runs(paragraph, text):
    """Parses simple inline markdown: **bold**, *italic*, `code`, and clean text."""
    # Pattern to match bold, code, italic
    token_spec = [
        ('BOLD', r'\*\*(.*?)\*\*'),
        ('CODE', r'`(.*?)`'),
        ('ITALIC', r'\*(.*?)\*'),
    ]
    tok_regex = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in token_spec)
    
    pos = 0
    for match in re.finditer(tok_regex, text):
        # Text before match
        if match.start() > pos:
            run = paragraph.add_run(text[pos:match.start()])
        
        kind = match.lastgroup
        if kind == 'BOLD':
            run = paragraph.add_run(match.group(1))
            run.bold = True
        elif kind == 'CODE':
            run = paragraph.add_run(match.group(2))
            run.font.name = 'Consolas'
            run.font.size = Pt(9.5)
            run.font.color.rgb = RGBColor(160, 40, 40)
        elif kind == 'ITALIC':
            run = paragraph.add_run(match.group(3))
            run.italic = True
        
        pos = match.end()
    
    if pos < len(text):
        paragraph.add_run(text[pos:])

def convert_md_to_docx():
    if not MD_PATH.exists():
        raise FileNotFoundError(f"Markdown report not found at {MD_PATH}")

    with open(MD_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    doc = Document()

    # Document Styles Setup
    style_normal = doc.styles['Normal']
    style_normal.font.name = 'Calibri'
    style_normal.font.size = Pt(11)
    style_normal.font.color.rgb = RGBColor(30, 30, 30)

    in_code_block = False
    code_block_lines = []
    in_table = False
    table_lines = []

    def flush_table():
        nonlocal in_table, table_lines
        if not table_lines:
            in_table = False
            return
        
        # Parse table lines
        # table_lines[0] is header, table_lines[1] is separator, table_lines[2:] are data
        rows_data = []
        for line in table_lines:
            line_str = line.strip().strip('|')
            cells = [c.strip() for c in line_str.split('|')]
            rows_data.append(cells)
        
        if len(rows_data) >= 2:
            headers = rows_data[0]
            # row 1 is separator |:---|:---:|
            data_rows = rows_data[2:] if len(rows_data) > 2 else []
            
            table = doc.add_table(rows=1 + len(data_rows), cols=len(headers))
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            
            # Format Header Row
            hdr_cells = table.rows[0].cells
            for idx, h_text in enumerate(headers):
                if idx < len(hdr_cells):
                    hdr_cells[idx].text = ""
                    p = hdr_cells[idx].paragraphs[0]
                    p.paragraph_format.space_before = Pt(4)
                    p.paragraph_format.space_after = Pt(4)
                    add_formatted_runs(p, h_text)
                    for run in p.runs:
                        run.bold = True
                        run.font.color.rgb = RGBColor(255, 255, 255)
                    set_cell_background(hdr_cells[idx], "1A365D")  # Dark Navy Header
            
            # Format Data Rows
            for r_idx, row in enumerate(data_rows):
                row_cells = table.rows[r_idx + 1].cells
                bg_color = "F7FAFC" if (r_idx % 2 == 1) else "FFFFFF"
                for c_idx, cell_text in enumerate(row):
                    if c_idx < len(row_cells):
                        row_cells[c_idx].text = ""
                        p = row_cells[c_idx].paragraphs[0]
                        p.paragraph_format.space_before = Pt(3)
                        p.paragraph_format.space_after = Pt(3)
                        add_formatted_runs(p, cell_text)
                        set_cell_background(row_cells[c_idx], bg_color)
            
            doc.add_paragraph().paragraph_format.space_after = Pt(6)
        
        table_lines = []
        in_table = False

    def flush_code():
        nonlocal in_code_block, code_block_lines
        if not code_block_lines:
            in_code_block = False
            return
        
        code_text = "".join(code_block_lines).strip()
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.left_indent = Inches(0.2)
        run = p.add_run(code_text)
        run.font.name = 'Consolas'
        run.font.size = Pt(9.5)
        run.font.color.rgb = RGBColor(40, 40, 40)
        
        code_block_lines = []
        in_code_block = False

    for line in lines:
        stripped = line.strip()

        # Handle Code Fences
        if stripped.startswith("```"):
            if in_code_block:
                flush_code()
            else:
                if in_table:
                    flush_table()
                in_code_block = True
                code_block_lines = []
            continue

        if in_code_block:
            code_block_lines.append(line)
            continue

        # Handle Tables
        if stripped.startswith("|") and stripped.endswith("|"):
            if not in_table:
                in_table = True
                table_lines = [stripped]
            else:
                table_lines.append(stripped)
            continue
        else:
            if in_table:
                flush_table()

        # Skip horizontal dividers
        if stripped == "---":
            continue

        # Empty line
        if not stripped:
            continue

        # Headings
        if stripped.startswith("# "):
            h = doc.add_heading(level=0)
            add_formatted_runs(h, stripped[2:].strip())
            h.paragraph_format.space_before = Pt(12)
            h.paragraph_format.space_after = Pt(8)
            continue
        elif stripped.startswith("## "):
            h = doc.add_heading(level=1)
            add_formatted_runs(h, stripped[3:].strip())
            h.paragraph_format.space_before = Pt(14)
            h.paragraph_format.space_after = Pt(6)
            continue
        elif stripped.startswith("### "):
            h = doc.add_heading(level=2)
            add_formatted_runs(h, stripped[4:].strip())
            h.paragraph_format.space_before = Pt(10)
            h.paragraph_format.space_after = Pt(4)
            continue
        elif stripped.startswith("#### "):
            h = doc.add_heading(level=3)
            add_formatted_runs(h, stripped[5:].strip())
            h.paragraph_format.space_before = Pt(8)
            h.paragraph_format.space_after = Pt(2)
            continue

        # Image embeds: ![Alt text](path)
        img_match = re.match(r'!\[(.*?)\]\((.*?)\)', stripped)
        if img_match:
            alt, img_path_str = img_match.group(1), img_match.group(2)
            # Resolve image path
            possible_paths = [
                REPO_ROOT / img_path_str,
                REPO_ROOT / "eval" / img_path_str,
                REPO_ROOT / "docs" / img_path_str,
                REPO_ROOT / "eval" / "figures" / Path(img_path_str).name,
                REPO_ROOT / "docs" / "diagrams" / Path(img_path_str).name
            ]
            found_path = None
            for p in possible_paths:
                if p.exists():
                    found_path = p
                    break
            
            if found_path:
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p.paragraph_format.space_before = Pt(8)
                p.paragraph_format.space_after = Pt(4)
                doc.add_picture(str(found_path), width=Inches(5.8))
                
                # Caption
                caption_p = doc.add_paragraph()
                caption_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                caption_p.paragraph_format.space_after = Pt(10)
                caption_run = caption_p.add_run(f"Figure: {alt}")
                caption_run.italic = True
                caption_run.font.size = Pt(9.5)
                caption_run.font.color.rgb = RGBColor(100, 100, 100)
            continue

        # Lists: Unordered
        if stripped.startswith("- ") or stripped.startswith("* "):
            p = doc.add_paragraph(style='List Bullet')
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            add_formatted_runs(p, stripped[2:].strip())
            continue

        # Lists: Ordered
        numbered_match = re.match(r'^(\d+)\.\s+(.*)', stripped)
        if numbered_match:
            p = doc.add_paragraph(style='List Number')
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            add_formatted_runs(p, numbered_match.group(2).strip())
            continue

        # Standard Paragraph
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(4)
        add_formatted_runs(p, stripped)

    if in_table:
        flush_table()
    if in_code_block:
        flush_code()

    doc.save(str(DOCX_PATH))
    print(f"Successfully generated Word report: {DOCX_PATH} ({DOCX_PATH.stat().st_size:,} bytes)")

if __name__ == "__main__":
    convert_md_to_docx()
