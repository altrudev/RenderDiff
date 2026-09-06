"""Printable assurance report. The JSON receipt remains the canonical evidence."""
from __future__ import annotations
import io
from xml.sax.saxutils import escape
from .receipt import verify

def pdf_report(report):
    if not verify(report):raise ValueError('report integrity failed')
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from pathlib import Path
    font='Helvetica'
    for path in ['/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf','/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf']:
        if Path(path).exists():
            font='RenderDiffUnicode';
            if font not in pdfmetrics.getRegisteredFontNames():pdfmetrics.registerFont(TTFont(font,path))
            break
    styles=getSampleStyleSheet()
    body=ParagraphStyle('RDText',parent=styles['BodyText'],fontName=font,fontSize=9,leading=13,spaceAfter=8,wordWrap='CJK')
    title=ParagraphStyle('RDTitle',parent=styles['Title'],fontName=font,fontSize=20,leading=24,spaceAfter=14)
    heading=ParagraphStyle('RDHeading',parent=styles['Heading2'],fontName=font,fontSize=12,leading=16,spaceBefore=12,spaceAfter=6)
    def paragraph(text,style=body):return Paragraph(escape(str(text)).replace('\n','<br/>'),style)
    buf=io.BytesIO();doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=42,bottomMargin=42)
    story=[paragraph('RenderDiff Assurance Report',title),paragraph('Engine: '+report.get('engine_version','unknown')),paragraph('Disposition: '+report['summary'].get('assurance_disposition',report['summary'].get('severity','unknown'))),paragraph('This report records representation evidence. It does not certify intent, authorship, authorization, or the absence of all hidden content.')]
    views=report.get('views',{})
    for label,text in [('Human-visible projection',views.get('human_visible',{}).get('text','Unavailable')),('Machine received',views.get('semantic',{}).get('machine_received_text','Unavailable'))]:
        story.append(paragraph(label,heading));story.append(paragraph(text[:12000]));
        if len(text)>12000:story.append(paragraph('Display truncated. See canonical JSON for full evidence.'))
    story.append(paragraph('Findings',heading))
    for f in report.get('findings',[]):
        story.append(paragraph(f.get('category','')+' — '+f.get('materiality',''),heading));story.append(paragraph(f.get('explanation','')))
        evidence=f.get('evidence',{})
        if 'codepoint' in evidence:story.append(paragraph('Codepoint: '+evidence['codepoint']+' - '+evidence.get('name','')))
        if 'decoded' in evidence:story.append(paragraph('Decoded evidence: '+repr(evidence['decoded'][:2000])))
        if 'positions' in evidence:story.append(paragraph('Confusable positions: '+repr(evidence['positions'][:20])))
        if 'fragments' in evidence:story.append(paragraph('Hidden fragments: '+repr(evidence['fragments'][:10])[:3000]))
    story.append(paragraph('Integrity and coverage',heading));story.append(paragraph('Canonical report SHA-256: '+report['receipt']['canonical_json_sha256']))
    story.append(paragraph('PDF is a human-readable derivative. Verify the original JSON receipt and any detached signature or evidence bundle independently.'))
    def footer(canvas,document):
        canvas.saveState();canvas.setFont(font,8);canvas.drawString(42,24,'RenderDiff | Evidence report');canvas.drawRightString(A4[0]-42,24,str(document.page));canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return buf.getvalue()
