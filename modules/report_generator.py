import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Custom canvas that performs a two-pass save to draw page headers,
    footers, and dynamic page counts ('Page X of Y') on all pages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))
        
        # Header (Top)
        self.drawString(54, 750, "INTELLIGENT MALWARE ANALYSIS AND MITIGATION PLATFORM")
        self.setFont("Helvetica", 8)
        self.drawRightString(558, 750, "Incident Report Summary")
        
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)
        
        # Footer (Bottom)
        self.line(54, 52, 558, 52)
        self.drawString(54, 40, "CONFIDENTIAL - FOR CYBERSECURITY EDUCATIONAL USE ONLY")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 40, page_text)
        
        self.restoreState()

def generate_pdf_report(file_data, iocs, mitre_mappings, mitigations, output_dir):
    """
    Generates a professional PDF report containing the static/dynamic results,
    IOCs, MITRE mappings, risk engine factors, and mitigations.
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    file_id = file_data["id"]
    filename = file_data["filename"]
    safe_filename = "".join([c if c.isalnum() else "_" for c in filename])
    report_filename = f"incident_report_{file_id}_{safe_filename}.pdf"
    pdf_path = os.path.join(output_dir, report_filename)
    
    # Document Setup
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=72,
        bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Palette
    c_primary = colors.HexColor("#0f172a") # Dark Slate
    c_text = colors.HexColor("#1e293b")
    c_muted = colors.HexColor("#64748b")
    
    # Score severity colors
    score = file_data.get("risk_score", 0)
    if score <= 30:
        c_severity = colors.HexColor("#16a34a") # Green
        severity_label = "LOW"
    elif score <= 60:
        c_severity = colors.HexColor("#ca8a04") # Yellow/Orange
        severity_label = "MEDIUM"
    elif score <= 80:
        c_severity = colors.HexColor("#ea580c") # Orange
        severity_label = "HIGH"
    else:
        c_severity = colors.HexColor("#dc2626") # Red
        severity_label = "CRITICAL"
        
    # Custom Paragraph Styles
    style_title = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=c_primary,
        spaceAfter=4
    )
    
    style_subtitle = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=10,
        leading=12,
        textColor=c_muted,
        spaceAfter=15
    )
    
    style_section = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=c_primary,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    
    style_body = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_text
    )
    
    style_body_bold = ParagraphStyle(
        'BodyDarkBold',
        parent=style_body,
        fontName='Helvetica-Bold'
    )
    
    style_table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white
    )
    
    style_explanation = ParagraphStyle(
        'ExplanationBox',
        parent=style_body,
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1e293b")
    )

    story = []
    
    # 1. Header Banner
    story.append(Paragraph("Malware Incident Analysis Report", style_title))
    story.append(Paragraph(f"Generated on {file_data.get('upload_date')} | Automated Sandbox Simulation", style_subtitle))
    
    # 2. Score & Executive Summary Panel
    summary_data = [
        [
            Paragraph("<b>File Name:</b>", style_body),
            Paragraph(filename, style_body),
            Paragraph("<b>Threat Level:</b>", style_body)
        ],
        [
            Paragraph("<b>SHA-256 Hash:</b>", style_body),
            Paragraph(file_data.get("hash"), style_body),
            Paragraph("", style_body) 
        ],
        [
            Paragraph("<b>File Size:</b>", style_body),
            Paragraph(format_size(file_data.get("file_size", 0)), style_body),
            Paragraph("", style_body)
        ],
        [
            Paragraph("<b>Category:</b>", style_body),
            Paragraph(file_data.get("malware_category", "Unknown"), style_body),
            Paragraph("", style_body)
        ]
    ]
    
    # Render the risk badge flowable
    score_cell = Paragraph(
        f"<font size=14><b>{score}/100</b></font><br/><br/><b>{severity_label} RISK</b>",
        ParagraphStyle('ScoreBadge', fontName='Helvetica-Bold', fontSize=10, leading=12, alignment=1, textColor=colors.white)
    )
    
    # Wrap elements in a outer table to display metadata next to the big risk badge
    summary_table = Table(
        [
            [summary_data[0][0], summary_data[0][1], score_cell],
            [summary_data[1][0], summary_data[1][1], ""],
            [summary_data[2][0], summary_data[2][1], ""],
            [summary_data[3][0], summary_data[3][1], ""]
        ],
        colWidths=[90, 274, 140]
    )
    
    summary_table.setStyle(TableStyle([
        ('SPAN', (2, 0), (2, 3)), # Span risk score across 4 rows
        ('BACKGROUND', (2, 0), (2, 3), c_severity),
        ('ALIGN', (2, 0), (2, 3), 'CENTER'),
        ('VALIGN', (2, 0), (2, 3), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 15))
    
    # Define small table styles
    style_table_header_small = ParagraphStyle(
        'TableHeaderSmall',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=6.5,
        leading=8,
        textColor=colors.white
    )
    style_body_small = ParagraphStyle(
        'BodyDarkSmall',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.5,
        leading=8,
        textColor=c_text
    )

    # 3. Multi-Source Sandbox Summaries
    story.append(Paragraph("Multi-Source Sandbox Summaries", style_section))
    
    vt = file_data.get("vt") or {}
    anyrun = file_data.get("anyrun") or {}
    bazaar = file_data.get("malwarebazaar") or {}
    opswat = file_data.get("opswat") or {}
    jotti = file_data.get("jotti") or {}
    cape = file_data.get("cape") or {}
    abuse = file_data.get("abuseipdb") or {}
    correlation = file_data.get("correlation") or {}
    
    # VirusTotal Summary Block
    vt_info = (
        f"<b>Status:</b> {vt.get('file_reputation', 'N/A')}<br/>"
        f"<b>Ratio:</b> {vt.get('detection_ratio', 'N/A')}<br/>"
        f"<b>Family:</b> {vt.get('detected_malware_family', 'N/A')}<br/>"
        f"<b>Score:</b> {vt.get('risk_score', 'N/A')}/100"
    )
    # ANY.RUN Summary Block
    anyrun_info = (
        f"<b>Status:</b> Active Threat Observed<br/>"
        f"<b>PowerShell:</b> {anyrun.get('powershell_activity', 'No')}<br/>"
        f"<b>Registry Changes:</b> {anyrun.get('registry_changes', 'No')}<br/>"
        f"<b>Score:</b> {anyrun.get('risk_score', 'N/A')}/100"
    )
    # MalwareBazaar Summary Block
    bazaar_info = (
        f"<b>Family:</b> {bazaar.get('malware_family', 'N/A')}<br/>"
        f"<b>YARA Match:</b> {bazaar.get('yara_rule', 'N/A')}<br/>"
        f"<b>Confidence:</b> {bazaar.get('threat_confidence_level', 'N/A')}<br/>"
        f"<b>Score:</b> {bazaar.get('risk_score', 'N/A')}/100"
    )
    # OPSWAT Summary Block
    opswat_info = (
        f"<b>Reputation:</b> {opswat.get('file_reputation', 'N/A')}<br/>"
        f"<b>Detections:</b> {opswat.get('detection_count', 0)}/{opswat.get('engine_count', 0)}<br/>"
        f"<b>Category:</b> {opswat.get('risk_category', 'N/A')}<br/>"
        f"<b>Score:</b> {opswat.get('threat_score', 'N/A')}/100"
    )
    # Jotti Summary Block
    jotti_info = (
        f"<b>Confidence:</b> {jotti.get('detection_confidence', 'N/A')}<br/>"
        f"<b>Malware Label:</b> {jotti.get('malware_labels', ['N/A'])[0] if jotti.get('malware_labels') else 'N/A'}<br/>"
        f"<b>Indicators:</b> {len(jotti.get('suspicious_indicators', []))}<br/>"
        f"<b>Score:</b> {jotti.get('risk_score', 'N/A')}/100"
    )
    # CAPE Summary Block
    cape_info = (
        f"<b>Processes:</b> {len(cape.get('processes_created', []))}<br/>"
        f"<b>Registry Mods:</b> {len(cape.get('registry_modifications', []))}<br/>"
        f"<b>MITRE:</b> {len(cape.get('mitre_techniques', []))}<br/>"
        f"<b>Score:</b> {cape.get('risk_score', 'N/A')}/100"
    )
    # AbuseIPDB Summary Block
    abuse_info = (
        f"<b>IP Score:</b> {abuse.get('confidence_score', 'N/A')}%<br/>"
        f"<b>Malicious IPs:</b> {len(abuse.get('malicious_ip_addresses', []))}<br/>"
        f"<b>Reports:</b> {abuse.get('total_reports', 'N/A')}<br/>"
        f"<b>Score:</b> {abuse.get('risk_score', 'N/A')}/100"
    )
    
    sandbox_table = Table(
        [
            [Paragraph("<b>VirusTotal Analyzer</b>", style_body_bold), Paragraph("<b>ANY.RUN Interactive Sandbox</b>", style_body_bold)],
            [Paragraph(vt_info, style_body), Paragraph(anyrun_info, style_body)],
            [Paragraph("<b>MalwareBazaar Database</b>", style_body_bold), Paragraph("<b>OPSWAT MetaDefender</b>", style_body_bold)],
            [Paragraph(bazaar_info, style_body), Paragraph(opswat_info, style_body)],
            [Paragraph("<b>Jotti Malware Scan</b>", style_body_bold), Paragraph("<b>CAPE Sandbox</b>", style_body_bold)],
            [Paragraph(jotti_info, style_body), Paragraph(cape_info, style_body)],
            [Paragraph("<b>AbuseIPDB Threat Intelligence</b>", style_body_bold), ""],
            [Paragraph(abuse_info, style_body), ""]
        ],
        colWidths=[252, 252]
    )
    sandbox_table.setStyle(TableStyle([
        ('SPAN', (0, 6), (1, 6)),
        ('SPAN', (0, 7), (1, 7)),
        ('BACKGROUND', (0, 0), (0, 0), colors.HexColor("#f8fafc")),
        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor("#f8fafc")),
        ('BACKGROUND', (0, 2), (0, 2), colors.HexColor("#f8fafc")),
        ('BACKGROUND', (1, 2), (1, 2), colors.HexColor("#f8fafc")),
        ('BACKGROUND', (0, 4), (0, 4), colors.HexColor("#f8fafc")),
        ('BACKGROUND', (1, 4), (1, 4), colors.HexColor("#f8fafc")),
        ('BACKGROUND', (0, 6), (1, 6), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(sandbox_table)
    story.append(Spacer(1, 12))
    
    # 4. Side-by-Side Comparison Table
    story.append(Paragraph("Multi-Source Side-by-Side Comparison", style_section))
    comp_rows = [[
        Paragraph("Parameter", style_table_header_small),
        Paragraph("VirusTotal", style_table_header_small),
        Paragraph("ANY.RUN", style_table_header_small),
        Paragraph("Bazaar", style_table_header_small),
        Paragraph("OPSWAT", style_table_header_small),
        Paragraph("Jotti", style_table_header_small),
        Paragraph("CAPE", style_table_header_small),
        Paragraph("AbuseIPDB", style_table_header_small)
    ]]
    for item in correlation.get("comparison_table", []):
        comp_rows.append([
            Paragraph(f"<b>{item.get('parameter')}</b>", style_body_small),
            Paragraph(str(item.get("virustotal") or "N/A"), style_body_small),
            Paragraph(str(item.get("anyrun") or "N/A"), style_body_small),
            Paragraph(str(item.get("malwarebazaar") or "N/A"), style_body_small),
            Paragraph(str(item.get("opswat") or "N/A"), style_body_small),
            Paragraph(str(item.get("jotti") or "N/A"), style_body_small),
            Paragraph(str(item.get("cape") or "N/A"), style_body_small),
            Paragraph(str(item.get("abuseipdb") or "N/A"), style_body_small)
        ])
        
    comp_table = Table(comp_rows, colWidths=[98, 58, 58, 58, 58, 58, 58, 58])
    comp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ('PADDING', (0, 0), (-1, -1), 3),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(comp_table)
    story.append(Spacer(1, 12))
    
    story.append(PageBreak())
    
    # 5. Explanations (Parameter Explanation Engine & Beginner Explanation)
    story.append(Paragraph("Correlated Threat Score Explanations", style_section))
    
    # Point reasons
    reasons_list = correlation.get("explanation_reasons", [])
    reasons_flow = []
    for r in reasons_list:
        sign = "+" if r.get("points", 0) >= 0 else ""
        reasons_flow.append(Paragraph(f"<b>{sign}{r.get('points')} points</b>: {r.get('reason')}", style_body))
        
    # Beginner friendly glossary
    beginner_list = correlation.get("beginner_explanations", [])
    beginner_flow = [Paragraph("<b>Simplified Cybersecurity Concepts (Beginner Friendly)</b>", style_body_bold)]
    for b in beginner_list:
        beginner_flow.append(Paragraph(f"• <b>{b.get('technical')}:</b> {b.get('explanation')}", style_body))
        
    exp_table = Table(
        [
            [Paragraph("<b>Score Points Calculations</b>", style_body_bold), Paragraph("<b>Beginner Friendly Explanations</b>", style_body_bold)],
            [reasons_flow, beginner_flow]
        ],
        colWidths=[252, 252]
    )
    exp_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(exp_table)
    story.append(Spacer(1, 12))
    
    # 6. Static Findings & Timeline
    story.append(Paragraph("Static Analysis & Timeline Findings", style_section))
    
    # Static list
    static_indicators = file_data.get("static_indicators", [])
    if not static_indicators:
        static_indicators = ["No anomalous static threat indicators flagged."]
    static_text = "<br/>".join([f"• {ind}" for ind in static_indicators])
    
    # Timeline snippet
    behaviors_json = file_data.get("behaviors", [])
    timeline_text = ""
    for idx, b in enumerate(behaviors_json[:4]): # Limit to first 4 events for space
        timeline_text += f"[{b.get('time')}] ({b.get('category')}) {b.get('activity')[:40]}...<br/>"
    if not timeline_text:
        timeline_text = "No dynamic behaviors registered."
        
    findings_table = Table(
        [
            [Paragraph("<b>Static Rule Matches</b>", style_body_bold), Paragraph("<b>Execution Logs (Abbreviated)</b>", style_body_bold)],
            [Paragraph(static_text, style_body), Paragraph(timeline_text, style_body)]
        ],
        colWidths=[252, 252]
    )
    findings_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 12))
    
    # 7. MITRE ATT&CK Mapping
    story.append(Paragraph("MITRE ATT&CK Mapping", style_section))
    if mitre_mappings:
        mitre_rows = [[
            Paragraph("ID", style_table_header),
            Paragraph("Technique", style_table_header),
            Paragraph("Simplified Explanation", style_table_header)
        ]]
        for m in mitre_mappings:
            mitre_rows.append([
                Paragraph(f"<b>{m.get('technique_id')}</b>", style_body),
                Paragraph(m.get("technique_name"), style_body_bold),
                Paragraph(m.get("beginner_explanation"), style_body)
            ])
        mitre_table = Table(mitre_rows, colWidths=[60, 162, 282])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_primary),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(mitre_table)
    else:
        story.append(Paragraph("No MITRE ATT&CK techniques mapped.", style_body))
        
    story.append(Spacer(1, 12))
    
    # 8. IOCs & Mitigations
    story.append(Paragraph("Indicators of Compromise & Countermeasures", style_section))
    
    # IOC text
    if iocs:
        ioc_text = "<br/>".join([f"<b>{ioc[0]}</b>: {ioc[1]}" for ioc in iocs])
    else:
        ioc_text = "No outbound IOCs extracted."
        
    # Mitigations list
    mitigations_list = correlation.get("mitigations", [])
    if not mitigations_list:
        mitigations_list = mitigations # Fallback to static mapping
    mit_text = ""
    for m in mitigations_list[:3]: # Limit to first 3
        mit_text += f"• <b>[{m.get('priority')}] {m.get('title')}</b>: {m.get('action')[:70]}...<br/>"
    if not mit_text:
        mit_text = "No custom mitigations loaded."
        
    final_table = Table(
        [
            [Paragraph("<b>Extracted IOCs</b>", style_body_bold), Paragraph("<b>Mitigation Action Plan</b>", style_body_bold)],
            [Paragraph(ioc_text, style_body), Paragraph(mit_text, style_body)]
        ],
        colWidths=[180, 324]
    )
    final_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(final_table)
    
    # Build Document using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    
    return report_filename

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
