"""Generate the project's draw.io diagrams (editable .drawio files) and export them to PNG.

Each diagram is written to docs/diagrams/<name>.drawio (open and edit it at app.diagrams.net
or in draw.io Desktop) and exported to docs/diagrams/<name>.png for the reports.

Usage: python docs/diagrams/build_diagrams.py [name ...]
Requires draw.io Desktop (winget install JGraph.Draw) for the PNG export.
"""
import os
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
DRAWIO = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "draw.io" / "draw.io.exe"

INK, MUTED = "#1F2D3D", "#4D5B69"
ZONES = {  # fill, stroke, title colour
    "blue": ("#EAF2FB", "#0072B2", "#0B4F7C"),
    "green": ("#EAF6F1", "#007F68", "#00594A"),
    "orange": ("#FFF4E5", "#B96A00", "#7A4600"),
    "grey": ("#F5F6F8", "#6B7785", "#2F3A45"),
    "purple": ("#F6ECF3", "#A8558E", "#6E2F5C"),
}
EDGE = f"edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor={MUTED};strokeWidth=1.5;endArrow=block;endFill=1;endSize=7;fontSize=11;fontColor={INK};labelBackgroundColor=#FFFFFF;"
LINE = f"html=1;endArrow=none;strokeColor={MUTED};strokeWidth=1.2;"


class Diagram:
    def __init__(self, name):
        self.name, self.cells, self.n = name, [], 0

    def _id(self):
        self.n += 1
        return f"c{self.n}"

    def zone(self, label, x, y, w, h, colour="blue", size=14):
        fill, stroke, title = ZONES[colour]
        style = (f"rounded=1;arcSize=3;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};strokeWidth=1.5;"
                 f"verticalAlign=top;fontStyle=1;fontSize={size};fontColor={title};spacingTop=4;")
        return self.vertex(label, x, y, w, h, style)

    def box(self, label, x, y, w, h, colour="blue", bold=False, size=12, fill="#FFFFFF", extra=""):
        stroke = ZONES[colour][1]
        style = (f"rounded=1;arcSize=10;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};strokeWidth=1.5;"
                 f"fontSize={size};fontColor={INK};{'fontStyle=1;' if bold else ''}{extra}")
        return self.vertex(label, x, y, w, h, style)

    def text(self, label, x, y, w, h, size=12, extra=""):
        return self.vertex(label, x, y, w, h, f"text;html=1;align=center;verticalAlign=middle;whiteSpace=wrap;fontSize={size};fontColor={INK};{extra}")

    def vertex(self, label, x, y, w, h, style):
        cid = self._id()
        self.cells.append(f'<mxCell id="{cid}" value="{escape(label, {chr(34): "&quot;"})}" style="{style}" vertex="1" parent="1">'
                          f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def edge(self, src, dst, label="", style=EDGE, points=(), exit=None, entry=None, extra=""):
        cid = self._id()
        st = style + extra
        if exit:
            st += f"exitX={exit[0]};exitY={exit[1]};exitDx=0;exitDy=0;"
        if entry:
            st += f"entryX={entry[0]};entryY={entry[1]};entryDx=0;entryDy=0;"
        pts = "".join(f'<mxPoint x="{px}" y="{py}"/>' for px, py in points)
        geo = f'<mxGeometry relative="1" as="geometry">{f"<Array as={chr(34)}points{chr(34)}>{pts}</Array>" if pts else ""}</mxGeometry>'
        self.cells.append(f'<mxCell id="{cid}" value="{escape(label)}" style="{st}" edge="1" parent="1" source="{src}" target="{dst}">{geo}</mxCell>')
        return cid

    def free_line(self, points, extra=""):
        cid = self._id()
        (sx, sy), *mid, (tx, ty) = points
        pts = "".join(f'<mxPoint x="{px}" y="{py}"/>' for px, py in mid)
        self.cells.append(
            f'<mxCell id="{cid}" value="" style="html=1;endArrow=none;strokeColor={MUTED};strokeWidth=1.5;{extra}" edge="1" parent="1">'
            f'<mxGeometry relative="1" as="geometry"><mxPoint x="{sx}" y="{sy}" as="sourcePoint"/><mxPoint x="{tx}" y="{ty}" as="targetPoint"/>'
            f'{f"<Array as={chr(34)}points{chr(34)}>{pts}</Array>" if pts else ""}</mxGeometry></mxCell>')

    def callout(self, n, x, y):
        return self.vertex(str(n), x, y, 24, 24, f"ellipse;html=1;fillColor=#FFFFFF;strokeColor={INK};strokeWidth=1.5;fontStyle=1;fontSize=12;fontColor={INK};")

    def save(self):
        xml = ('<mxfile host="build_diagrams.py"><diagram name="' + self.name + '"><mxGraphModel grid="0" page="0" background="#FFFFFF">'
               '<root><mxCell id="0"/><mxCell id="1" parent="0"/>' + "".join(self.cells) + "</root></mxGraphModel></diagram></mxfile>")
        path = HERE / f"{self.name}.drawio"
        path.write_text(xml, encoding="utf-8")
        return path


def b(t):
    return f"<b>{t}</b>"


def small(t):
    return f'<span style="font-size:11px;color:{MUTED}">{t}</span>'


# ---------------------------------------------------------------- A1 architecture
def a1_architecture():
    d = Diagram("a1_architecture")
    d.zone("Data sources", 20, 20, 250, 470, "blue")
    d.zone("Offline ML pipeline (CRISP-DM)", 310, 20, 260, 470, "green")
    d.zone("Azure for Students<br>Australia East · Docker", 610, 20, 290, 470, "orange", size=13)
    d.vertex("", 864, 30, 26, 26, "image;aspect=fixed;html=1;points=[];image=img/lib/azure2/containers/App_Services.svg;")
    s1 = d.box(f"{b('Corrected CSE-CIC-IDS2018')}<br>{small('training &amp; internal test')}", 40, 70, 210, 70)
    s2 = d.box(f"{b('Corrected CIC-IDS2017')}<br>{small('external test only')}", 40, 175, 210, 70)
    s3 = d.box(f"{b('Isolated attack lab')}<br>{small('Kali → Ubuntu, host-only network;<br>flows via corrected CICFlowMeter')}", 40, 280, 210, 90)
    p1 = d.box("Clean &amp; de-duplicate", 330, 70, 220, 50, "green")
    p2 = d.box("Session-aware split<br>+ class weighting", 330, 150, 220, 55, "green")
    p3 = d.box("Models: Random Forest · XGBoost · LightGBM<br>+ Isolation Forest (benign-only)", 330, 235, 220, 70, "green")
    p4 = d.box("Evaluation (frozen models):<br>internal · external · lab", 330, 345, 220, 60, "green")
    c1 = d.box(b("FastAPI scoring service"), 630, 78, 250, 50, "orange")
    c2 = d.box(f"{b('Threat analysis layer')}<br>{small('SHAP or anomaly score · candidate ATT&amp;CK<br>(or unmapped) · severity &amp; response')}", 630, 150, 250, 80, "orange")
    c3 = d.vertex(b("SQLite alert store"), 695, 260, 120, 70,
                  f"shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;size=12;fillColor=#FFFFFF;strokeColor={ZONES['orange'][1]};strokeWidth=1.5;fontSize=12;fontColor={INK};")
    c4 = d.box(f"{b('Streamlit dashboard')}<br>{small('alert feed · trends · explanations · metrics')}", 630, 365, 250, 65, "orange")
    actor = f"shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;strokeColor={INK};fillColor=#FFFFFF;strokeWidth=1.5;fontSize=12;fontColor={INK};"
    u1 = d.vertex("SMB owner /<br>IT manager", 975, 200, 30, 60, actor)
    u2 = d.vertex("SOC / MSP<br>analyst", 975, 345, 30, 60, actor)
    d.box("Security &amp; compliance: HTTPS · authentication · pseudonymised identifiers · Privacy Act 1988 · "
          "Essential Eight · NIST CSF 2.0 (Detect/Respond) · CI/CD via GitHub Actions", 20, 525, 990, 45, "grey", fill="#F5F6F8", size=12)
    d.edge(s1, p1, exit=(1, 0.36), entry=(0, 0.5))
    for p in (p1, p2, p3):
        pass
    d.edge(p1, p2, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(p2, p3, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(p3, p4, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(s2, p4, extra="dashed=1;", exit=(1, 0.5), entry=(0, 0.3), points=[(290, 210), (290, 363)])
    d.edge(s3, p4, extra="dashed=1;", exit=(1, 0.6), entry=(0, 0.7), points=[(290, 334), (290, 387)])
    d.edge(p3, c1, "trained model", extra=f"strokeColor={ZONES['green'][1]};fontColor={ZONES['green'][2]};", exit=(1, 0.5), entry=(0, 0.3), points=[(590, 270), (590, 93)])
    d.edge(s3, c1, "replayed stream", extra=f"strokeColor={ZONES['blue'][1]};fontColor={ZONES['blue'][2]};dashed=1;", exit=(0.5, 1), entry=(0, 0.75),
           points=[(145, 507), (600, 507), (600, 115)])
    d.edge(c1, c2, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(c2, c3, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(c3, c4, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(c4, u1, exit=(1, 0.35), entry=(0, 0.5), points=[(930, 388), (930, 230)])
    d.edge(c4, u2, exit=(1, 0.65), entry=(0, 0.5), points=[(940, 407), (940, 375)])
    return d


# ---------------------------------------------------------------- A2: ML pipeline
def w5_ml_pipeline():
    d = Diagram("w5_ml_pipeline")
    d.zone("Data preparation", 20, 20, 1060, 125, "blue")
    d1 = d.box("Corrected CSE-CIC-IDS2018<br>(Liu et al., 2022)", 40, 62, 220, 62)
    d2 = d.box("Clean: drop NaN/∞,<br>de-duplicate", 300, 62, 220, 62)
    d3 = d.box("Harmonise labels<br>('Attempted' flows handled)", 560, 62, 220, 62)
    d4 = d.box("Session-aware split:<br>train / validation / test", 820, 62, 240, 62)
    d.zone("Training (fit on train, tune on validation)", 20, 180, 500, 300, "green", size=13)
    t1 = d.box("Fit preprocessing<br>(train only)", 40, 222, 200, 58, "green")
    t2 = d.box("Class weighting", 290, 222, 200, 58, "green")
    t3 = d.box("Isolation Forest<br>(benign flows only)", 40, 312, 200, 58, "green")
    t4 = d.box("Train Random Forest ·<br>XGBoost · LightGBM", 290, 312, 200, 58, "green")
    t5 = d.box("Tune thresholds<br>(validation only)", 40, 402, 200, 58, "green")
    t6 = d.box(b("Frozen models"), 290, 402, 200, 58, "green")
    d.zone("Evaluation · apply only (no fitting)", 560, 180, 520, 300, "orange", size=13)
    m = d.box("Metrics: per-class &amp; macro<br>precision, recall, F1;<br>confusion matrix, FPR,<br>PR-AUC, latency", 580, 228, 220, 112, "orange")
    s = d.box("SHAP explanations<br>(TreeSHAP)", 580, 392, 220, 58, "orange")
    e1 = d.box("Internal test (held-out)", 840, 222, 220, 50, "orange")
    e2 = d.box("External: corrected CIC-IDS2017<br>(binary + shared classes)", 840, 292, 220, 62, "orange")
    e3 = d.box("Lab captures<br>(port scan = withheld class)", 840, 374, 220, 62, "orange")
    for a, c in ((d1, d2), (d2, d3), (d3, d4)):
        d.edge(a, c, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(d4, t1, "train", exit=(0.15, 1), entry=(0.5, 0), points=[(856, 158), (140, 158)])
    d.edge(d4, t5, "validation", exit=(0.3, 1), entry=(0, 0.5), points=[(892, 168), (30, 168), (30, 431)])
    d.edge(d4, e1, "test", extra="dashed=1;", exit=(0.55, 1), entry=(0.5, 0), points=[(952, 200), (950, 200)])
    d.edge(t1, t2, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(t1, t3, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(t2, t4, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(t4, t6, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(t3, t6, exit=(1, 0.5), entry=(0, 0.3), points=[(265, 341), (265, 419)])
    d.edge(t5, t6, exit=(1, 0.75), entry=(0, 0.75))
    d.edge(t6, m, "apply", extra="dashed=1;", exit=(1, 0.5), entry=(0, 0.8), points=[(540, 431), (540, 318)])
    for e, y in ((e1, 0.25), (e2, 0.5), (e3, 0.75)):
        d.edge(e, m, extra="dashed=1;", exit=(0, 0.5), entry=(1, y))
    d.edge(m, s, "explain alerts", extra="dashed=1;", exit=(0.5, 1), entry=(0.5, 0))
    d.free_line([(40, 515), (100, 515)], f"endArrow=block;endFill=1;endSize=7;")
    d.text("fit / train", 105, 503, 90, 24, 12, "align=left;")
    d.free_line([(220, 515), (280, 515)], f"endArrow=block;endFill=1;endSize=7;dashed=1;")
    d.text("apply only (no fitting)", 285, 503, 170, 24, 12, "align=left;")
    return d


# ---------------------------------------------------------------- A2: attack lab
def w5_attack_lab():
    d = Diagram("w5_attack_lab")
    d.zone("Team laptop · VirtualBox host (NAT disabled, no internet)", 20, 20, 700, 430, "grey", size=13)
    d.zone("Host-only network 192.168.56.0/24", 40, 72, 660, 300, "blue", size=13)
    kali = d.box(f"{b('Kali Linux attacker')}<br>192.168.56.10<br>{small('nmap · Hydra · hping3 · slowhttptest')}", 60, 120, 200, 130)
    ubu = d.box(f"{b('Ubuntu victim')}<br>192.168.56.20<br>{small('SSH · Apache web server')}", 480, 120, 200, 130, "green")
    for i, lab in enumerate(["port scan (T1046)", "SSH brute force (T1110)", "network flood (T1498)", "slow HTTP DoS (T1499)"]):
        y = 0.2 + 0.2 * i
        d.edge(kali, ubu, lab, extra=f"strokeColor=#B96A00;labelBackgroundColor={ZONES['blue'][0]};", exit=(1, y), entry=(0, y))
    d.text(small("arrows: scenario (candidate ATT&amp;CK technique)"), 262, 254, 216, 22, 11)
    sensor = d.box("Capture sensor on victim interface: tcpdump → PCAP → corrected CICFlowMeter", 60, 290, 620, 50, "green")
    d.edge(ubu, sensor, exit=(0.5, 1), entry=(0.84, 0))
    d.text(small("<i>Raw PCAPs never leave the team laptop.</i>"), 40, 385, 660, 26, 12)
    l1 = d.box("Attack execution log<br>(timestamps)", 770, 72, 220, 60)
    l2 = d.box("Label flows against<br>the execution log", 770, 182, 220, 60, "green")
    l3 = d.box("Pseudonymise IP addresses<br>(keyed hash)", 770, 292, 220, 60, "green")
    l4 = d.box(f"{b('Upload flows only')}<br>Azure (Australia East)", 770, 402, 220, 60, "orange")
    d.vertex("", 950, 412, 32, 32, "image;aspect=fixed;html=1;points=[];image=img/lib/azure2/containers/App_Services.svg;")
    d.edge(kali, l1, "commands + times", exit=(0.5, 0), entry=(0, 0.5), points=[(160, 58), (745, 58), (745, 102)])
    d.edge(sensor, l2, "flows", exit=(1, 0.5), entry=(0, 0.5), points=[(750, 315), (750, 212)])
    d.edge(l1, l2, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(l2, l3, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(l3, l4, exit=(0.5, 1), entry=(0.5, 0))
    d.box("Safety controls: host-only adapter only · no bridged/NAT adapters · VM snapshots and rollback · "
          "team-owned VMs only · isolation checklist before each session (Criminal Code Act 1995, Part 10.7)", 20, 485, 970, 48, "grey", fill="#F5F6F8")
    return d


# ---------------------------------------------------------------- A2: use cases
def w5_use_cases():
    d = Diagram("w5_use_cases")
    d.vertex(b("ExplainIDS dashboard"), 210, 20, 520, 640,
             f"rounded=0;whiteSpace=wrap;html=1;fillColor=#F8FAFC;strokeColor={MUTED};strokeWidth=1.5;verticalAlign=top;fontSize=14;fontColor={INK};spacingTop=6;")
    uc = {}
    oval = f"ellipse;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor={ZONES['blue'][1]};strokeWidth=1.5;fontSize=12;fontColor={INK};"
    oval_g = oval.replace(ZONES["blue"][1], ZONES["green"][1])
    left = [("feed", "View alert feed"), ("filter", "Filter and search alerts"), ("shap", "View alert explanation (SHAP)"),
            ("attack", "View ATT&amp;CK context and<br>response guidance"), ("confirm", "Confirm or dismiss alert"),
            ("agg", "View aggregated incidents"), ("export", "Export alert report (CSV)")]
    for i, (k, lab) in enumerate(left):
        uc[k] = d.vertex(lab, 240, 62 + i * 74, 230, 54, oval)
    uc["metrics"] = d.vertex("View model performance<br>metrics", 495, 210, 210, 54, oval_g)
    uc["upload"] = d.vertex("Upload flows or<br>replay stream", 495, 360, 210, 54, oval_g)
    uc["signin"] = d.vertex("Sign in (authentication)", 240, 580, 230, 50, oval)
    actor = f"shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;strokeColor={INK};fillColor=#FFFFFF;strokeWidth=1.5;fontSize=12;fontColor={INK};"
    owner = d.vertex("SMB owner /<br>IT manager", 90, 150, 34, 66, actor.replace("verticalLabelPosition=bottom;verticalAlign=top;", "verticalLabelPosition=top;verticalAlign=bottom;"))
    analyst = d.vertex("SOC / MSP<br>analyst", 90, 420, 34, 66, actor)
    admin = d.vertex("Team<br>administrator", 820, 330, 34, 66, actor)
    api = d.box("«system»<br>ML scoring API", 790, 70, 150, 60, "grey")
    for k in ("feed", "attack", "agg", "export", "signin"):
        d.edge(owner, uc[k], style=LINE, entry=(0, 0.5))
    for k in ("feed", "filter", "shap", "attack", "confirm", "agg", "signin"):
        d.edge(analyst, uc[k], style=LINE, entry=(0, 0.5))
    for k in ("metrics", "upload", "signin"):
        d.edge(admin, uc[k], style=LINE, entry=(1, 0.5))
    d.edge(api, uc["feed"], style=LINE, entry=(1, 0.5))
    return d


# ---------------------------------------------------------------- A2: wireframe
def w5_dashboard_wireframe():
    d = Diagram("w5_dashboard_wireframe")
    grey = "#666666"
    panel = f"rounded=1;arcSize=4;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor={grey};strokeWidth=1.3;fontSize=12;fontColor={INK};verticalAlign=top;align=left;spacingLeft=10;spacingTop=6;"
    field = f"rounded=1;arcSize=12;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor={grey};fontSize=12;fontColor={INK};"
    d.vertex("", 20, 20, 920, 570, f"rounded=0;html=1;fillColor=#FAFAFA;strokeColor={grey};strokeWidth=1.5;")
    d.vertex("", 30, 30, 900, 52, f"rounded=1;arcSize=8;html=1;fillColor=#E6E6E6;strokeColor={grey};")
    d.text(b("ExplainIDS"), 40, 42, 110, 28, 15, "align=left;")
    d.callout(1, 150, 44)
    for lab, x, w in (("Date range: 24 h", 230, 170), ("Severity: all", 412, 140), ("Search alerts…", 564, 200), ("User ▾", 776, 140)):
        d.vertex(lab, x, 41, w, 30, field)
    for i, lab in enumerate(["Alerts (24 h)", "High severity", "Aggregated incidents", "Model FPR (validation)"]):
        d.vertex(f"{lab}<br><b>—</b>", 30 + i * 225, 95, 212, 64, panel.replace("align=left;spacingLeft=10;", "align=center;").replace("verticalAlign=top;", "verticalAlign=middle;"))
    d.callout(4, 664, 100)
    rows = [("12:04", "host-01", "SSH brute force", "High", "T1110", "Open"),
            ("12:03", "host-02", "Benign", "Low", "—", "Reviewed"),
            ("11:58", "host-03", "Network flood", "High", "T1498", "Open"),
            ("11:52", "host-04", "Port scan", "Med", "T1046", "Open")]
    head = ["Time", "Source (pseudonymised)", "Predicted class", "Severity", "ATT&amp;CK", "Status"]
    td = 'style="border:1px solid #999;padding:3px 6px"'
    table = (f'<b>Alert feed</b><table style="border-collapse:collapse;width:100%;margin-top:6px;font-size:11px">'
             f'<tr style="background:#E6E6E6">{"".join(f"<th {td}>{h}</th>" for h in head)}</tr>'
             + "".join(f'<tr>{"".join(f"<td {td}>{c}</td>" for c in r)}</tr>' for r in rows) + "</table>")
    d.vertex(table, 30, 172, 600, 230, panel)
    d.vertex(b("Alert detail"), 645, 172, 285, 405, panel)
    d.text(b("Top SHAP features"), 660, 205, 170, 22, 12, "align=left;")
    d.callout(2, 893, 204)
    for i, (lab, w) in enumerate((("SYN flags", 120), ("Flow duration", 98), ("Packet rate", 84), ("Bwd packets", 60), ("Dst port", 38))):
        y = 234 + i * 24
        d.text(lab, 660, y, 95, 20, 11, "align=left;")
        d.vertex("", 760, y + 4, w, 12, f"rounded=0;html=1;fillColor=#A6A6A6;strokeColor=none;")
    d.vertex("ATT&amp;CK: T1110 Brute Force<br>(candidate)", 660, 368, 255, 50, field + "fillColor=#F0F0F0;")
    d.callout(3, 902, 360)
    d.text(f"{b('Recommended response')}<br>Review SSH activity;<br>restrict repeated attempts.", 660, 428, 255, 70, 12, "align=left;verticalAlign=top;")
    d.vertex("Confirm", 660, 520, 120, 34, field + "fillColor=#F0F0F0;")
    d.vertex("Dismiss", 795, 520, 120, 34, field + "fillColor=#F0F0F0;")
    d.vertex(b("Alerts over time"), 30, 415, 290, 162, panel)
    pts = [(48, 548), (78, 540), (108, 544), (138, 520), (168, 528), (198, 492), (228, 512), (258, 505), (288, 486), (308, 494)]
    d.free_line(pts, "strokeColor=#808080;strokeWidth=2;")
    d.free_line([(45, 452), (45, 560), (310, 560)], "strokeColor=#808080;strokeWidth=1;")
    d.vertex(b("Attack distribution"), 335, 415, 295, 162, panel)
    for i, (lab, h) in enumerate((("SSH", 80), ("DoS", 58), ("Scan", 36))):
        x = 375 + i * 85
        d.vertex("", x, 545 - h, 50, h, "rounded=0;html=1;fillColor=#A6A6A6;strokeColor=#808080;")
        d.text(lab, x - 10, 548, 70, 20, 11)
    d.free_line([(355, 452), (355, 545), (615, 545)], "strokeColor=#808080;strokeWidth=1;")
    legend = "  ".join(f"{n} = {t}" for n, t in (("①", "FR7 dashboard views"), ("②", "FR4 explanations"), ("③", "FR5 ATT&amp;CK guidance"), ("④", "FR6 aggregation")))
    d.text(legend, 20, 600, 920, 26, 13)
    return d


BUILDERS = {f.__name__: f for f in (a1_architecture, w5_ml_pipeline, w5_attack_lab, w5_use_cases, w5_dashboard_wireframe)}


def export(drawio_path):
    png = drawio_path.with_suffix(".png")
    subprocess.run([str(DRAWIO), "--export", "--format", "png", "--scale", "2.5", "--border", "12",
                    "--output", str(png), str(drawio_path)], check=True, capture_output=True, timeout=120)
    return png


if __name__ == "__main__":
    names = sys.argv[1:] or list(BUILDERS)
    for name in names:
        path = BUILDERS[name]().save()
        print(export(path))
