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


# ---------------------------------------------------------------- A2 Week 7: architecture v2 (as built)
def w7_architecture():
    d = Diagram("w7_architecture")
    d.zone("Data sources", 20, 20, 230, 440, "blue")
    s1 = d.box(f"{b('Corrected CIC-IDS2017')}<br>{small('trains the deployed model;<br>RQ1–RQ3 experiments')}", 35, 65, 200, 80)
    s2 = d.box(f"{b('Corrected CSE-CIC-IDS2018')}<br>{small('second network for RQ1/RQ3;<br>all attacks + 5% benign sample')}", 35, 175, 200, 85)
    s3 = d.box(f"{b('Isolated lab flows')}<br>{small('own traffic, labelled from<br>the attack schedule')}", 35, 290, 200, 80)
    d.zone("Offline pipeline (Python, seed 42)", 280, 20, 270, 440, "green", size=13)
    p1 = d.box("Clean · harmonise labels ·<br>global de-duplication", 295, 65, 240, 55, "green")
    p2 = d.box("Chronological split per class<br>70 / 10 / 20 · cap 60k per class", 295, 145, 240, 55, "green")
    p3 = d.box("LightGBM · XGBoost · Random Forest<br>+ Isolation Forest (benign only)", 295, 225, 240, 58, "green")
    p4 = d.box(f"{b('Evaluation')}<br>{small('baseline · RQ1 cross-dataset ·<br>RQ2 SHAP stability · RQ3 unseen · lab')}", 295, 310, 240, 75, "green")
    d.zone("Artefacts", 580, 20, 170, 440, "purple")
    cyl = (f"shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;size=10;fillColor=#FFFFFF;"
           f"strokeColor={ZONES['purple'][1]};strokeWidth=1.5;fontSize=11;fontColor={INK};")
    a1 = d.vertex(f"{b('detector.joblib')}<br>model + thresholds", 595, 223, 140, 62, cyl)
    a2 = d.vertex(f"{b('model_card.json')}<br>test metrics, SHAP", 595, 305, 140, 58, cyl)
    a3 = d.vertex(f"{b('replay.parquet')}<br>held-out test flows", 595, 141, 140, 62, cyl)
    a4 = d.vertex(f"{b('research.json')}<br>RQ1–RQ3 answers", 595, 380, 140, 58, cyl)
    d.zone("Docker container · FastAPI + web console", 780, 20, 270, 440, "orange", size=13)
    c1 = d.box(f"{b('FastAPI')}<br>{small('/replay · /score-csv · /predict ·<br>/model · /health')}", 795, 65, 240, 70, "orange")
    c2 = d.box(f"{b('Scoring')}<br>{small('classifier + anomaly → SHAP top-5 →<br>candidate ATT&amp;CK, severity, response')}", 795, 160, 240, 75, "orange")
    c3 = d.box(f"{b('Web console')}<br>{small('Traffic replay · Incidents · ATT&amp;CK ·<br>Model lab · Findings · Analyse a file')}", 795, 260, 240, 75, "orange")
    c4 = d.box(f"{b('Static export')}<br>{small('pre-scored replay; free static hosting')}", 795, 360, 240, 60, "orange")
    actor = f"shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;strokeColor={INK};fillColor=#FFFFFF;strokeWidth=1.5;fontSize=12;fontColor={INK};"
    u1 = d.vertex("SMB IT manager /<br>analyst", 1100, 265, 30, 60, actor)
    d.box("Deployment target: Azure for Students App Service (container) or a free Hugging Face Space · $10 budget alert · "
          "shut down after marking", 280, 475, 770, 40, "orange", fill="#FFF4E5", size=11)
    d.box("Engineering &amp; security: GitHub Actions CI (pytest + privacy guard) · API key on /predict · bounded uploads · "
          "invalid rows dropped · keyed-hash pseudonymisation for lab data · public code, private data", 20, 528, 1030, 40, "grey", fill="#F5F6F8", size=11)
    for s, y in ((s1, 0.4), (s2, 0.5), (s3, 0.6)):
        d.edge(s, p1 if s is s1 else p4, extra="" if s is s1 else "dashed=1;", exit=(1, 0.5), entry=(0, y) if s is s1 else (0, y))
    for a, c in ((p1, p2), (p2, p3), (p3, p4)):
        d.edge(a, c, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(p2, a3, "test split", exit=(1, 0.5), entry=(0, 0.5))
    d.edge(p3, a1, "model", exit=(1, 0.5), entry=(0, 0.5))
    d.edge(p4, a2, exit=(1, 0.3), entry=(0, 0.5))
    d.edge(p4, a4, exit=(1, 0.8), entry=(0, 0.5), points=[(565, 370), (565, 409)])
    for a, y in ((a3, 0.3), (a1, 0.55), (a2, 0.8)):
        d.edge(a, c1, extra="dashed=1;", exit=(1, 0.5), entry=(0, y))
    d.edge(a4, c3, extra="dashed=1;", exit=(1, 0.5), entry=(0, 0.6))
    d.edge(c1, c2, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(c2, c3, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(c3, c4, "export", exit=(0.5, 1), entry=(0.5, 0))
    d.edge(c3, u1, exit=(1, 0.5), entry=(0, 0.5))
    return d


# ---------------------------------------------------------------- A2 Week 7: sequence (one replay batch)
def w7_sequence():
    d = Diagram("w7_sequence")
    names = ["Analyst", "Web console", "FastAPI", "Detector<br>(classifier + IF)", "Explainer<br>(TreeSHAP)", "Threat map<br>(ATT&amp;CK)"]
    xs = [70 + i * 175 for i in range(len(names))]
    bottom = 640
    for name, x in zip(names, xs):
        d.box(b(name), x - 70, 20, 140, 46, "grey" if name == "Analyst" else "blue", size=12)
        d.free_line([(x, 66), (x, bottom)], "dashed=1;strokeColor=#9AA5B1;")

    def msg(i, j, y, label, ret=False):
        style = "endArrow=open;endSize=8;" + ("dashed=1;" if ret else "endFill=1;endArrow=block;")
        d.free_line([(xs[i], y), (xs[j], y)], style)
        left = min(xs[i], xs[j])
        d.text(label, left + 6, y - 22, abs(xs[j] - xs[i]) - 12, 20, 11)

    steps = [(0, 1, "Start replay"), (1, 2, "GET /replay?cursor&amp;n"), (2, 3, "predict + anomaly(batch)"),
             (3, 2, "classes, outlier flags", True), (2, 4, "top_features(flagged flows)"), (4, 2, "SHAP top-5 per alert", True),
             (2, 5, "context_for(class)"), (5, 2, "technique, tactic, severity, response", True),
             (2, 1, "flows + alerts (JSON)", True), (1, 0, "queue, KPIs, network map", True),
             (0, 1, "open alert"), (1, 0, "why · technique · response", True),
             (0, 1, "Confirm / Dismiss")]
    for k, (i, j, label, *ret) in enumerate(steps):
        msg(i, j, 105 + k * 37 + (22 if k >= 1 else 0) + (14 if k >= 10 else 0), label, bool(ret))
    # UML loop frame around the repeated messages (2-10): transparent, so nothing underneath is hidden
    d.vertex(f"{b('loop')} every second while replaying", xs[0] + 30, 117, xs[-1] - xs[0] + 20, 358,
             f"rounded=0;html=1;fillColor=none;strokeColor={MUTED};strokeWidth=1.2;dashed=1;align=left;verticalAlign=top;"
             f"spacingLeft=6;fontSize=11;fontColor={INK};")
    d.text(small("The API is stateless: each viewer keeps its own cursor, so many people can watch at once."),
           xs[0] - 60, bottom + 8, xs[-1] - xs[0] + 120, 22, 11)
    return d


# ---------------------------------------------------------------- A2 Week 7: sequence (sign-in, triage, repair)
def w7_triage_sequence():
    d = Diagram("w7_triage_sequence")
    names = ["Analyst", "Web console", "FastAPI", "Site envelope<br>(local normal)", "Triage store<br>(SQLite)", "Repair script"]
    xs = [70 + i * 175 for i in range(len(names))]
    bottom = 640
    for name, x in zip(names, xs):
        d.box(b(name), x - 70, 20, 140, 46, "grey" if name == "Analyst" else "blue", size=12)
        d.free_line([(x, 66), (x, bottom)], "dashed=1;strokeColor=#9AA5B1;")

    def msg(i, j, y, label, ret=False):
        style = "endArrow=open;endSize=8;" + ("dashed=1;" if ret else "endFill=1;endArrow=block;")
        d.free_line([(xs[i], y), (xs[j], y)], style)
        left = min(xs[i], xs[j])
        d.text(label, left + 6, y - 22, abs(xs[j] - xs[i]) - 12, 20, 11)

    steps = [(0, 1, "Sign in"), (1, 2, "POST /auth/login (HTTPS)"), (2, 1, "session cookie (HttpOnly)", True),
             (0, 1, "Dismiss alert"), (1, 2, "POST /alerts/{id}/status"),
             (2, 3, "resembles this site's normal?"), (3, 2, "eligible / not eligible", True),
             (2, 4, "record decision, features, eligibility"), (2, 1, "saved; retrain: yes / no", True),
             (1, 0, "toast with the reason", True),
             (5, 2, "GET /triage/repair-set.csv"), (2, 4, "eligible dismissals"), (4, 2, "model features, no addresses", True),
             (2, 5, "repair set", True)]
    for k, (i, j, label, *ret) in enumerate(steps):
        msg(i, j, 105 + k * 36 + (14 if k >= 3 else 0) + (18 if k >= 10 else 0), label, bool(ret))
    d.text(small("A dismissal retrains the model only if the flow resembles the site's normal traffic; "
                 "every write needs a signed-in session or the collector key."),
           xs[0] - 60, bottom + 8, xs[-1] - xs[0] + 120, 22, 11)
    return d


# ---------------------------------------------------------------- A2 Week 7: evaluation framework
def w7_evaluation():
    d = Diagram("w7_evaluation")
    d.zone("Shared preparation (same for every experiment)", 20, 20, 1020, 110, "blue")
    steps = ["Corrected CIC releases<br>(2017 · 2018 · lab)", "Global de-duplication<br>(no vector in two splits)",
             "Chronological split<br>per class 70/10/20", "Cap 60k flows per class<br>seed 42"]
    ids_ = [d.box(t, 40 + i * 250, 60, 220, 52) for i, t in enumerate(steps)]
    for a, c in zip(ids_, ids_[1:]):
        d.edge(a, c, exit=(1, 0.5), entry=(0, 0.5))
    cols = [("RQ1 · Does it work on a new network?", "green",
             ["Train on one dataset", "Test on both test splits<br>(same flows per target)",
              "All features vs portable<br>(no port / TCP window)", "Recall, FPR, macro F1 over<br>12 common classes · SHAP shift"]),
            ("RQ2 · Do explanations stay the same?", "purple",
             ["Fix training rows and<br>500 test attack flows", "Retrain with 5 seeds<br>(bagging on)",
              "Per-alert top-5 SHAP<br>Jaccard (same prediction)", "Global top-10 Jaccard,<br>Spearman · macro F1 per seed"]),
            ("RQ3 · Can it catch unseen attacks?", "orange",
             ["Remove one attack class<br>from train + validation", "Classifier + Isolation Forest<br>(raw vs signed-log input)",
              "Score every flow<br>of the withheld class", "Detection, benign FPR,<br>'mistaken for' class"])]
    for c, (title, colour, items) in enumerate(cols):
        x = 20 + c * 345
        d.zone(title, x, 160, 330, 400, colour, size=13)
        boxes = [d.box(t, x + 25, 205 + i * 85, 280, 58, colour) for i, t in enumerate(items)]
        for a, z in zip(boxes, boxes[1:]):
            d.edge(a, z, exit=(0.5, 1), entry=(0.5, 0))
    d.box("Every result: script + JSON/Markdown in docs/results/ · metrics per rule 4 (precision, recall, F1 macro and per class, "
          "benign FPR, confusion matrix; never accuracy alone) · summarised in docs/RESEARCH.md and the console's Findings tab",
          20, 580, 1020, 44, "grey", fill="#F5F6F8", size=11)
    return d


def w7_repair_loop():
    d = Diagram("w7_repair_loop")
    d.zone("Site network (authorised, passive)", 20, 20, 300, 340, "blue")
    d.zone("Detection and triage", 360, 20, 330, 340, "green")
    d.zone("Local repair (no attack labels needed)", 730, 20, 330, 340, "orange", size=13)
    cap = d.box(f"{b('Bounded capture')}<br>{small('dumpcap · full packets · time and byte limits')}", 40, 70, 260, 62)
    ext = d.box(f"{b('Flow extraction')}<br>{small('corrected CICFlowMeter in WSL · 83 features')}", 40, 170, 260, 62)
    val = d.box(f"{b('Validation')}<br>{small('schema, finite values · unusable rows counted')}", 40, 270, 260, 62)
    d.edge(cap, ext, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(ext, val, exit=(0.5, 1), entry=(0.5, 0))
    score = d.box(f"{b('Score')}<br>{small('classifier + anomaly detector, vetoed by the site envelope')}", 380, 70, 290, 62, "green")
    console = d.box(f"{b('Console alert')}<br>{small('SHAP reasons · candidate ATT&amp;CK technique')}", 380, 170, 290, 62, "green")
    tri = d.box(f"{b('Analyst triage')}<br>{small('confirm · dismiss (false alarm) · reopen')}", 380, 270, 290, 62, "green")
    d.edge(val, score, exit=(1, 0.5), entry=(0, 0.5), points=[(330, 301), (330, 101)])
    d.edge(score, console, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(console, tri, exit=(0.5, 1), entry=(0.5, 0))
    store = d.box(f"{b('Durable triage store')}<br>{small('SQLite · decision + model features · no addresses')}", 750, 270, 290, 62, "orange")
    repair = d.box(f"{b('Repair set')}<br>{small('dismissed alerts = analyst-confirmed benign flows')}", 750, 170, 290, 62, "orange")
    model = d.box(f"{b('repair_model.py')}<br>{small('retrain with repair set · attach site normal traffic as exemplar envelope')}", 750, 70, 290, 62, "orange")
    d.edge(tri, store, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(store, repair, exit=(0.5, 0), entry=(0.5, 1))
    d.edge(repair, model, exit=(0.5, 0), entry=(0.5, 1))
    d.edge(model, score, label="served model", exit=(0, 0.5), entry=(1, 0.5))
    d.box("Every repair is reported before and after on the benchmark test split (detection) and on local traffic (alert "
          "rate), so a gain on one cannot hide a loss on the other.", 20, 380, 1040, 40, "grey", fill="#F5F6F8", size=11)
    return d


def w7_realnet_design():
    d = Diagram("w7_realnet_design")
    d.zone("Data (each used for one purpose only)", 20, 20, 1040, 150, "blue")
    day0 = d.box(f"{b('Previous day')}<br>{small('2 sessions · 222 flows · local repair flows and site envelope only')}", 40, 60, 320, 86)
    blocks = d.box(f"{b('Evaluation evening')}<br>{small('12 blocks · 5 min or 90 MB each · 10 min apart · scored only')}", 380, 60, 320, 86)
    bench = d.box(f"{b('Benchmark test split')}<br>{small('later period, never trained on · attack detection')}", 720, 60, 320, 86)
    d.zone("Conditions (5 label seeds each) · local flows come from the previous day", 20, 195, 640, 300, "green", size=13)
    conds = ["Source only (deployed model)", "Few-shot: + k = 50 labelled target attacks per class",
             "+ 30 lab service flows (does a lab repair transfer?)", "+ 30 local flows: port-spread · triaged · least confident",
             "+ local anomaly rule: threshold · isolation forest · refit · exemplar envelope",
             "All of the above again without port and TCP-window features"]
    cids = [d.box(t, 40, 232 + i * 43, 600, 28, "green", size=11) for i, t in enumerate(conds)]
    for a, z in zip(cids, cids[1:]):
        d.edge(a, z, exit=(0.5, 1), entry=(0.5, 0))
    d.zone("Measures (evening blocks · benchmark test)", 680, 195, 380, 300, "purple", size=13)
    meas = [f"{b('Alert rate per block')}<br>{small('no attacks generated: alerts are upper bounds on false alerts')}",
            f"{b('Per-block sign test')}<br>{small('blocks are the unit; seeds share blocks')}",
            f"{b('Benchmark detection')}<br>{small('class-balanced, same conditions')}",
            f"{b('Mechanism audits')}<br>{small('alerts by service · benign-envelope features · offload counterfactual')}"]
    for t, i in zip(meas, range(len(meas))):
        d.box(t, 700, 240 + i * 62, 340, 50, "purple", size=11)
    d.box("Privacy: household consent · passive capture only · keyed pseudonyms · aggregates in shared outputs · "
          "pcaps stay local. Repeated on a second evening for independence.", 20, 515, 1040, 40, "grey", fill="#F5F6F8", size=11)
    return d


BUILDERS = {f.__name__: f for f in (a1_architecture, w5_ml_pipeline, w5_attack_lab, w5_use_cases, w5_dashboard_wireframe,
                                    w7_architecture, w7_sequence, w7_triage_sequence, w7_evaluation, w7_repair_loop, w7_realnet_design)}


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
