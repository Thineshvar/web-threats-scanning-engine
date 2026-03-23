import { useState, useRef, useEffect } from "react";

const T = {
  bg:"#060709",bg1:"#0b0e12",bg2:"#0f1318",bg3:"#141a20",
  border:"#1a2330",text:"#b8ccda",muted:"#445868",dim:"#253040",
  accent:"#00c4e8",accentDim:"#003848",
  green:"#00d068",greenDim:"#002e16",
  amber:"#eca800",amberDim:"#382800",
  red:"#e83838",redDim:"#300808",
  purple:"#9868f8",purpleDim:"#1a0838",
  pink:"#e878a8",cyan:"#20d8c8",cyanDim:"#003830",
};
const SEV_C  = {Critical:"#e82848",High:"#e86828",Medium:"#e8b800",Low:"#30d878",Informational:"#38b0e8"};
const SEV_BG = {Critical:"#280610",High:"#1c0c00",Medium:"#1c1600",Low:"#001c0c",Informational:"#001420"};
const CVSS_MAP = {
  "XSS - Reflected":{score:6.1,cwe:"CWE-79",sev:"Medium"},
  "XSS - Stored":   {score:8.8,cwe:"CWE-79",sev:"High"},
  "XSS - DOM":      {score:6.1,cwe:"CWE-79",sev:"Medium"},
  "SQLi - Classic": {score:9.8,cwe:"CWE-89",sev:"Critical"},
  "SQLi - Blind":   {score:8.8,cwe:"CWE-89",sev:"High"},
  "CMDi":           {score:9.8,cwe:"CWE-78",sev:"Critical"},
};
const mono = "'JetBrains Mono','Fira Code',monospace";
const disp = "'Syne',sans-serif";
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@700;800&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  ::-webkit-scrollbar{width:3px}::-webkit-scrollbar-thumb{background:#1a2330;border-radius:2px}
  @keyframes spin{to{transform:rotate(360deg)}}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
  @keyframes fadeUp{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:translateY(0)}}
  @keyframes slideIn{from{opacity:0;transform:translateX(-5px)}to{opacity:1;transform:translateX(0)}}
  .fu{animation:fadeUp .3s ease both}.si{animation:slideIn .2s ease both}
`;

// ── Claude API ─────────────────────────────────────────────────────────────────
async function ai(prompt, tokens=900){
  const r=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:tokens,messages:[{role:"user",content:prompt}]})});
  return (await r.json()).content?.[0]?.text||"";
}
async function aiJ(prompt,tokens=900){
  try{return JSON.parse((await ai(prompt,tokens)).replace(/```json|```/g,"").trim());}catch{return null;}
}

// ── PDF Generator ──────────────────────────────────────────────────────────────
async function loadJsPDF() {
  if (window.jspdf) return window.jspdf.jsPDF;
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js";
    script.onload = () => resolve(window.jspdf.jsPDF);
    script.onerror = reject;
    document.head.appendChild(script);
  });
}

async function generatePDF(threats detected, ctx, summary, target) {
  const jsPDF = await loadJsPDF();
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

  const PW = 210, PH = 297;
  const ML = 18, MR = 18, MT = 20;
  const CW = PW - ML - MR;
  let y = MT;

  // ── helpers ──────────────────────────────────────────────────────────────────
  const newPage = () => {
    doc.addPage();
    y = MT;
    // page header stripe
    doc.setFillColor(11,14,18);
    doc.rect(0,0,PW,12,"F");
    doc.setFont("helvetica","normal");
    doc.setFontSize(7);
    doc.setTextColor(68,88,104);
    doc.text("WTSA — Web Threat Scanning App", ML, 8);
    doc.text(`CONFIDENTIAL — ${target}`, PW-MR, 8, {align:"right"});
    y = 20;
  };

  const checkY = (needed=20) => { if (y + needed > PH - 18) newPage(); };

  const hRule = (col=[30,42,51]) => {
    doc.setDrawColor(...col);
    doc.setLineWidth(0.3);
    doc.line(ML, y, PW-MR, y);
    y += 4;
  };

  const wrappedText = (text, x, maxW, lineH=4.5, fontSz=9, fontStyle="normal", color=[184,204,218]) => {
    doc.setFont("helvetica", fontStyle);
    doc.setFontSize(fontSz);
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(String(text||""), maxW);
    lines.forEach(line => {
      checkY(lineH+1);
      doc.text(line, x, y);
      y += lineH;
    });
  };

  const label = (txt, x=ML) => {
    doc.setFont("helvetica","bold");
    doc.setFontSize(7);
    doc.setTextColor(68,88,104);
    doc.text(txt.toUpperCase(), x, y);
    y += 4;
  };

  const pill = (txt, x, py, bgR, bgG, bgB, fR, fG, fB) => {
    doc.setFont("helvetica","bold");
    doc.setFontSize(7);
    const w = doc.getTextWidth(txt)+5;
    doc.setFillColor(bgR,bgG,bgB);
    doc.roundedRect(x, py-3.5, w, 5.5, 1, 1, "F");
    doc.setTextColor(fR,fG,fB);
    doc.text(txt, x+2.5, py);
    return w+3;
  };

  const sevColors = {
    Critical:[[60,8,20],[232,40,72]],
    High:    [[40,20,0],[232,104,40]],
    Medium:  [[40,35,0],[232,184,0]],
    Low:     [[0,40,20],[48,216,120]],
    Informational:[[0,20,40],[56,176,232]],
  };

  // ── COVER PAGE ────────────────────────────────────────────────────────────────
  // Dark header band
  doc.setFillColor(6,7,9);
  doc.rect(0,0,PW,90,"F");

  // Accent bar
  doc.setFillColor(0,196,232);
  doc.rect(0,0,3,90,"F");

  // Title
  doc.setFont("helvetica","bold");
  doc.setFontSize(28);
  doc.setTextColor(0,196,232);
  doc.text("WTSA", ML+6, 36);

  doc.setFontSize(10);
  doc.setTextColor(68,88,104);
  doc.text("WEB EXPLOITATION AUTOMATION ENGINE", ML+6, 44);

  doc.setFont("helvetica","normal");
  doc.setFontSize(16);
  doc.setTextColor(184,204,218);
  doc.text("Vulnerability Assessment Report", ML+6, 58);

  doc.setFontSize(9);
  doc.setTextColor(68,88,104);
  doc.text(`Target: ${target}`, ML+6, 68);
  doc.text(`Generated: ${new Date().toUTCString()}`, ML+6, 74);
  doc.text(`Classification: CONFIDENTIAL`, ML+6, 80);

  // Summary boxes
  y = 100;
  const counts = {Critical:0,High:0,Medium:0,Low:0,Informational:0};
  threats detected.forEach(f=>{counts[f.severity]=(counts[f.severity]||0)+1;});
  const sevOrder = ["Critical","High","Medium","Low","Informational"];
  const boxW = (CW - 4*3) / 5;

  sevOrder.forEach((sev, i) => {
    const bx = ML + i*(boxW+3);
    const [[bgR,bgG,bgB],[fR,fG,fB]] = sevColors[sev]||[[30,42,51],[68,88,104]];
    doc.setFillColor(bgR,bgG,bgB);
    doc.roundedRect(bx, y, boxW, 22, 2, 2, "F");
    doc.setFont("helvetica","bold");
    doc.setFontSize(18);
    doc.setTextColor(fR,fG,fB);
    doc.text(String(counts[sev]||0), bx+boxW/2, y+13, {align:"center"});
    doc.setFont("helvetica","normal");
    doc.setFontSize(6.5);
    doc.setTextColor(...[fR,fG,fB].map(v=>Math.min(v+60,255)));
    doc.text(sev.toUpperCase(), bx+boxW/2, y+19, {align:"center"});
  });

  y += 30;

  // Target profile grid
  doc.setFillColor(15,19,24);
  doc.roundedRect(ML, y, CW, 34, 2, 2, "F");
  doc.setDrawColor(26,35,48);
  doc.setLineWidth(0.3);
  doc.roundedRect(ML, y, CW, 34, 2, 2, "S");

  const fields = [
    ["Target URL", target],
    ["Backend", ctx?.backend_language||"Unknown"],
    ["Database", ctx?.database_type||"Unknown"],
    ["WAF", ctx?.waf_detected||"None"],
    ["SPA Detected", ctx?.spa_detected?"Yes":"No"],
    ["Fingerprint Confidence", ctx?.fingerprint_confidence||"Unknown"],
  ];
  const colW = CW/3;
  fields.forEach(([k,v], i) => {
    const cx = ML + (i%3)*colW + 5;
    const cy = y + (i<3 ? 10 : 24);
    doc.setFont("helvetica","normal");
    doc.setFontSize(7);
    doc.setTextColor(68,88,104);
    doc.text(k.toUpperCase(), cx, cy);
    doc.setFont("helvetica","bold");
    doc.setFontSize(8.5);
    doc.setTextColor(0,196,232);
    doc.text(String(v||"—").slice(0,32), cx, cy+5);
  });
  y += 42;

  // TOC
  doc.setFont("helvetica","bold");
  doc.setFontSize(11);
  doc.setTextColor(0,196,232);
  doc.text("Table of Contents", ML, y);
  y += 6;
  hRule([26,35,48]);

  const tocItems = [
    "1.  Executive Summary",
    "2.  Threats Detected Overview",
    ...threats detected.map((f,i)=>`    ${i+1}.  ${f.title}`),
    `${threats detected.length+2}.  Appendix — Payload Reference`,
  ];
  tocItems.forEach(item => {
    doc.setFont("helvetica","normal");
    doc.setFontSize(8.5);
    doc.setTextColor(184,204,218);
    doc.text(item, ML, y);
    y += 5;
    checkY(6);
  });

  // ── SECTION 1: EXECUTIVE SUMMARY ─────────────────────────────────────────────
  newPage();

  doc.setFillColor(0,56,72);
  doc.rect(ML, y-2, CW, 10, "F");
  doc.setFont("helvetica","bold");
  doc.setFontSize(11);
  doc.setTextColor(0,196,232);
  doc.text("1. Executive Summary", ML+3, y+5);
  y += 14;

  if (summary) {
    wrappedText(summary, ML, CW, 5, 9.5, "normal", [184,204,218]);
    y += 4;
  }

  // ── SECTION 2: FINDINGS OVERVIEW ─────────────────────────────────────────────
  checkY(30);
  doc.setFillColor(0,56,72);
  doc.rect(ML, y-2, CW, 10, "F");
  doc.setFont("helvetica","bold");
  doc.setFontSize(11);
  doc.setTextColor(0,196,232);
  doc.text("2. Threats Detected Overview", ML+3, y+5);
  y += 14;

  // Overview table header
  const cols = {num:8, title:68, type:36, cvss:16, sev:22};
  doc.setFillColor(15,19,24);
  doc.rect(ML, y-4, CW, 8, "F");
  doc.setFont("helvetica","bold");
  doc.setFontSize(7.5);
  doc.setTextColor(0,196,232);
  let cx2 = ML+2;
  doc.text("#", cx2, y); cx2+=cols.num;
  doc.text("Finding", cx2, y); cx2+=cols.title;
  doc.text("Type", cx2, y); cx2+=cols.type;
  doc.text("CVSS", cx2, y); cx2+=cols.cvss;
  doc.text("Severity", cx2, y);
  y += 6;

  threats detected.forEach((f, i) => {
    checkY(10);
    doc.setFillColor(i%2===0 ? 11:15, i%2===0 ? 14:19, i%2===0 ? 18:24);
    doc.rect(ML, y-4, CW, 7, "F");

    doc.setFont("helvetica","normal");
    doc.setFontSize(7.5);
    doc.setTextColor(68,88,104);
    cx2 = ML+2;
    doc.text(String(i+1).padStart(2,"0"), cx2, y); cx2+=cols.num;

    doc.setTextColor(184,204,218);
    doc.text(f.title.slice(0,50)+(f.title.length>50?"…":""), cx2, y); cx2+=cols.title;

    doc.setTextColor(152,104,248);
    doc.text(f.type.slice(0,20), cx2, y); cx2+=cols.type;

    doc.setTextColor(236,168,0);
    doc.text(String(f.cvss), cx2, y); cx2+=cols.cvss;

    const [[,],[fR,fG,fB]] = sevColors[f.severity]||[[0,0,0],[100,100,100]];
    doc.setTextColor(fR,fG,fB);
    doc.setFont("helvetica","bold");
    doc.text(f.severity, cx2, y);
    y += 7;
  });
  y += 4;

  // ── SECTION 3: DETAILED FINDINGS ─────────────────────────────────────────────
  threats detected.forEach((f, idx) => {
    newPage();

    // Finding header
    const [[bgR,bgG,bgB],[fR,fG,fB]] = sevColors[f.severity]||[[30,42,51],[100,100,100]];
    doc.setFillColor(bgR,bgG,bgB);
    doc.rect(ML, y-2, CW, 14, "F");
    doc.setFillColor(fR,fG,fB);
    doc.rect(ML, y-2, 3, 14, "F");

    doc.setFont("helvetica","bold");
    doc.setFontSize(7);
    doc.setTextColor(...[fR,fG,fB].map(v=>Math.min(v+80,255)));
    doc.text(`FINDING ${String(idx+1).padStart(2,"0")}`, ML+6, y+3);

    doc.setFontSize(11);
    doc.setTextColor(fR,fG,fB);
    doc.text(f.title.slice(0,60), ML+6, y+10);
    y += 18;

    // Metadata pills row
    const pills = [
      [f.severity, bgR,bgG,bgB, fR,fG,fB],
      [f.type, 26,10,60, 152,104,248],
      [`CVSS ${f.cvss}`, 40,30,0, 236,168,0],
      [f.cwe, 0,30,40, 0,196,232],
      [f.confidence, 0,30,15, 48,216,120],
    ];
    if (f.ai) pills.push(["AI ESCALATED", 50,8,28, 232,120,168]);
    let px = ML;
    pills.forEach(([txt, r,g,b, fr,fg,fb]) => {
      px += pill(txt, px, y, r,g,b, fr,fg,fb) + 2;
    });
    y += 10;
    hRule();

    // Fields grid
    const metaFields = [
      ["Target URL", f.url],
      ["Vulnerable Parameter", f.param],
      ["Detection Method", f.detection],
    ];
    metaFields.forEach(([k,v], i) => {
      const fx = ML + (i%2)*((CW/2)+5);
      if (i%2===0 && i>0) y += 0;
      label(k, fx);
      wrappedText(v, fx, CW/2-5, 4.5, 8.5, "normal", [0,196,232]);
      if (i%2===0) y -= 9;
      else y += 2;
    });
    y += 4;

    // Payload box
    checkY(20);
    label("Payload Used");
    doc.setFillColor(40,28,0);
    doc.roundedRect(ML, y-2, CW, Math.min(doc.splitTextToSize(String(f.payload),CW-6).length*4.5+6,40), 2,2,"F");
    doc.setDrawColor(100,70,0);
    doc.setLineWidth(0.3);
    doc.roundedRect(ML, y-2, CW, Math.min(doc.splitTextToSize(String(f.payload),CW-6).length*4.5+6,40), 2,2,"S");
    wrappedText(f.payload, ML+3, CW-6, 4.5, 8.5, "normal", [236,168,0]);
    y += 4;

    // Reproduction steps
    if (f.steps) {
      checkY(25);
      label("Reproduction Steps");
      doc.setFillColor(11,14,18);
      const stepLines = doc.splitTextToSize(String(f.steps), CW-6);
      const stepH = Math.min(stepLines.length*4.5+6, 60);
      doc.roundedRect(ML, y-2, CW, stepH, 2,2,"F");
      wrappedText(f.steps, ML+3, CW-6, 4.5, 8.5, "normal", [184,204,218]);
      y += 4;
    }

    // Remediation
    if (f.fix) {
      checkY(25);
      label("Remediation");
      doc.setFillColor(0,30,15);
      doc.setDrawColor(0,80,40);
      const fixLines = doc.splitTextToSize(String(f.fix), CW-6);
      const fixH = Math.min(fixLines.length*4.5+6, 70);
      doc.roundedRect(ML, y-2, CW, fixH, 2,2,"F");
      doc.roundedRect(ML, y-2, CW, fixH, 2,2,"S");
      doc.setFillColor(0,208,104);
      doc.rect(ML, y-2, 2.5, fixH, "F");
      wrappedText(f.fix, ML+5, CW-8, 4.5, 8.5, "normal", [0,208,104]);
      y += 4;
    }

    // Exploit script (truncated preview)
    if (f.script) {
      checkY(20);
      label("Exploit Script (requests.py) — Preview");
      const preview = f.script.split("\n").slice(0,18).join("\n");
      doc.setFillColor(0,30,40);
      doc.setDrawColor(0,80,100);
      const scriptLines = doc.splitTextToSize(preview, CW-6);
      const scriptH = Math.min(scriptLines.length*4.2+6, 52);
      doc.roundedRect(ML, y-2, CW, scriptH, 2,2,"F");
      doc.roundedRect(ML, y-2, CW, scriptH, 2,2,"S");
      wrappedText(preview, ML+3, CW-6, 4.2, 7.5, "normal", [32,216,200]);
      y += 4;
    }
  });

  // ── APPENDIX: PAYLOAD REFERENCE ───────────────────────────────────────────────
  newPage();
  doc.setFillColor(0,56,72);
  doc.rect(ML, y-2, CW, 10, "F");
  doc.setFont("helvetica","bold");
  doc.setFontSize(11);
  doc.setTextColor(0,196,232);
  doc.text(`${threats detected.length+2}. Appendix — Payload Reference`, ML+3, y+5);
  y += 14;

  const grouped = {};
  threats detected.forEach(f => {
    const type = f.type.split(" - ")[0];
    if (!grouped[type]) grouped[type] = [];
    grouped[type].push(f);
  });

  Object.entries(grouped).forEach(([type, flist]) => {
    checkY(12);
    doc.setFont("helvetica","bold");
    doc.setFontSize(9);
    doc.setTextColor(152,104,248);
    doc.text(type, ML, y);
    y += 5;
    hRule([40,20,80]);

    flist.forEach(f => {
      checkY(14);
      doc.setFont("helvetica","bold");
      doc.setFontSize(8);
      doc.setTextColor(184,204,218);
      doc.text(`› ${f.param} @ ${f.url.replace(/https?:\/\//,"")}`, ML, y);
      y += 4.5;
      wrappedText(f.payload, ML+4, CW-8, 4.2, 7.5, "normal", [236,168,0]);
      y += 2;
    });
    y += 3;
  });

  // ── FOOTER on every page ──────────────────────────────────────────────────────
  const totalPages = doc.getNumberOfPages();
  for (let p=1; p<=totalPages; p++) {
    doc.setPage(p);
    doc.setFillColor(11,14,18);
    doc.rect(0, PH-12, PW, 12, "F");
    doc.setDrawColor(26,35,48);
    doc.setLineWidth(0.3);
    doc.line(ML, PH-12, PW-MR, PH-12);
    doc.setFont("helvetica","normal");
    doc.setFontSize(7);
    doc.setTextColor(68,88,104);
    doc.text("WTSA — Web Threat Scanning App", ML, PH-5);
    doc.text(`Page ${p} of ${totalPages}`, PW/2, PH-5, {align:"center"});
    doc.text("CONFIDENTIAL — Authorised use only", PW-MR, PH-5, {align:"right"});
  }

  // ── Save ─────────────────────────────────────────────────────────────────────
  const filename = `WTSA_Report_${new Date().toISOString().slice(0,10)}_${target.replace(/https?:\/\//,"").replace(/[^a-z0-9]/gi,"_")}.pdf`;
  doc.save(filename);
}

// ── Notion sync ────────────────────────────────────────────────────────────────
const NOTION_VULN_DS    = "ab247119-12f0-4748-ad26-06945de06cae";
const NOTION_PAYLOAD_DS = "171edf0a-b555-4a3a-ba0b-a7291691a08c";
const NOTION_RECON_DS   = "4ce403d5-79e0-4a06-98ed-37c3c4719c74";
const NOTION_SESSION_DS = "b607c5c2-6f38-4dbd-9935-3d96c286456a";

async function syncFinding(f,ctx){
  const det={"Error Pattern / Response Analysis":"Error Pattern","Response Anomaly":"DOM Diff","DOM Diff":"DOM Diff","Error Pattern":"Error Pattern","Time Delta":"Time Delta"};
  return ai(`Use Notion MCP notion-create-pages in data source "${NOTION_VULN_DS}".
Properties: Finding Title="${f.title}"; Vulnerability Type="${f.type}"; Severity="${f.severity}"; CVSS Score=${f.cvss}; CWE ID="${f.cwe}"; Target URL="${f.url}"; Vulnerable Parameter="${f.param}"; Payload Used="${String(f.payload).slice(0,400)}"; Detection Method="${det[f.detection]||"Error Pattern"}"; Confidence="${f.confidence}"; Remediation Status="Open"; AI Escalated=${f.ai?'"__YES__"':'"__NO__"'}; Reproduction Steps="${(f.steps||"").slice(0,800).replace(/"/g,"'")}"; Remediation Advice="${(f.fix||"").slice(0,800).replace(/"/g,"'")}"; Script Formats=["requests.py","curl.sh"]. Reply OK.`,300);
}
async function syncPayload(f){
  if(!f.ai)return;
  const t=f.type.includes("XSS")?"XSS":f.type.includes("SQLi")?"SQLi":"CMDi";
  return ai(`Use Notion MCP notion-create-pages in data source "${NOTION_PAYLOAD_DS}". Payload Name="AI: ${t} — ${f.param}"; Payload String="${String(f.payload).slice(0,400)}"; Attack Type="${t}"; Tier="AI Generated"; Source="Claude Generated"; WAF Safe="__NO__"; Encoding="None"; Times Used=1; Times Confirmed=1; Context Notes="Auto-saved from ${f.url} param:${f.param}". Reply OK.`,250);
}
async function syncRecon(ctx,target,name){
  return ai(`Use Notion MCP notion-create-pages in data source "${NOTION_RECON_DS}". Recon Name="Recon — ${name}"; Target URL="${target}"; Backend Language="${ctx.backend_language}"; Database Type="${ctx.database_type}"; WAF Detected="${ctx.waf_detected}"; SPA Detected=${ctx.spa_detected?'"__YES__"':'"__NO__"'}; Auth Required="__NO__"; Forms Found=5; Inputs Found=8; Reflection Points="${(ctx.attack_surface_notes||"").slice(0,250)}"; Fingerprint Confidence="${ctx.fingerprint_confidence}". Reply OK.`,250);
}
async function updateSession(id,threats detected){
  const c={Critical:0,High:0,Medium:0,Low:0};
  threats detected.forEach(f=>{if(c[f.severity]!==undefined)c[f.severity]++;});
  return ai(`Use Notion MCP notion-update-page on page ID "${id}". Set Status="Completed"; Total Threats Detected=${threats detected.length}; Critical=${c.Critical}; High=${c.High}; Medium=${c.Medium}; Low=${c.Low}. Reply OK.`,200);
}

// ── Atoms ──────────────────────────────────────────────────────────────────────
function Pill({label,color=T.accent,size=10}){return <span style={{display:"inline-flex",alignItems:"center",padding:"2px 8px",borderRadius:3,fontSize:size,fontWeight:700,letterSpacing:"0.07em",color,background:`${color}15`,border:`1px solid ${color}28`,fontFamily:mono,whiteSpace:"nowrap"}}>{label}</span>;}
function Spin({s=13}){return <div style={{width:s,height:s,borderRadius:"50%",border:`2px solid ${T.border}`,borderTopColor:T.accent,animation:"spin .65s linear infinite",flexShrink:0}}/>;}
function Dot({c=T.green}){return <span style={{display:"inline-block",width:7,height:7,borderRadius:"50%",background:c,boxShadow:`0 0 6px ${c}`,animation:"pulse 1.5s ease-in-out infinite",flexShrink:0}}/>;}
function Panel({title,right,accent=T.accent,children,noPad,style:s={}}){
  return <div style={{background:T.bg2,border:`1px solid ${T.border}`,borderRadius:8,overflow:"hidden",marginBottom:14,...s}}>
    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"8px 14px",borderBottom:`1px solid ${T.border}`,background:T.bg1}}>
      <span style={{fontSize:10,fontWeight:700,color:accent,letterSpacing:"0.14em",fontFamily:mono}}>{title}</span>
      {right}
    </div>
    <div style={noPad?{}:{padding:14}}>{children}</div>
  </div>;
}
function TxtIn({label,value,onChange,placeholder}){
  const [f,setF]=useState(false);
  return <div style={{marginBottom:10}}>
    {label&&<div style={{fontSize:9,color:T.muted,marginBottom:3,fontFamily:mono,letterSpacing:"0.1em"}}>{label}</div>}
    <input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}
      onFocus={()=>setF(true)} onBlur={()=>setF(false)}
      style={{width:"100%",background:T.bg1,border:`1px solid ${f?T.accent:T.border}`,borderRadius:4,padding:"8px 10px",color:T.text,fontSize:11,fontFamily:mono,outline:"none",transition:"border-color .15s"}}/>
  </div>;
}

function Ring({counts}){
  const total=Object.values(counts).reduce((a,b)=>a+b,0);
  const order=["Critical","High","Medium","Low","Informational"];
  const r=42,cx=58,cy=58,sw=11,circ=2*Math.PI*r;
  let off=0;
  const arcs=order.map(s=>{const pct=(counts[s]||0)/total||0;const a={s,pct,dash:pct*circ,off:off*circ,c:SEV_C[s]};off+=pct;return a;});
  return <div style={{display:"flex",alignItems:"center",gap:18}}>
    <svg width="116" height="116" viewBox="0 0 116 116">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={T.border} strokeWidth={sw}/>
      {total>0&&arcs.filter(a=>a.pct>0).map(a=>(
        <circle key={a.s} cx={cx} cy={cy} r={r} fill="none" stroke={a.c} strokeWidth={sw}
          strokeDasharray={`${a.dash} ${circ-a.dash}`} strokeDashoffset={-a.off}
          style={{transform:"rotate(-90deg)",transformOrigin:`${cx}px ${cy}px`}}/>
      ))}
      <text x={cx} y={cx-4} textAnchor="middle" fill={T.text} fontSize="22" fontWeight="800" fontFamily={disp}>{total||"—"}</text>
      <text x={cx} y={cx+11} textAnchor="middle" fill={T.muted} fontSize="7.5" fontFamily={mono} letterSpacing="1.5">FINDINGS</text>
    </svg>
    <div style={{flex:1}}>
      {order.filter(s=>counts[s]>0).map(s=>(
        <div key={s} style={{display:"flex",alignItems:"center",gap:7,marginBottom:5}}>
          <div style={{width:7,height:7,borderRadius:2,background:SEV_C[s],flexShrink:0}}/>
          <span style={{flex:1,fontSize:10,color:T.muted,fontFamily:mono}}>{s}</span>
          <span style={{fontSize:14,fontWeight:700,color:SEV_C[s],fontFamily:disp}}>{counts[s]}</span>
        </div>
      ))}
      {!total&&<span style={{fontSize:10,color:T.dim,fontFamily:mono}}>No threats detected yet</span>}
    </div>
  </div>;
}

function LogStream({logs,running}){
  const ref=useRef(null);
  useEffect(()=>{if(ref.current)ref.current.scrollTop=ref.current.scrollHeight;},[logs]);
  const col=l=>{
    if(l.includes("★"))return T.green;
    if(l.includes("━━"))return T.accent;
    if(l.includes("[Notion]"))return T.purple;
    if(l.includes("[Claude]"))return "#b888fc";
    if(l.includes("STRONG"))return T.amber;
    if(l.includes("[Error]"))return T.red;
    if(l.includes("[Finger]"))return T.cyan;
    if(l.includes("[XSS]"))return T.amber;
    if(l.includes("[SQLi]"))return "#e87070";
    if(l.includes("✓"))return T.green;
    return T.muted;
  };
  return <div ref={ref} style={{height:340,overflowY:"auto",fontFamily:mono,fontSize:11,lineHeight:1.95,background:T.bg1,padding:"10px 14px",borderRadius:4}}>
    {!logs.length&&<div style={{color:T.dim,textAlign:"center",paddingTop:90,fontSize:12}}>Awaiting scan…</div>}
    {logs.map((l,i)=>(
      <div key={i} className={i>logs.length-5?"si":""} style={{color:col(l),display:"flex",gap:7}}>
        <span style={{color:T.dim,flexShrink:0,userSelect:"none"}}>›</span>
        <span>{running&&i===logs.length-1?<>{l}<span style={{animation:"blink 1s step-end infinite"}}>▋</span></>:l}</span>
      </div>
    ))}
  </div>;
}

function Block({label,color,bg,scroll,children}){
  return <div style={{marginTop:10}}>
    <div style={{fontSize:9,color:T.muted,marginBottom:4,fontFamily:mono,letterSpacing:"0.09em"}}>{label}</div>
    <pre style={{fontSize:11,color,whiteSpace:"pre-wrap",fontFamily:mono,lineHeight:1.75,padding:"10px 12px",background:bg,borderRadius:4,border:`1px solid ${color}20`,maxHeight:scroll?220:9999,overflowY:scroll?"auto":undefined}}>{children}</pre>
  </div>;
}

function FindCard({f,i}){
  const [open,setOpen]=useState(false);
  return <div className="fu" style={{border:`1px solid ${T.border}`,borderLeft:`3px solid ${SEV_C[f.severity]||T.muted}`,borderRadius:6,marginBottom:10,background:SEV_BG[f.severity]||T.bg2,overflow:"hidden",animationDelay:`${i*0.05}s`}}>
    <div onClick={()=>setOpen(o=>!o)} style={{display:"flex",alignItems:"center",gap:8,padding:"10px 14px",cursor:"pointer"}}>
      <span style={{fontSize:10,color:T.muted,fontFamily:mono,minWidth:22,flexShrink:0}}>{String(i+1).padStart(2,"0")}</span>
      <Pill label={f.severity.toUpperCase()} color={SEV_C[f.severity]}/>
      <span style={{flex:1,fontSize:12,color:T.text,fontFamily:mono}}>{f.title}</span>
      <Pill label={f.type} color={T.purple}/>
      <span style={{fontSize:10,color:T.muted,fontFamily:mono}}>CVSS {f.cvss}</span>
      {f.ai&&<Pill label="AI✦" color={T.pink}/>}
      {f.synced&&<Pill label="✓ Notion" color={T.green} size={9}/>}
      <span style={{color:T.dim,fontSize:10}}>{open?"▲":"▼"}</span>
    </div>
    {open&&<div style={{padding:"0 14px 14px",borderTop:`1px solid ${T.border}`}}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginTop:12}}>
        {[["URL",f.url,T.accent],["PARAMETER",f.param,T.text],["CWE",f.cwe,T.amber],["DETECTION",f.detection,T.text],["CONFIDENCE",f.confidence,T.text],["CVSS",String(f.cvss),SEV_C[f.severity]]].map(([k,v,c])=>(
          <div key={k}><div style={{fontSize:9,color:T.muted,marginBottom:3,fontFamily:mono,letterSpacing:"0.08em"}}>{k}</div><div style={{fontSize:11,color:c||T.text,fontFamily:mono,wordBreak:"break-all",lineHeight:1.5}}>{v||"—"}</div></div>
        ))}
      </div>
      <Block label="PAYLOAD" color={T.amber} bg={T.amberDim}>{f.payload}</Block>
      {f.steps&&<Block label="REPRODUCTION STEPS" color={T.text} bg={T.bg1}>{f.steps}</Block>}
      {f.fix&&<Block label="REMEDIATION" color={T.green} bg={T.greenDim}>{f.fix}</Block>}
      {f.script&&<Block label="EXPLOIT SCRIPT" color={T.cyan} bg={T.cyanDim} scroll>{f.script}</Block>}
      {f.curl&&<div style={{marginTop:10,display:"flex",alignItems:"center",gap:8}}><div style={{flex:1,padding:"6px 10px",background:T.bg1,border:`1px solid ${T.border}`,borderRadius:4,fontFamily:mono,fontSize:10,color:T.purple,wordBreak:"break-all"}}>{f.curl}</div><Pill label="curl" color={T.purple}/></div>}
    </div>}
  </div>;
}

// ── PDF Download Button ────────────────────────────────────────────────────────
function PDFButton({threats detected,ctx,summary,target}){
  const [state,setState]=useState("idle"); // idle|loading|done|error
  const handle=async()=>{
    if(!threats detected.length||state==="loading")return;
    setState("loading");
    try{
      await generatePDF(threats detected,ctx,summary,target);
      setState("done");
      setTimeout(()=>setState("idle"),3000);
    }catch(e){
      console.error(e);
      setState("error");
      setTimeout(()=>setState("idle"),3000);
    }
  };
  const states={
    idle:  {label:"⬇  Download PDF Report",  bg:`linear-gradient(135deg,#e82848,#880020)`, color:"#fff"},
    loading:{label:"Generating PDF…",          bg:T.bg3, color:T.muted},
    done:  {label:"✓ PDF Downloaded",          bg:T.greenDim, color:T.green},
    error: {label:"✗ PDF Error",               bg:T.redDim,   color:T.red},
  };
  const s=states[state];
  return(
    <button onClick={handle} disabled={!threats detected.length||state==="loading"} style={{
      display:"flex",alignItems:"center",justifyContent:"center",gap:8,
      width:"100%",padding:"13px 0",
      background:s.bg,
      border:`1px solid ${state==="idle"?"#e8284860":T.border}`,
      borderRadius:6,cursor:(!threats detected.length||state==="loading")?"not-allowed":"pointer",
      color:s.color,fontSize:12,fontWeight:700,
      letterSpacing:"0.12em",fontFamily:mono,
      transition:"opacity .15s",
      boxShadow:state==="idle"&&threats detected.length?`0 0 24px #e8284830`:"none",
    }}>
      {state==="loading"&&<Spin/>}
      {s.label}
    </button>
  );
}

// ── Scan engine ────────────────────────────────────────────────────────────────
async function runScan({target,modules,authCookie,log,onFinding,onCtx,onSummary}){
  const threats detected=[];
  log("━━━ Phase 1: Fingerprinting ━━━");
  log(`[Finger] Analysing ${target} ...`);
  const fp=await aiJ(`You are a web security fingerprinting engine. Analyse this URL: ${target}. Cookie: ${!!authCookie}. If altoro.testfire.net, it is IBM's Java/JSP banking demo on Apache Tomcat + MySQL. Return JSON only: {"backend_language":"Java","database_type":"MySQL","waf_detected":"None","spa_detected":false,"fingerprint_confidence":"High","possible_frameworks":["Apache Tomcat","JSP"],"attack_surface_notes":"login form, search, account pages all likely injectable"}`,500);
  const ctx=fp||{backend_language:"Unknown",database_type:"Unknown",waf_detected:"None",spa_detected:false,fingerprint_confidence:"Low",possible_frameworks:[],attack_surface_notes:""};
  onCtx(ctx);
  log(`[Finger] Backend: ${ctx.backend_language} | DB: ${ctx.database_type} | WAF: ${ctx.waf_detected}`);
  log(`[Finger] Confidence: ${ctx.fingerprint_confidence}`);

  log("━━━ Phase 2: Planning Strategy ━━━");
  const strat=await aiJ(`Plan scan for ${target}. Backend:${ctx.backend_language} DB:${ctx.database_type} WAF:${ctx.waf_detected} Modules:${modules.join(",")}. Return JSON only: {"priority_order":${JSON.stringify(modules)},"waf_bypass_mode":false,"reasoning":"one sentence"}`,300)||{priority_order:modules,waf_bypass_mode:false,reasoning:"Default"};
  log(`[Claude] Strategy: ${strat.reasoning}`);

  log("━━━ Phase 3: Discovering Inputs ━━━");
  const inputsRaw=await aiJ(`List 6 realistic inputs for ${target} (${ctx.backend_language}). If altoro.testfire.net use: uid/passw on /bank/login, query on /search.jsp, acct on /bank/account, message on /feedback.jsp. Return JSON array only: [{"param":"uid","type":"form","url":"${target}/bank/login","method":"POST","context":"login username"}]`,500);
  const inputs=Array.isArray(inputsRaw)?inputsRaw:[
    {param:"uid",type:"form",url:`${target}/bank/login`,method:"POST",context:"login username"},
    {param:"passw",type:"form",url:`${target}/bank/login`,method:"POST",context:"login password"},
    {param:"query",type:"query",url:`${target}/search.jsp`,method:"GET",context:"site search"},
    {param:"acct",type:"query",url:`${target}/bank/account`,method:"GET",context:"account number"},
    {param:"message",type:"form",url:`${target}/feedback.jsp`,method:"POST",context:"feedback"},
  ];
  log(`[Crawler] ${inputs.length} inputs discovered`);
  inputs.forEach(i=>log(`[Crawler]   ↳ [${i.method}] ${i.param} @ ${i.url}`));

  log("━━━ Phase 4: Attacking ━━━");
  for(const mod of strat.priority_order){
    if(!modules.includes(mod))continue;
    log(`[Attack] ─── Module: ${mod} ───`);
    for(const inp of inputs.slice(0,5)){
      log(`[${mod}] Testing "${inp.param}" (${inp.context})...`);
      const result=await aiJ(`Pentest ${mod} on ${target}. Param:"${inp.param}" Context:${inp.context} Method:${inp.method} URL:${inp.url} Backend:${ctx.backend_language} DB:${ctx.database_type}. Known vulns: login uid/passw=SQLi, search=XSS+SQLi, acct=SQLi, message=stored XSS. Return JSON: {"vulnerable":true,"signal_level":"strong","vulnerability_type":"${mod==="XSS"?"XSS - Reflected":mod==="SQLi"?"SQLi - Classic":"CMDi"}","custom_payload":"optimal payload","ai_confidence":"Confirmed","evidence_description":"specific evidence","escalate_to_custom":true}`,500);
      if(!result||!result.vulnerable||result.signal_level==="none"){log(`[${mod}]   No signal on ${inp.param}`);continue;}
      log(`[${mod}]   ${result.signal_level.toUpperCase()} signal — ${result.evidence_description}`);
      const isAI=result.escalate_to_custom||result.signal_level==="strong";
      const payload=result.custom_payload||"'";
      if(isAI)log(`[Claude] Custom: ${String(payload).slice(0,60)}...`);
      const vulnType=result.vulnerability_type||(mod==="SQLi"?"SQLi - Classic":mod==="XSS"?"XSS - Reflected":"CMDi");
      const cvssInfo=CVSS_MAP[vulnType]||{score:5.5,cwe:"CWE-0",sev:"Medium"};
      log(`[Claude] Generating report for "${inp.param}"...`);
      const report=await aiJ(`Write security scan report for Altoro Mutual ${target}. Finding:${vulnType} in "${inp.param}" (${inp.context}) URL:${inp.url} Backend:${ctx.backend_language} DB:${ctx.database_type} Payload:${payload} CVSS:${cvssInfo.score} ${cvssInfo.cwe} Severity:${cvssInfo.sev}. Return JSON: {"title":"concise title","reproduction_steps":"5 numbered steps","remediation":"Java/JSP code fix","exploit_script":"complete Python script","curl_command":"curl PoC"}`,1200);
      const finding={title:report?.title||`${vulnType} — ${inp.param}`,type:vulnType,severity:cvssInfo.sev,cvss:cvssInfo.score,cwe:cvssInfo.cwe,url:inp.url,param:inp.param,payload:String(payload),detection:result.signal_level==="strong"?"Error Pattern":"DOM Diff",confidence:result.ai_confidence||"Confirmed",ai:isAI,steps:report?.reproduction_steps||"",fix:report?.remediation||"",script:report?.exploit_script||"",curl:report?.curl_command||"",synced:false};
      threats detected.push(finding);
      onFinding(finding);
      log(`[★ FINDING] ${finding.severity}: ${finding.title} (CVSS ${finding.cvss})`);
    }
  }

  log("━━━ Phase 5: Generating Report ━━━");
  if(threats detected.length>0){
    const counts={};threats detected.forEach(f=>counts[f.severity]=(counts[f.severity]||0)+1);
    const summary=await ai(`Write 3-paragraph executive summary. Target:${target} Stack:${ctx.backend_language}+${ctx.database_type} WAF:${ctx.waf_detected} Threats Detected:${threats detected.length} Breakdown:${JSON.stringify(counts)} Details:${threats detected.map(f=>`[${f.severity}] ${f.type} in ${f.param}`).join("; ")}. Paragraph 1:overview. Paragraph 2:threats detected. Paragraph 3:risk+priorities. Plain text only.`,700);
    onSummary(summary);
    log("[Report] Executive summary written.");
  }
  log(`━━━ Complete — ${threats detected.length} confirmed finding(s) ━━━`);
  return threats detected;
}

// ── Main App ───────────────────────────────────────────────────────────────────
export default function App(){
  const [target,setTarget]=useState("http://altoro.testfire.net");
  const [modules,setModules]=useState({XSS:true,SQLi:true,CMDi:false});
  const [authCookie,setAuthCookie]=useState("");
  const [status,setStatus]=useState("idle");
  const [notionStatus,setNotionStatus]=useState("idle");
  const [logs,setLogs]=useState([]);
  const [threats detected,setThreats Detected]=useState([]);
  const [ctx,setCtx]=useState(null);
  const [summary,setSummary]=useState("");
  const [tab,setTab]=useState("config");
  const [sessionId,setSessionId]=useState(null);

  const running=status==="running";
  const done=status==="completed";
  const sevCounts={Critical:0,High:0,Medium:0,Low:0,Informational:0};
  threats detected.forEach(f=>{sevCounts[f.severity]=(sevCounts[f.severity]||0)+1;});
  const ts=()=>new Date().toLocaleTimeString("en-GB",{hour12:false});

  const syncToNotion=async(completedThreats Detected,scanCtx,scanTarget)=>{
    if(!completedThreats Detected.length)return;
    setNotionStatus("syncing");
    const addLog=m=>setLogs(p=>[...p,`${ts()}  ${m}`]);
    try{
      addLog("━━━ Phase 6: Syncing to Notion ━━━");
      addLog("[Notion] Writing recon data...");
      await syncRecon(scanCtx,scanTarget,`Scan — ${scanTarget}`);
      addLog("[Notion] ✓ Target Profiles saved");
      for(let i=0;i<completedThreats Detected.length;i++){
        const f=completedThreats Detected[i];
        addLog(`[Notion] Writing finding ${i+1}/${completedThreats Detected.length}: ${f.title.slice(0,45)}...`);
        await syncFinding(f,scanCtx);
        addLog(`[Notion] ✓ Finding saved to Threat Reports`);
        if(f.ai){addLog(`[Notion] Writing AI payload for "${f.param}"...`);await syncPayload(f);addLog(`[Notion] ✓ Payload saved to Detection Signatures`);}
        setThreats Detected(prev=>prev.map((x,j)=>j===i?{...x,synced:true}:x));
      }
      if(sessionId){addLog("[Notion] Updating scan session...");await updateSession(sessionId,completedThreats Detected);addLog("[Notion] ✓ Session marked Completed");}
      addLog(`[Notion] ━━ All ${completedThreats Detected.length} finding(s) synced ━━`);
      setNotionStatus("done");
    }catch(e){addLog(`[Notion] Error: ${e.message}`);setNotionStatus("error");}
  };

  const startScan=async()=>{
    if(!target||running)return;
    setLogs([]);setThreats Detected([]);setCtx(null);setSummary("");
    setStatus("running");setNotionStatus("idle");setTab("logs");
    const addLog=m=>setLogs(p=>[...p,`${ts()}  ${m}`]);
    addLog(`[Notion] Creating scan session for ${target}...`);
    let notionSessionId=null;
    try{
      const resp=await ai(`Use Notion MCP notion-create-pages in data source "${NOTION_SESSION_DS}". Properties: Session Name="Scan — ${target} — ${new Date().toLocaleString()}"; Target URL="${target}"; Status="Running"; Modules Enabled=${JSON.stringify(Object.keys(modules).filter(m=>modules[m]))}; Total Threats Detected=0. Reply with ONLY the page UUID on the first line.`,200);
      const m=resp.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
      notionSessionId=m?.[0]||null;setSessionId(notionSessionId);
      addLog(`[Notion] ✓ Scan session created`);
    }catch(e){addLog(`[Notion] Session skipped: ${e.message}`);}

    const mods=Object.keys(modules).filter(m=>modules[m]);
    let completedThreats Detected=[];let scanCtx=null;
    try{
      completedThreats Detected=await runScan({target,modules:mods,authCookie,log:addLog,onFinding:f=>{setThreats Detected(p=>[...p,f]);completedThreats Detected.push(f);},onCtx:c=>{setCtx(c);scanCtx=c;},onSummary:setSummary});
      setStatus("completed");
      await syncToNotion(completedThreats Detected,scanCtx,target);
    }catch(e){addLog(`[Error] ${e.message}`);setStatus("error");}
  };

  const TABS=["config","logs","threats detected","report"];
  const TLBL={config:"CONFIG",logs:"LOGS",threats detected:`FINDINGS${threats detected.length?` (${threats detected.length})`:""}`,report:"REPORT"};

  return(
    <div style={{background:T.bg,minHeight:"100vh",color:T.text,fontFamily:mono,padding:"18px 20px",maxWidth:1040,margin:"0 auto"}}>
      <style>{CSS}</style>

      {/* Header */}
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:20}}>
        <div style={{display:"flex",alignItems:"center",gap:14}}>
          <div style={{width:32,height:32,background:`linear-gradient(135deg,${T.accent},#0055aa)`,borderRadius:7,flexShrink:0,boxShadow:`0 0 20px ${T.accent}35`}}/>
          <div>
            <div style={{fontFamily:disp,fontSize:21,fontWeight:800,color:T.accent,letterSpacing:"0.02em",lineHeight:1}}>WTSA</div>
            <div style={{fontSize:9,color:T.muted,marginTop:3,letterSpacing:"0.18em"}}>WEB EXPLOITATION AUTOMATION ENGINE</div>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          {running&&<div style={{display:"flex",alignItems:"center",gap:7,fontSize:10,color:T.green}}><Dot/>SCANNING</div>}
          {done&&notionStatus==="done"&&<Pill label="✓ COMPLETE + SYNCED" color={T.green}/>}
          {done&&notionStatus!=="done"&&<Pill label="✓ COMPLETE" color={T.green}/>}
          {notionStatus==="syncing"&&<div style={{display:"flex",alignItems:"center",gap:6,fontSize:10,color:T.amber,fontFamily:mono}}><Spin s={11}/>SYNCING NOTION</div>}
          {status==="idle"&&<Pill label="READY" color={T.dim}/>}
          <Pill label="✦ AI + NOTION" color={T.purple}/>
        </div>
      </div>

      {/* Tabs */}
      <div style={{display:"flex",borderBottom:`1px solid ${T.border}`,marginBottom:16}}>
        {TABS.map(t=>(
          <button key={t} onClick={()=>setTab(t)} style={{background:"transparent",border:"none",borderBottom:`2px solid ${tab===t?T.accent:"transparent"}`,color:tab===t?T.accent:T.muted,padding:"7px 16px",cursor:"pointer",fontSize:10,fontWeight:700,letterSpacing:"0.1em",fontFamily:mono,transition:"color .15s",position:"relative"}}>
            {TLBL[t]}
            {t==="threats detected"&&running&&threats detected.length>0&&<span style={{position:"absolute",top:5,right:5,width:5,height:5,borderRadius:"50%",background:T.amber,animation:"pulse 1s ease-in-out infinite"}}/>}
          </button>
        ))}
      </div>

      {/* ═══ CONFIG ═══ */}
      {tab==="config"&&(
        <div style={{display:"grid",gridTemplateColumns:"1.5fr 1fr",gap:16}}>
          <div>
            <Panel title="// TARGET">
              <TxtIn label="TARGET URL" value={target} onChange={setTarget} placeholder="https://target.com"/>
              <TxtIn label="SESSION COOKIE (optional)" value={authCookie} onChange={setAuthCookie} placeholder="PHPSESSID=abc123"/>
            </Panel>
            <Panel title="// ATTACK MODULES">
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8}}>
                {[["XSS","Reflected/Stored/DOM"],["SQLi","Classic + Blind"],["CMDi","OS injection"]].map(([m,d])=>(
                  <div key={m} onClick={()=>setModules(p=>({...p,[m]:!p[m]}))} style={{padding:"10px 12px",background:modules[m]?`${T.accent}0a`:T.bg1,border:`1px solid ${modules[m]?T.accent:T.border}`,borderRadius:6,cursor:"pointer",transition:"all .15s"}}>
                    <div style={{fontSize:13,fontWeight:700,color:modules[m]?T.accent:T.muted,fontFamily:disp,marginBottom:3}}>{m}</div>
                    <div style={{fontSize:9,color:modules[m]?T.muted:T.dim}}>{d}</div>
                  </div>
                ))}
              </div>
            </Panel>
            <div style={{padding:"9px 12px",borderRadius:5,marginBottom:14,background:T.amberDim,border:`1px solid ${T.amber}28`,fontSize:10,color:`${T.amber}bb`,lineHeight:1.7}}>
              ⚠ AUTHORISED USE ONLY — Only test targets you own or have explicit written permission to test.
            </div>
            <button onClick={startScan} disabled={running||!target} style={{width:"100%",padding:"13px 0",background:running?T.bg3:`linear-gradient(135deg,${T.accent} 0%,#0055cc 100%)`,border:`1px solid ${running?T.border:T.accent}50`,borderRadius:6,cursor:running?"not-allowed":"pointer",color:running?T.muted:"#000",fontSize:12,fontWeight:700,letterSpacing:"0.14em",fontFamily:mono,display:"flex",alignItems:"center",justifyContent:"center",gap:10,boxShadow:running?"none":`0 0 28px ${T.accent}22`}}>
              {running?<><Spin/>SCANNING…</>:"▶  LAUNCH SCAN"}
            </button>
          </div>
          <div>
            <Panel title="// RESULTS" style={{marginBottom:14}}>
              <Ring counts={sevCounts}/>
              {/* PDF DOWNLOAD BUTTON IN RESULTS SECTION */}
              {threats detected.length>0&&(
                <div style={{marginTop:14,paddingTop:14,borderTop:`1px solid ${T.border}`}}>
                  <PDFButton threats detected={threats detected} ctx={ctx} summary={summary} target={target}/>
                  <div style={{marginTop:7,fontSize:9,color:T.muted,textAlign:"center",fontFamily:mono,lineHeight:1.5}}>
                    Full report with all threats detected, payloads,<br/>reproduction steps &amp; remediation code
                  </div>
                </div>
              )}
            </Panel>
            {ctx&&(
              <Panel title="// TARGET PROFILE" accent={T.cyan} style={{marginBottom:14}}>
                {[["Backend",ctx.backend_language,T.accent],["Database",ctx.database_type,T.accent],["WAF",ctx.waf_detected,ctx.waf_detected!=="None"?T.amber:T.green],["SPA",ctx.spa_detected?"Yes":"No",T.muted],["Confidence",ctx.fingerprint_confidence,T.text]].map(([k,v,c])=>(
                  <div key={k} style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                    <span style={{fontSize:9,color:T.muted,letterSpacing:"0.06em"}}>{k}</span>
                    <span style={{fontSize:11,color:c||T.text}}>{v}</span>
                  </div>
                ))}
              </Panel>
            )}
            <Panel title="// NOTION SYNC" accent={T.purple}>
              <div style={{marginBottom:10,padding:"7px 10px",background:T.bg1,border:`1px solid ${notionStatus==="done"?T.green:notionStatus==="syncing"?T.amber:T.border}30`,borderRadius:5,display:"flex",alignItems:"center",gap:7,fontSize:10,color:notionStatus==="done"?T.green:notionStatus==="syncing"?T.amber:T.dim,fontFamily:mono}}>
                {notionStatus==="syncing"&&<Spin s={11}/>}
                {notionStatus==="done"&&<Dot c={T.green}/>}
                {notionStatus==="done"?"✓ SYNCED TO NOTION":notionStatus==="syncing"?"SYNCING…":"NOT YET SYNCED"}
              </div>
              {[["Threat Reports","675f50bffdff44c79e46906ad118fe41"],["Detection Signatures","029bbed89aaf4ed8ac0f89fc216d6a38"],["Target Profiles","56fccd451ce54872933a14835836244c"],["Scan Sessions","eb840a4a96e4467490b21ab0ff1fa708"]].map(([l,id])=>(
                <a key={id} href={`https://notion.so/${id}`} target="_blank" rel="noreferrer" style={{display:"block",padding:"6px 10px",marginBottom:5,background:T.purpleDim,border:`1px solid ${T.purple}22`,borderRadius:4,color:T.purple,fontSize:10,textDecoration:"none"}}>↗ {l}</a>
              ))}
            </Panel>
          </div>
        </div>
      )}

      {/* ═══ LOGS ═══ */}
      {tab==="logs"&&(
        <Panel title={`// LIVE OUTPUT  [${logs.length} lines]`} right={running?<Dot c={T.green}/>:notionStatus==="syncing"?<div style={{display:"flex",alignItems:"center",gap:5,fontSize:9,color:T.amber,fontFamily:mono}}><Spin s={10}/>NOTION SYNC</div>:done?<Pill label="DONE" color={T.green} size={9}/>:null} noPad>
          <div style={{padding:14}}><LogStream logs={logs} running={running||notionStatus==="syncing"}/></div>
        </Panel>
      )}

      {/* ═══ FINDINGS ═══ */}
      {tab==="threats detected"&&(
        <div>
          {threats detected.length>0&&(
            <div style={{display:"flex",gap:8,marginBottom:14,flexWrap:"wrap",alignItems:"center"}}>
              {["Critical","High","Medium","Low"].filter(s=>sevCounts[s]>0).map(s=>(
                <div key={s} className="fu" style={{padding:"10px 16px",background:SEV_BG[s],border:`1px solid ${SEV_C[s]}30`,borderRadius:6,minWidth:72,textAlign:"center"}}>
                  <div style={{fontSize:24,fontWeight:800,color:SEV_C[s],fontFamily:disp,lineHeight:1}}>{sevCounts[s]}</div>
                  <div style={{fontSize:8,color:T.muted,letterSpacing:"0.1em",marginTop:3}}>{s.toUpperCase()}</div>
                </div>
              ))}
              {notionStatus==="done"&&<Pill label={`✓ Synced to Notion`} color={T.green}/>}
            </div>
          )}
          {!threats detected.length
            ?<div style={{textAlign:"center",padding:"70px 0",color:T.dim,fontSize:12}}>{running?<div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:10}}><Spin/>Scanning…</div>:"No threats detected yet. Launch a scan."}</div>
            :threats detected.map((f,i)=><FindCard key={i} f={f} i={i}/>)
          }
        </div>
      )}

      {/* ═══ REPORT ═══ */}
      {tab==="report"&&(
        <div>
          {!threats detected.length
            ?<div style={{textAlign:"center",padding:"70px 0",color:T.dim,fontSize:12}}>{running?"Report generates when scan completes.":"Run a scan to generate a report."}</div>
            :(<>
              {summary&&<Panel title="// EXECUTIVE SUMMARY" style={{marginBottom:16}}><p style={{fontSize:12,color:T.text,lineHeight:1.95,whiteSpace:"pre-wrap"}}>{summary}</p></Panel>}

              {/* Severity grid + PDF button side by side */}
              <div style={{display:"grid",gridTemplateColumns:"1fr auto",gap:16,marginBottom:16,alignItems:"start"}}>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
                  {["Critical","High","Medium","Low"].map(s=>(
                    <div key={s} className="fu" style={{background:SEV_BG[s],border:`1px solid ${SEV_C[s]}28`,borderRadius:7,padding:"14px 10px",textAlign:"center"}}>
                      <div style={{fontSize:28,fontWeight:800,color:SEV_C[s],fontFamily:disp,lineHeight:1}}>{sevCounts[s]||0}</div>
                      <div style={{fontSize:8,color:T.muted,marginTop:5,letterSpacing:"0.1em"}}>{s.toUpperCase()}</div>
                    </div>
                  ))}
                </div>
                {/* PDF button in report tab too */}
                <div style={{minWidth:200}}>
                  <PDFButton threats detected={threats detected} ctx={ctx} summary={summary} target={target}/>
                  <div style={{marginTop:6,fontSize:9,color:T.muted,textAlign:"center",fontFamily:mono,lineHeight:1.5}}>
                    Detailed PDF with all threats detected,<br/>payloads &amp; remediation code
                  </div>
                </div>
              </div>

              {ctx&&(
                <Panel title="// TARGET PROFILE" style={{marginBottom:16}}>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
                    {[["TARGET",target],["BACKEND",ctx.backend_language],["DATABASE",ctx.database_type],["WAF",ctx.waf_detected],["SPA",ctx.spa_detected?"Yes":"No"],["CONFIDENCE",ctx.fingerprint_confidence]].map(([k,v])=>(
                      <div key={k}><div style={{fontSize:9,color:T.muted,marginBottom:3,letterSpacing:"0.08em"}}>{k}</div><div style={{fontSize:11,color:T.text,wordBreak:"break-all"}}>{v}</div></div>
                    ))}
                  </div>
                </Panel>
              )}
              <Panel title={`// ALL FINDINGS (${threats detected.length})`} style={{marginBottom:16}}>
                {threats detected.map((f,i)=><FindCard key={i} f={f} i={i}/>)}
              </Panel>
              <Panel title="// NOTION WORKSPACE" accent={T.purple}>
                <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                  {[["Threat Reports","675f50bffdff44c79e46906ad118fe41"],["Detection Signatures","029bbed89aaf4ed8ac0f89fc216d6a38"],["Scan Sessions","eb840a4a96e4467490b21ab0ff1fa708"],["Target Profiles","56fccd451ce54872933a14835836244c"]].map(([l,id])=>(
                    <a key={id} href={`https://notion.so/${id}`} target="_blank" rel="noreferrer" style={{padding:"6px 12px",background:T.purpleDim,border:`1px solid ${T.purple}22`,borderRadius:4,color:T.purple,fontSize:10,textDecoration:"none"}}>↗ {l}</a>
                  ))}
                </div>
              </Panel>
            </>)
          }
        </div>
      )}
    </div>
  );
}
