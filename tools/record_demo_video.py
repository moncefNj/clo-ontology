#!/usr/bin/env python3
"""
record_demo_video.py -- record the CLO Studio walkthrough video (silent, captioned).

Drives examples/demo/clo_studio.html with Playwright (headless Chromium), overlays captions
and a pointer, records the session and converts it to MP4 with ffmpeg.

  pip install playwright && playwright install chromium     # once
  python3 tools/record_demo_video.py --out demo/clo_studio_demo.mp4
"""
import argparse
import os
import shutil
import subprocess
import tempfile

from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "examples", "demo", "clo_studio.html")
W, H = 1366, 820

OVERLAY = r"""
(() => {
  const s = document.createElement('style');
  s.textContent = `
  #vcap{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);max-width:1050px;z-index:99999;
        background:rgba(12,20,24,.92);color:#fff;font:500 19px/1.45 system-ui,sans-serif;padding:12px 20px;
        border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,.25);transition:opacity .25s}
  #vcap b{color:#7fe0d6}
  #vptr{position:fixed;left:0;top:0;width:22px;height:22px;border-radius:50%;z-index:99998;pointer-events:none;
        background:rgba(194,65,12,.85);border:2px solid #fff;box-shadow:0 0 0 3px rgba(194,65,12,.35);
        transition:transform .7s cubic-bezier(.3,.7,.3,1)}
  .vhl{outline:3px solid #C2410C !important;outline-offset:3px;border-radius:6px}
  #vcard{position:fixed;inset:0;z-index:100000;background:#0E1417;color:#E4ECE9;display:flex;flex-direction:column;
         align-items:center;justify-content:center;gap:14px;font:500 22px/1.5 system-ui,sans-serif;text-align:center;padding:40px}
  #vcard h1{font:600 46px/1.15 system-ui,sans-serif;margin:0;color:#fff}
  #vcard .m{color:#4CC0B5;font:500 18px ui-monospace,monospace}`;
  document.head.appendChild(s);
  const c = document.createElement('div'); c.id='vcap'; c.style.opacity=0; document.body.appendChild(c);
  const p = document.createElement('div'); p.id='vptr'; p.style.transform='translate(680px,420px)'; document.body.appendChild(p);
})();
"""


def run(out):
    tmp = tempfile.mkdtemp()
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        ctx = b.new_context(viewport={"width": W, "height": H}, record_video_dir=tmp,
                            record_video_size={"width": W, "height": H})
        pg = ctx.new_page()
        pg.goto("file://" + PAGE)
        pg.wait_for_timeout(400)
        pg.evaluate(OVERLAY)

        def card(title, lines, ms):
            pg.evaluate("""([t,l])=>{let c=document.getElementById('vcard'); if(!c){c=document.createElement('div');c.id='vcard';document.body.appendChild(c);}
                c.innerHTML='<h1>'+t+'</h1>'+l.map(x=>'<div>'+x+'</div>').join(''); c.style.display='flex';}""", [title, lines])
            pg.wait_for_timeout(ms)
            pg.evaluate("()=>{const c=document.getElementById('vcard'); if(c) c.style.display='none';}")

        def cap(text, ms=0):
            pg.evaluate("t=>{const c=document.getElementById('vcap'); c.innerHTML=t; c.style.opacity=t?1:0;}", text)
            if ms:
                pg.wait_for_timeout(ms)

        def point(sel, click=True, hl=True, ms=900):
            el = pg.locator(sel).first
            el.scroll_into_view_if_needed()
            bb = el.bounding_box()
            if bb:
                pg.evaluate("([x,y])=>{document.getElementById('vptr').style.transform=`translate(${x}px,${y}px)`}",
                            [bb["x"] + min(bb["width"] / 2, 60) - 11, bb["y"] + bb["height"] / 2 - 11])
            pg.wait_for_timeout(ms)
            if hl:
                pg.evaluate("()=>document.querySelectorAll('.vhl').forEach(e=>e.classList.remove('vhl'))")
                el.evaluate("e=>e.classList.add('vhl')")
            if click:
                el.click()
                pg.wait_for_timeout(350)
                pg.evaluate("()=>{const p=document.getElementById('vptr');p.style.boxShadow='0 0 0 12px rgba(194,65,12,.15)';"
                            "setTimeout(()=>p.style.boxShadow='0 0 0 3px rgba(194,65,12,.35)',300)}")

        def unhl():
            pg.evaluate("()=>document.querySelectorAll('.vhl').forEach(e=>e.classList.remove('vhl'))")

        def scroll_to(sel, block="start"):
            pg.locator(sel).first.evaluate("(e,b)=>e.scrollIntoView({behavior:'smooth',block:b})", block)
            pg.wait_for_timeout(900)

        card("CLO Studio", ["Explaining and repairing multi-cloud tag governance findings",
                            "<span class='m'>ICSOC 2026 · Demonstrations (anonymous submission)</span>"], 5000)
        cap("Cloud tags are written by one team and read by others: FinOps needs a <b>cost-center</b>, Security a "
            "<b>data-classification</b>, Operations an <b>owner</b> and an <b>environment</b>.", 6500)
        cap("CLO Studio is one HTML page generated from real CLO runs on a company example: "
            "<b>10 resources</b> on AWS, Azure and GCP, <b>4 teams</b>, <b>5 governance roles</b>.", 6500)
        point(".tally", click=False)
        cap("Every number is the output of the pipeline: findings grouped by root cause, proposed values, and records "
            "on which no absence may be concluded.", 6000)
        unhl()
        # 1. explain a finding
        point("#res-pay-receipts")
        cap("Select a resource. <b>pay-receipts</b> is a GCP bucket owned by the Payments team.", 4500)
        scroll_to("#detail")
        cap("<b>What the standard requires here</b>: each key, whether it is present, the role that needs it, and "
            "the policy and property chain that reach this resource.", 7500)
        point("#detail .finding:has-text('cost-center')", click=False)
        scroll_to("#detail .finding:has-text('cost-center')", "center")
        cap("Why is <b>cost-center</b> missing? The shared standard reaches the bucket through its account and the "
            "organisation (chain <b>C-4</b>); FinOps needs the key (chain <b>C-9</b>).", 8000)
        cap("The record is <b>complete</b>, so the closed world may conclude the key is absent. The repair proposes "
            "the team's value only because the key's <b>value sources</b> allow it, with a dry-run command.", 8500)
        unhl()
        pg.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); pg.wait_for_timeout(700)
        # 2. role lens
        point("#lens .chip[data-r='FinOps']")
        cap("<b>View as FinOps</b>: resources without a FinOps finding fade out. Each role sees its own backlog.", 6000)
        point("#lens .chip[data-r='All']", hl=False)
        unhl()
        # 3. what-if: new role
        point("#sw-role", ms=600)
        cap("What if a <b>Sustainability</b> role joins the shared standard? Error findings go from 17 to 23 and "
            "<b>carbon-scope</b> appears in the derived standard.", 7000)
        scroll_to("#std")
        cap("The standard is <b>derived</b> from role needs: the change is one line of data, and no rule is edited.", 6000)
        pg.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); pg.wait_for_timeout(700)
        point("#sw-role", hl=False)
        unhl()
        # 4. closing the world
        point("#res-vol-scratch")
        cap("<b>vol-scratch</b> came from a listing that never returns tags: CLO draws <b>no closed-world verdict</b> "
            "and re-reads it.", 6500)
        point("#sw-closure")
        cap("Close the world everywhere, as an export-based check does: the volume becomes 'unlabelled', a finding "
            "the response gives <b>no evidence</b> for.")
        point("#res-vol-scratch", hl=False)
        scroll_to("#detail")
        pg.wait_for_timeout(6500)
        pg.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); pg.wait_for_timeout(700)
        point("#sw-closure", hl=False)
        unhl()
        # 5. repairs
        point("#sw-naive")
        cap("Team-majority repairs fill <b>11</b> values instead of 1, including a <b>data-classification</b> guessed "
            "from the team's habit. CLO never guesses a key without a value source.", 7500)
        point("#res-vm-build", hl=False)
        scroll_to("#detail")
        pg.wait_for_timeout(2500)
        pg.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); pg.wait_for_timeout(700)
        point("#sw-naive", hl=False)
        unhl()
        # 6. loop
        point("#t-loop")
        cap("<b>Closed loop</b> over 8 cycles with simulated owners: the team-majority policy closes more findings, "
            "but writes <b>778</b> silently wrong values, against <b>16</b>.", 8000)
        scroll_to("#p-loop .panel:has-text('generator')")
        cap("And the honest limit: when the estate is irregular, CLO's repair accuracy falls; what its value sources "
            "buy is <b>abstention</b>.", 7000)
        pg.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); pg.wait_for_timeout(700)
        # 7. corpus
        point("#t-corpus")
        cap("<b>Open corpus</b>: 1,686 resources recorded by Cloud Custodian's tests. Completeness is derived from the "
            "<b>shape of the response</b>, and checked against other observations.", 7500)
        scroll_to("#p-corpus .grid2")
        cap("One key, many spellings (Environment, Env, env, Stage), and 1,655 missing-key reports an export check "
            "would make <b>without evidence</b>.", 7000)
        pg.evaluate("window.scrollTo({top:0,behavior:'smooth'})"); pg.wait_for_timeout(700)
        # 8. enforce
        point("#t-enforce")
        cap("<b>Execute</b>: the derived standard compiled into AWS Config, Azure Policy and Cloud Custodian; team "
            "policies and composition stay in CLO's audit.", 6500)
        point("#p-enforce .chip[data-f='custodian.yml']")
        pg.wait_for_timeout(3500)
        cap("", 0)
        unhl()
        card("Try it", ["One self-contained HTML file: no server, no cloud credentials.",
                        "<span class='m'>make demo</span> regenerates it from the pipeline in about a minute.",
                        "<span class='m'>Repository and paper: see the submission</span>"], 6000)
        pg.close()
        ctx.close()
        b.close()
    webm = next(os.path.join(tmp, f) for f in os.listdir(tmp) if f.endswith(".webm"))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    if out.endswith(".webm"):
        shutil.copy(webm, out)
    else:
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", webm, "-c:v", "libx264", "-pix_fmt", "yuv420p",
                        "-preset", "slow", "-crf", "22", "-movflags", "+faststart", out], check=True)
    print("wrote", out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "demo", "clo_studio_demo.mp4"))
    run(ap.parse_args().out)
