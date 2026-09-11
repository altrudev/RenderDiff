"""Playwright worker. Must only be invoked inside the networkless OS sandbox."""
from __future__ import annotations
import json, os
from pathlib import Path
from playwright.sync_api import sync_playwright

MAX_TEXT=1_000_000
SCRIPT=r'''() => {
 const limit=2000, nodes=[]; let truncated=false, shadowRootCount=0;
 function walk(root){for(const el of root.querySelectorAll('*')){if(nodes.length>=limit){truncated=true;return}const style=getComputedStyle(el);const visible=!!el.getClientRects().length && style.visibility!=='hidden' && style.visibility!=='collapse' && style.display!=='none' && Number(style.opacity)!==0;const own=[...el.childNodes].filter(n=>n.nodeType===3).map(n=>n.textContent).join('');if(own.trim() || el.hasAttribute('aria-label') || el.hasAttribute('hidden'))nodes.push({tag:el.tagName.toLowerCase(),text:own.slice(0,4096),visible,display:style.display,visibility:style.visibility,opacity:style.opacity,ariaHidden:el.getAttribute('aria-hidden'),ariaLabel:el.getAttribute('aria-label')});if(el.shadowRoot){shadowRootCount++;walk(el.shadowRoot);}}}
 walk(document);return {text:document.body?.innerText||'',dom:document.documentElement.outerHTML.slice(0,MAX_TEXT),nodes,truncated,canvases:[...document.querySelectorAll('canvas')].map(c=>({width:c.width,height:c.height})),shadowRootCount};
}'''.replace('MAX_TEXT','1000000')

def main():
    source=Path('/work/evidence.html').read_text(encoding='utf-8')
    exe=Path('/work/browser-path').read_text().strip()
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=exe,headless=True,chromium_sandbox=False,args=['--no-sandbox','--disable-gpu','--disable-background-networking','--disable-extensions','--disable-dev-shm-usage'])
        context=browser.new_context(service_workers='block',accept_downloads=False,java_script_enabled=True)
        page=context.new_page();page.set_default_timeout(5000)
        page.route('**/*',lambda route:route.abort())
        page.set_content(source,wait_until='domcontentloaded',timeout=5000)
        page.wait_for_timeout(300)
        snapshot=page.evaluate(SCRIPT)
        try:
            cdp=context.new_cdp_session(page)
            ax=cdp.send('Accessibility.getFullAXTree')
            nodes=ax.get('nodes',[])
            snapshot['accessibility']={'available':True,'node_count':len(nodes),'nodes':nodes[:2000],'truncated':len(nodes)>2000}
        except Exception as exc:
            snapshot['accessibility']={'available':False,'reason':type(exc).__name__}
        browser.close()
    snapshot['dom']=snapshot['dom'][:MAX_TEXT]
    snapshot['available']=True;snapshot['observer']='playwright-isolated-chromium';snapshot['network']='disabled';snapshot['coverage']='DOM, computed styles, open shadow roots, accessibility tree, canvas metadata; no OCR or visual perception guarantee'
    Path('/work/report.json').write_text(json.dumps(snapshot,ensure_ascii=False,default=str),encoding='utf-8')
if __name__=='__main__':main()
