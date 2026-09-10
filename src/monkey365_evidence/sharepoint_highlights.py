"""Screenshot-only annotations, outside SharePoint's clipping containers."""

from __future__ import annotations

import base64
import math
from pathlib import Path

from playwright.sync_api import Locator, Page

from .models import Control

# Measure painted text and form controls, not their full-width layout wrappers.
# Native Fluent choice inputs are transparent; their labels paint the control.
CONTENT_BOUNDS = r"""root => {
    const rects = [];
    const visible = el => {
        if (getComputedStyle(el).visibility !== 'visible') return false;
        for (let n = el; n; n = n.parentElement) {
            const s = getComputedStyle(n);
            if (s.display === 'none' ||
                n.getAttribute('aria-hidden') === 'true' || n.hidden) return false;
        }
        return true;
    };
    const add = r => { if (r.width > 0 && r.height > 0) rects.push(r); };
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        if (!node.textContent.trim() || !visible(node.parentElement)) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        for (const r of range.getClientRects()) add(r);
    }
    const selector = 'input, select, textarea, [role="slider"], .ms-Checkbox-checkbox';
    const controls = [...root.querySelectorAll(selector)];
    if (root.matches(selector)) controls.push(root);
    for (const el of controls) {
        if (!visible(el)) continue;
        // Fluent radio inputs are invisible, full-row hit targets. Measuring
        // those recreates the oversized box even though the text is fitted.
        if (el.matches('input[type=radio], input[type=checkbox]') &&
            Number(getComputedStyle(el).opacity) === 0) continue;
        add(el.getBoundingClientRect());
    }
    for (const label of root.querySelectorAll('.ms-ChoiceField-field')) {
        if (!visible(label)) continue;
        const r = label.getBoundingClientRect();
        const pseudo = getComputedStyle(label, '::before');
        const size = parseFloat(pseudo.width) || 20;
        // The visible radio is painted by the label's pseudo-element.
        add({left:r.left, top:r.top, right:r.left+size, bottom:r.top+size,
             width:size, height:size});
    }
    if (!rects.length) throw new Error('No visible setting content to highlight');
    return {
        x: Math.min(...rects.map(r => r.left)), y: Math.min(...rects.map(r => r.top)),
        right: Math.max(...rects.map(r => r.right)),
        bottom: Math.max(...rects.map(r => r.bottom))
    };
}"""


def _bounds(locator: Locator) -> dict:
    return locator.evaluate(CONTENT_BOUNDS)


def capture_highlights(page: Page, control: Control, destination: Path) -> bool:
    """Draw complete, content-sized boxes and refuse off-screen evidence.

    Use a viewport screenshot with an explicit clip: Locator.screenshot can
    scroll nested containers *after* measuring annotations. Fixed overlays on
    the document root avoid the admin center's overflow clipping entirely.
    """
    if control.frame_selector:
        raise RuntimeError("SharePoint overlay capture does not support framed routes")
    target = page.locator(control.screenshot_selector) if control.screenshot_selector else None
    settings = [page.locator(s) for s in dict.fromkeys(control.highlight_selectors)]
    for setting in settings:
        if setting.count() != 1:
            raise RuntimeError("highlight must identify exactly one setting")
        setting.wait_for(state="visible")
    original_viewport = page.viewport_size
    overlay = None
    try:
        # Resolve every target first, then scroll before measuring any boxes.
        # Larger temporary viewports accommodate compound checks without
        # silently leaving their first target above a nested scroll viewport.
        for attempt in range(3):
            for setting in settings:
                setting.scroll_into_view_if_needed()
            page.mouse.move(0, 0)  # Keep hover tooltips out of the evidence.
            page.wait_for_timeout(100)
            viewport = page.evaluate("() => ({width: innerWidth, height: innerHeight})")
            area = target.bounding_box() if target else {
                "x": 0, "y": 0, **viewport,
            }
            if not area:
                raise RuntimeError("screenshot region has no visible bounds")
            left, top = max(0, math.ceil(area["x"])), max(0, math.ceil(area["y"]))
            right = min(viewport["width"], math.floor(area["x"] + area["width"]))
            bottom = min(viewport["height"], math.floor(area["y"] + area["height"]))
            boxes = []
            for setting in settings:
                box = _bounds(setting)
                # Slider headings are outside the slider's layout wrapper.
                label = setting.get_attribute("aria-label") or ""
                if setting.locator('[role="slider"]').count():
                    name = "OneDrive" if label == "OneDrive" else "SharePoint"
                    heading = page.locator(control.screenshot_selector).get_by_text(name, exact=True)
                    if heading.count() != 1:
                        raise RuntimeError(f"cannot uniquely locate {name} slider heading")
                    title = _bounds(heading)
                    box = {"x": min(box["x"], title["x"]),
                           "y": min(box["y"], title["y"]),
                           "right": max(box["right"], title["right"]),
                           "bottom": max(box["bottom"], title["bottom"])}
                    # SharePoint's permissiveness legend shares its column.
                    # Enclose it rather than running a border through its text.
                    if name == "SharePoint":
                        for text in ("Most permissive", "Least permissive"):
                            legend = page.locator(control.screenshot_selector).get_by_text(
                                text, exact=True)
                            if legend.count() == 1:
                                r = _bounds(legend)
                                box = {"x": min(box["x"], r["x"]),
                                       "y": min(box["y"], r["y"]),
                                       "right": max(box["right"], r["right"]),
                                       "bottom": max(box["bottom"], r["bottom"])}
                boxes.append(box)
            if all(left + 2 <= b["x"] and top + 2 <= b["y"]
                   and b["right"] <= right - 2 and b["bottom"] <= bottom - 2
                   for b in boxes):
                break
            if attempt == 2 or not original_viewport:
                raise RuntimeError("highlight content does not fit inside the screenshot")
            page.set_viewport_size({"width": viewport["width"],
                                    "height": viewport["height"] + 600})

        clip = {"x": left, "y": top, "width": right - left, "height": bottom - top}
        rectangles = [{"x": max(left + 1, math.floor(b["x"]) - 5),
                       "y": max(top + 1, math.floor(b["y"]) - 5),
                       "right": min(right - 1, math.ceil(b["right"]) + 5),
                       "bottom": min(bottom - 1, math.ceil(b["bottom"]) + 5)} for b in boxes]
        overlay = page.evaluate_handle("""rectangles => {
            const layer = document.createElement('div');
            layer.setAttribute('data-evidence-highlights', '');
            layer.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:2147483647';
            for (const r of rectangles) {
                const box = document.createElement('div');
                box.style.cssText = `position:absolute;box-sizing:border-box;border:3px solid #e00000;
                    left:${r.x}px;top:${r.y}px;width:${r.right-r.x}px;height:${r.bottom-r.y}px;`;
                layer.appendChild(box);
            }
            document.documentElement.appendChild(layer);
            return layer;
        }""", rectangles)
        # Confirm every border's actual geometry lies wholly inside the crop.
        actual = overlay.evaluate("el => [...el.children].map(n => n.getBoundingClientRect().toJSON())")
        if len(actual) != len(settings) or any(
            r["left"] < left or r["top"] < top or r["right"] > right or r["bottom"] > bottom
            for r in actual
        ):
            raise RuntimeError("annotation border would be clipped by the screenshot")
        png = page.screenshot(clip=clip, full_page=False)
        verified = page.evaluate("""async ({data, clip, rectangles}) => {
            const image = new Image(); image.src = 'data:image/png;base64,' + data;
            await image.decode();
            const canvas = document.createElement('canvas');
            canvas.width = image.width; canvas.height = image.height;
            const ctx = canvas.getContext('2d'); ctx.drawImage(image, 0, 0);
            const pixels = ctx.getImageData(0,0,canvas.width,canvas.height).data;
            const sx = canvas.width/clip.width, sy = canvas.height/clip.height;
            const red = (x,y) => {
                const i = (y*canvas.width+x)*4;
                return pixels[i] === 224 && pixels[i+1] === 0 && pixels[i+2] === 0;
            };
            return rectangles.every(r => {
                // Sample inside the 3px stroke to avoid fractional-DPI edge antialiasing.
                const x = Math.ceil((r.left-clip.x+1)*sx);
                const y = Math.ceil((r.top-clip.y+1)*sy);
                const right = Math.floor((r.right-clip.x-1)*sx)-1;
                const bottom = Math.floor((r.bottom-clip.y-1)*sy)-1;
                if(x<0 || y<0 || right>=canvas.width || bottom>=canvas.height) return false;
                for(let i=x;i<=right;i++) if(!red(i,y) || !red(i,bottom)) return false;
                for(let i=y;i<=bottom;i++) if(!red(x,i) || !red(right,i)) return false;
                return true;
            });
        }""", {"data": base64.b64encode(png).decode(), "clip": clip, "rectangles": actual})
        if not verified:
            raise RuntimeError("PNG does not contain all four complete highlight borders")
        destination.write_bytes(png)
        return True
    finally:
        if overlay:
            overlay.evaluate("el => el.remove()")
            overlay.dispose()
        if original_viewport and page.viewport_size != original_viewport:
            page.set_viewport_size(original_viewport)
