import base64

import pytest
from playwright.sync_api import Error, sync_playwright

from monkey365_evidence.models import Control
from monkey365_evidence.sharepoint_highlights import capture_highlights


@pytest.fixture
def browser():
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=True)
        except Error as error:
            if "Executable doesn't exist" not in str(error):
                raise
            pytest.skip("Install Chromium with: python -m playwright install chromium")
        yield browser
        browser.close()


@pytest.mark.parametrize("scale", [1, 2])
def test_complete_fitted_borders_in_overflow_container(browser, tmp_path, monkeypatch, scale):
    page = browser.new_page(viewport={"width": 900, "height": 600}, device_scale_factor=scale)
    page.set_content("""
        <style>
        body { margin:0; font:14px Arial; }
        #capture { margin:20px; padding:20px; height:350px; overflow:hidden; }
        #scroller { height:200px; overflow:hidden; }
        #row { display:flex; align-items:center; width:1600px; height:40px; }
        input[type=text] { width:45px; margin-left:8px; }
        </style>
        <div id="capture"><h1>Sharing</h1><div id="scroller">
        <div id="row"><input id="check" type="checkbox">
        <label for="check">Guest access expires after this many days</label>
        <input type="text" value="60" disabled></div></div></div>
    """)
    control = Control("7.2.9", "Guest expiration", "https://example.com", (),
                      screenshot_selector="#capture", highlight_selectors=("#row",))
    original = page.screenshot
    observed = {}

    def screenshot(**kwargs):
        observed["rects"] = page.locator('[data-evidence-highlights] > div').evaluate_all(
            "els => els.map(el => el.getBoundingClientRect().toJSON())")
        observed["clip"] = kwargs["clip"]
        return original(**kwargs)

    monkeypatch.setattr(page, "screenshot", screenshot)
    destination = tmp_path / "fitted.png"
    assert capture_highlights(page, control, destination)
    assert len(observed["rects"]) == 1
    assert observed["rects"][0]["width"] < 500  # Not the 1600px layout wrapper.
    # Inspect the actual PNG, not just the CSS or the highlighted flag.
    result = page.evaluate("""async ({data, rects, clip, scale}) => {
        const image = new Image(); image.src = 'data:image/png;base64,' + data;
        await image.decode();
        const canvas = document.createElement('canvas');
        canvas.width = image.width; canvas.height = image.height;
        const ctx = canvas.getContext('2d'); ctx.drawImage(image, 0, 0);
        const pixels = ctx.getImageData(0,0,canvas.width,canvas.height).data;
        const red = (x,y) => {
            const i = (y*canvas.width+x)*4;
            return pixels[i] === 224 && pixels[i+1] === 0 && pixels[i+2] === 0;
        };
        return rects.every(r => {
            const x = Math.round((r.left-clip.x)*scale);
            const y = Math.round((r.top-clip.y)*scale);
            const right = Math.round((r.right-clip.x)*scale)-1;
            const bottom = Math.round((r.bottom-clip.y)*scale)-1;
            if (x<1 || y<1 || right>=canvas.width-1 || bottom>=canvas.height-1) return false;
            for(let i=x; i<=right; i++) if(!red(i,y) || !red(i,bottom)) return false;
            for(let i=y; i<=bottom; i++) if(!red(x,i) || !red(right,i)) return false;
            return true;
        });
    }""", {**observed, "scale": scale,
            "data": base64.b64encode(destination.read_bytes()).decode()})
    assert result, "PNG must contain all four complete red edges"
    assert page.locator('[data-evidence-highlights]').count() == 0
    assert not page.locator("#check").is_checked()
    assert page.locator('input[type=text]').input_value() == "60"
    assert page.locator("#row").get_attribute("style") is None
    page.close()


def test_out_of_crop_content_fails_without_screenshot(browser, tmp_path):
    page = browser.new_page(viewport={"width": 600, "height": 400})
    page.set_content('<div id="capture" style="padding:20px;width:100px;overflow:hidden">'
                     '<div id="row"><input style="width:900px" value="60"></div></div>')
    control = Control("7.2.9", "Guest expiration", "https://example.com", (),
                      screenshot_selector="#capture", highlight_selectors=("#row",))
    destination = tmp_path / "must-not-exist.png"
    with pytest.raises(RuntimeError, match="does not fit"):
        capture_highlights(page, control, destination)
    assert not destination.exists()
    assert page.viewport_size == {"width": 600, "height": 400}
    assert page.locator('[data-evidence-highlights]').count() == 0
    page.close()


def test_overlay_removed_after_screenshot_error(browser, tmp_path, monkeypatch):
    page = browser.new_page()
    page.set_content('<div id="capture" style="padding:30px">'
                     '<div id="row"><label>Expiration</label><input value="60"></div></div>')
    control = Control("7.2.9", "Guest expiration", "https://example.com", (),
                      screenshot_selector="#capture", highlight_selectors=("#row",))

    def fail(**kwargs):
        raise OSError("simulated disk error")

    monkeypatch.setattr(page, "screenshot", fail)
    with pytest.raises(OSError, match="simulated disk error"):
        capture_highlights(page, control, tmp_path / "error.png")
    assert page.locator('[data-evidence-highlights]').count() == 0
    page.close()


def test_invisible_full_width_radio_hit_target_is_not_boxed(browser, tmp_path, monkeypatch):
    page = browser.new_page()
    page.set_content('''<style>
        #capture { padding:30px; }
        #row { position:relative; width:800px; }
        input { opacity:0; position:absolute; width:800px; height:20px; }
        .ms-ChoiceField-field { position:relative; display:block; padding-left:26px; }
        .ms-ChoiceField-field::before { content:''; position:absolute; left:0; top:0;
            width:20px; height:20px; border:1px solid black; border-radius:50%; }
        </style><div id="capture"><div id="row">
        <input type="radio" id="edit" checked>
        <label class="ms-ChoiceField-field" for="edit"><span>Edit</span></label>
        </div></div>''')
    control = Control("7.2.11", "Permission", "https://example.com", (),
                      screenshot_selector="#capture", highlight_selectors=("#row",))
    original = page.screenshot
    widths = []

    def screenshot(**kwargs):
        widths.append(page.locator('[data-evidence-highlights] > div').bounding_box()["width"])
        return original(**kwargs)

    monkeypatch.setattr(page, "screenshot", screenshot)
    assert capture_highlights(page, control, tmp_path / "radio.png")
    assert 40 < widths[0] < 100
    assert page.locator("#edit").is_checked()
    page.close()


def test_missing_border_pixels_are_rejected_before_writing(browser, tmp_path, monkeypatch):
    page = browser.new_page()
    page.set_content('<div id="capture" style="padding:30px">'
                     '<div id="row"><label>Expiration</label><input value="60"></div></div>')
    control = Control("7.2.9", "Guest expiration", "https://example.com", (),
                      screenshot_selector="#capture", highlight_selectors=("#row",))
    original = page.screenshot

    def incomplete(**kwargs):
        page.locator('[data-evidence-highlights] > div').evaluate(
            "el => el.style.borderRightColor = 'transparent'")
        return original(**kwargs)

    monkeypatch.setattr(page, "screenshot", incomplete)
    destination = tmp_path / "must-not-exist.png"
    with pytest.raises(RuntimeError, match="four complete highlight borders"):
        capture_highlights(page, control, destination)
    assert not destination.exists()
    assert page.locator('[data-evidence-highlights]').count() == 0
    page.close()
