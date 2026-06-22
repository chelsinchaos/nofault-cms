import io

import pytest
from PIL import Image
from PIL.PngImagePlugin import PngInfo

from nofault.render.media import UnsupportedMediaError, strip_image_metadata


def _png_with_metadata(text_key: str, text_val: str) -> bytes:
    img = Image.new("RGB", (8, 8), "red")
    meta = PngInfo()
    meta.add_text(text_key, text_val)
    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=meta)
    return buf.getvalue()


def test_strips_png_text_metadata():
    secret = "GPS:40.7,-74.0 / source: apartment 4b"
    data = _png_with_metadata("Comment", secret)
    assert secret.encode() in data  # present before stripping

    clean, fmt = strip_image_metadata(data)
    assert fmt == "PNG"
    assert secret.encode() not in clean  # gone after stripping
    # re-opened image carries no text metadata
    reopened = Image.open(io.BytesIO(clean))
    assert "Comment" not in reopened.info


def test_jpeg_exif_dropped():
    img = Image.new("RGB", (8, 8), "blue")
    buf = io.BytesIO()
    # craft a tiny EXIF blob carrying an Artist tag
    exif = img.getexif()
    exif[0x013B] = "secret-author"  # Artist
    img.save(buf, format="JPEG", exif=exif)
    raw = buf.getvalue()

    clean, fmt = strip_image_metadata(raw)
    assert fmt == "JPEG"
    reopened = Image.open(io.BytesIO(clean))
    assert len(reopened.getexif()) == 0


def test_rejects_non_image():
    with pytest.raises(UnsupportedMediaError):
        strip_image_metadata(b"this is not an image")


def test_rejects_pdf():
    with pytest.raises(UnsupportedMediaError):
        strip_image_metadata(b"%PDF-1.7\n...")
