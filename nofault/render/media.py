"""Mandatory media metadata stripping.

Photos, scans and screenshots routinely embed GPS coordinates, capture
timestamps, camera serial numbers and author fields in EXIF/XMP/IPTC. For an
investigative source this metadata is repeatedly fatal. We therefore **re-encode**
every image (decode pixels, drop all metadata, re-emit) rather than trying to
selectively delete tags — re-encoding cannot leave a tag behind.

Only a small allowlist of raster formats is accepted; anything else (including
PDFs, which can carry extensive hidden metadata and active content) is rejected
so it cannot be published without an explicit, separate, audited path.
"""

from __future__ import annotations

import io

from PIL import Image

# Map input format -> safe re-encode target. JPEG/PNG/GIF/WebP cover the common
# field cases. We normalise GIF->PNG to avoid animation/comment channels.
_SUPPORTED = {"JPEG": "JPEG", "PNG": "PNG", "WEBP": "WEBP", "GIF": "PNG"}


class UnsupportedMediaError(ValueError):
    """Raised for media we refuse to process (so it can't leak metadata)."""


def strip_image_metadata(data: bytes) -> tuple[bytes, str]:
    """Return ``(clean_bytes, format)`` with all metadata removed.

    Raises :class:`UnsupportedMediaError` for unsupported or malformed input.
    """
    try:
        with Image.open(io.BytesIO(data)) as img:
            src_format = img.format or ""
            if src_format not in _SUPPORTED:
                raise UnsupportedMediaError(f"unsupported image format: {src_format!r}")
            target = _SUPPORTED[src_format]
            # Copy pixel data into a fresh image so no info/exif dict carries over.
            keeps_alpha = target in {"PNG", "WEBP"} and img.mode in {"RGBA", "LA", "P"}
            mode = "RGBA" if keeps_alpha else "RGB"
            # Copy pixels into a fresh image so no info/exif/icc dict carries over.
            src = img.convert(mode)
            clean = Image.new(mode, src.size)
            clean.paste(src)
            out = io.BytesIO()
            clean.save(out, format=target)
            return out.getvalue(), target
    except UnsupportedMediaError:
        raise
    except Exception as exc:  # malformed / decompression bomb / etc.
        raise UnsupportedMediaError(f"could not process image: {exc}") from exc
