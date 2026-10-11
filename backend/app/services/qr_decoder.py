import cv2
import numpy as np


class QRDecodeError(Exception):
    pass


def _attempts(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    yield img
    yield gray
    yield cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    yield cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 10)
    yield cv2.resize(gray, None, fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA)
    yield cv2.bitwise_not(gray)  # inverted QR codes


def decode_qr(data: bytes) -> list[str]:
    """Return every QR payload found in an image (several preprocessing passes)."""
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise QRDecodeError("That file is not a readable image. Upload a PNG, JPG or WebP.")
    h, w = img.shape[:2]
    if h * w > 30_000_000:
        raise QRDecodeError("Image is too large. Use a photo under 30 megapixels.")

    detector = cv2.QRCodeDetector()
    for candidate in _attempts(img):
        found = []
        try:
            ok, decoded, _, _ = detector.detectAndDecodeMulti(candidate)
            if ok:
                found = [d for d in decoded if d]
        except cv2.error:
            pass
        if not found:
            try:
                text, _, _ = detector.detectAndDecode(candidate)
                if text:
                    found = [text]
            except cv2.error:
                pass
        if found:
            return list(dict.fromkeys(found))  # de-duplicate, keep order
    raise QRDecodeError("No QR code found. Retake the photo with the code flat, well lit and fully in frame.")
