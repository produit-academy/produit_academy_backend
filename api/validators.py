import os
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

# Allowed extension profiles
ALLOWED_DOCUMENT_EXTENSIONS = {'.pdf', '.doc', '.docx', '.txt', '.zip'}
ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp'}
ALLOWED_AUDIO_EXTENSIONS = {'.mp3', '.wav', '.ogg', '.m4a', '.aac', '.webm'}
ALLOWED_STUDY_MATERIAL_EXTENSIONS = {'.pdf', '.doc', '.docx'}

# File size limits in bytes
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024       # 10 MB
MAX_AUDIO_SIZE_BYTES = 25 * 1024 * 1024       # 25 MB
MAX_DOCUMENT_SIZE_BYTES = 30 * 1024 * 1024    # 30 MB
MAX_MATERIAL_SIZE_BYTES = 50 * 1024 * 1024    # 50 MB

# Dangerous extensions that must never be uploaded under any circumstances
DISALLOWED_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.sh', '.bash', '.bin', '.dll', '.so',
    '.php', '.phtml', '.php5', '.py', '.rb', '.pl', '.cgi',
    '.js', '.ts', '.html', '.htm', '.xhtml', '.svg', '.jsp', '.asp', '.aspx',
    '.vbs', '.scr', '.msi', '.jar', '.war', '.apk'
}


def sanitize_filename(filename):
    """Sanitize filename to prevent directory traversal and strip dangerous characters."""
    if not filename:
        return 'unnamed_file'
    base = os.path.basename(str(filename).replace('\\', '/'))
    # Remove null bytes and non-printable characters
    cleaned = ''.join(c for c in base if c.isalnum() or c in '._- ')
    return cleaned.strip() or 'unnamed_file'


def validate_uploaded_file(uploaded_file, allowed_extensions=None, max_size_bytes=None):
    """
    Validates uploaded file extension, size, and checks against disallowed executable types.
    Raises ValidationError if any check fails.
    """
    if not uploaded_file:
        return

    name = getattr(uploaded_file, 'name', '')
    ext = os.path.splitext(name)[1].lower()

    # Reject dangerous executable / script files unconditionally
    if ext in DISALLOWED_EXTENSIONS:
        raise ValidationError(_(f"File type '{ext}' is not permitted for security reasons."))

    # Check allowed extensions whitelist
    if allowed_extensions and ext not in allowed_extensions:
        allowed_list = ', '.join(sorted(allowed_extensions))
        raise ValidationError(_(f"Unsupported file format '{ext}'. Allowed formats: {allowed_list}."))

    # Check file size
    size = getattr(uploaded_file, 'size', None)
    if size and max_size_bytes and size > max_size_bytes:
        max_mb = max_size_bytes / (1024 * 1024)
        raise ValidationError(_(f"File size exceeds maximum allowed limit of {max_mb:.0f} MB."))

