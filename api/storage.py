import os
import requests
import cloudinary
import cloudinary.uploader
import cloudinary.utils
from django.core.files.storage import Storage
from django.core.files.base import ContentFile
from django.utils.deconstruct import deconstructible


@deconstructible
class CloudinaryMediaStorage(Storage):
    """
    Custom Cloudinary Storage backend that uploads all files (images, PDFs, documents, audio)
    with resource_type='auto' and generates secure CDN URLs on demand.
    """

    def _save(self, name, content):
        clean_name = str(name).replace('\\', '/').lstrip('/')
        folder = os.path.dirname(clean_name)

        upload_options = {
            'resource_type': 'auto',
            'use_filename': True,
            'unique_filename': True,
        }
        if folder:
            upload_options['folder'] = folder

        if hasattr(content, 'seek') and callable(content.seek):
            content.seek(0)

        response = cloudinary.uploader.upload(content, **upload_options)

        public_id = response.get('public_id')
        fmt = response.get('format')
        if fmt and not public_id.lower().endswith(f".{fmt.lower()}"):
            stored_name = f"{public_id}.{fmt}"
        else:
            stored_name = public_id

        return stored_name

    def url(self, name):
        if not name:
            return ''
        name_str = str(name).strip()
        if name_str.startswith('http://') or name_str.startswith('https://'):
            return name_str

        ext = os.path.splitext(name_str)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp', '.ico', '.pdf']:
            res_type = 'image'
        elif ext in ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.mp3', '.wav', '.ogg']:
            res_type = 'video'
        else:
            res_type = 'raw'

        cld_url, _ = cloudinary.utils.cloudinary_url(
            name_str,
            resource_type=res_type,
            secure=True
        )
        return cld_url

    def exists(self, name):
        return False

    def size(self, name):
        return None

    def _open(self, name, mode='rb'):
        target_url = self.url(name)
        if target_url.startswith('http://') or target_url.startswith('https://'):
            res = requests.get(target_url, timeout=10)
            if res.status_code == 200:
                file_obj = ContentFile(res.content)
                file_obj.name = os.path.basename(name)
                return file_obj
        return None
