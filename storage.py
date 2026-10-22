import os
import time
from werkzeug.utils import secure_filename

# GCS Configuration
GCS_BUCKET_NAME = os.environ.get('GCS_BUCKET_NAME', 'wapl-id-uploads')
USE_GCS = os.environ.get('USE_GCS', 'false').lower() == 'true'

# Import Google Cloud Storage if available
try:
    from google.cloud import storage as gcs_storage
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False
    print("google-cloud-storage not available, using local storage")


class Storage:
    """File storage handler - supports local and Google Cloud Storage"""
    
    _gcs_client = None
    _gcs_bucket = None
    
    @classmethod
    def _get_gcs_bucket(cls):
        """Get or create GCS bucket connection"""
        if not GCS_AVAILABLE or not USE_GCS:
            return None
        
        if cls._gcs_bucket is None:
            try:
                cls._gcs_client = gcs_storage.Client()
                cls._gcs_bucket = cls._gcs_client.bucket(GCS_BUCKET_NAME)
                print(f"✅ Connected to GCS bucket: {GCS_BUCKET_NAME}")
            except Exception as e:
                print(f"❌ Failed to connect to GCS: {e}")
                return None
        return cls._gcs_bucket
    
    @classmethod
    def save_file(cls, file_obj, subfolder=''):
        """
        Save a file to storage (GCS or local).
        Returns the relative path or GCS URL to the file.
        """
        if not file_obj:
            return None
            
        filename = secure_filename(file_obj.filename)
        # Add timestamp to ensure uniqueness
        timestamp = int(time.time())
        unique_filename = f"{os.path.splitext(filename)[0]}_{timestamp}{os.path.splitext(filename)[1]}"
        
        bucket = cls._get_gcs_bucket()
        
        if bucket:
            # Upload to GCS
            try:
                blob_path = f"{subfolder}/{unique_filename}" if subfolder else unique_filename
                blob = bucket.blob(blob_path)
                
                # Set content type
                content_type = file_obj.content_type or 'application/octet-stream'
                blob.upload_from_file(file_obj, content_type=content_type)
                
                # Return the public URL
                public_url = f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/{blob_path}"
                print(f"✅ Uploaded to GCS: {public_url}")
                return public_url
            except Exception as e:
                print(f"❌ GCS upload failed, falling back to local: {e}")
        
        # Local upload (fallback)
        upload_base_path = './uploads'
        target_dir = os.path.join(upload_base_path, subfolder)
        os.makedirs(target_dir, exist_ok=True)
        
        save_path = os.path.join(target_dir, unique_filename)
        file_obj.save(save_path)
        
        # Return local path identifier (to be served by Flask route)
        return f"{subfolder}/{unique_filename}" if subfolder else unique_filename

    @classmethod
    def delete_file(cls, path_or_url):
        """Delete file from storage (GCS or local)"""
        if not path_or_url:
            return
        
        # Check if it's a GCS URL
        if path_or_url.startswith('https://storage.googleapis.com/'):
            bucket = cls._get_gcs_bucket()
            if bucket:
                try:
                    # Extract blob path from URL
                    blob_path = path_or_url.replace(f'https://storage.googleapis.com/{GCS_BUCKET_NAME}/', '')
                    blob = bucket.blob(blob_path)
                    blob.delete()
                    print(f"🗑️ Deleted from GCS: {blob_path}")
                    return
                except Exception as e:
                    print(f"⚠️ Failed to delete from GCS: {e}")
            return
            
        # Local file deletion
        try:
            upload_base_path = './uploads'
            full_path = os.path.join(upload_base_path, path_or_url)
            if os.path.exists(full_path):
                os.remove(full_path)
                print(f"🗑️ Deleted local file: {full_path}")
        except Exception as e:
            print(f"⚠️ Failed to delete local file: {e}")

    @classmethod
    def upload_local_file(cls, local_path, subfolder=''):
        """Upload a local file to storage and return path/URL"""
        if not os.path.exists(local_path):
            return None
        
        bucket = cls._get_gcs_bucket()
        
        if bucket:
            # Upload to GCS
            try:
                filename = os.path.basename(local_path)
                blob_path = f"{subfolder}/{filename}" if subfolder else filename
                blob = bucket.blob(blob_path)
                blob.upload_from_filename(local_path)
                public_url = f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/{blob_path}"
                print(f"✅ Uploaded to GCS: {public_url}")
                return public_url
            except Exception as e:
                print(f"❌ GCS upload failed: {e}")
        
        # Return local path
        normalized_path = local_path.replace('\\', '/')
        if 'uploads/' in normalized_path:
            path_parts = normalized_path.split('uploads/')
            return 'uploads/' + path_parts[1]
        return normalized_path
    
    @classmethod
    def get_public_url(cls, path_or_url):
        """Get the public URL for a file"""
        if not path_or_url:
            return None
        
        # Already a full URL
        if path_or_url.startswith('http'):
            return path_or_url
        
        # GCS is enabled but path is local - could be an old file
        if USE_GCS and GCS_AVAILABLE:
            # Check if file exists in GCS
            bucket = cls._get_gcs_bucket()
            if bucket:
                blob = bucket.blob(path_or_url)
                if blob.exists():
                    return f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/{path_or_url}"
        
        # Return local path (will be served by Flask)
        return f"/uploads/{path_or_url}"
