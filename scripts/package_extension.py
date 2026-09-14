"""Package the extension directory into a downloadable zip file."""
import os
import zipfile

def package_extension():
    ext_dir = "extension"
    out_zip = "static/downloads/scam-detective-extension.zip"
    os.makedirs(os.path.dirname(out_zip), exist_ok=True)
    
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(ext_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, ext_dir)
                zf.write(full_path, rel_path)
                
    print(f"Extension successfully packaged to {out_zip}")

if __name__ == "__main__":
    package_extension()
