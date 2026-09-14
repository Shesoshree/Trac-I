"""Package deliverables into a clean ZIP archive for submission."""

import os
import sys
import zipfile

def package_project(output_zip="artifacts/Trac-I_Source_and_Models.zip"):
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.dirname(os.path.abspath(output_zip)), exist_ok=True)

    exclude_dirs = {
        ".venv", "venv", "__pycache__", ".git", ".idea", ".vscode", 
        "node_modules", ".pytest_cache", ".system_generated"
    }
    exclude_extensions = {".pyc", ".pyo", ".log", ".tmp"}

    count = 0
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(root_dir):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for f in files:
                ext = os.path.splitext(f)[1]
                if ext in exclude_extensions:
                    continue
                
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, root_dir)

                # Skip existing zip archive itself
                if rel_path.endswith(".zip"):
                    continue

                zf.write(full_path, rel_path)
                count += 1

    file_size_mb = os.path.getsize(output_zip) / (1024 * 1024)
    print(f"Packaged {count} files into {output_zip} ({file_size_mb:.2f} MB)")

if __name__ == "__main__":
    out = "artifacts/Trac-I_Source_and_Models.zip"
    if len(sys.argv) > 1:
        out = sys.argv[1]
    package_project(out)
