import os
import subprocess
import shutil
import tempfile

def strip_metadata(file_path):
    """
    Strips all metadata from a wav file using ffmpeg.
    """
    print(f"Processing: {file_path}")
    
    fd, temp_path = tempfile.mkstemp(suffix=".wav")
    os.close(fd)
    
    try:d
        command = [
            'ffmpeg', '-y', '-i', file_path,
            '-map_metadata', '-1',
            '-c:a', 'copy',
            '-fflags', '+bitexact',
            '-flags:a', '+bitexact',
            temp_path
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            shutil.move(temp_path, file_path)
            print(f"Successfully stripped metadata from: {file_path}")
        else:
            print(f"Error processing {file_path}: {result.stderr}")
            if os.path.exists(temp_path):
                os.remove(temp_path)
    except Exception as e:
        print(f"Failed to process {file_path}: {str(e)}")
        if os.path.exists(temp_path):
            os.remove(temp_path)

def main():
    root_dir = os.getcwd()
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.lower().endswith('.wav'):
                file_path = os.path.join(root, file)
                if os.path.abspath(file_path) == os.path.abspath(__file__):
                    continue
                strip_metadata(file_path)

if __name__ == "__main__":
    main()
