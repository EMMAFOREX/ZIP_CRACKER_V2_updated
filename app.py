from flask import Flask, render_template, request, jsonify, send_file
import zipfile
import itertools
import string
import os
import tempfile
from threading import Thread
import time
import json

app = Flask(__name__)

# In-memory storage for progress (in production, use Redis or database)
progress_data = {}

def generate_passwords(min_length, max_length, char_set):
    """Generate passwords based on character set and length range"""
    characters = ""
    
    if 'numeric' in char_set:
        characters += string.digits
    if 'lowercase' in char_set:
        characters += string.ascii_lowercase
    if 'uppercase' in char_set:
        characters += string.ascii_uppercase
    if 'special' in char_set:
        characters += string.punctuation
    
    if not characters:
        characters = string.digits + string.ascii_letters  # default
    
    for length in range(min_length, max_length + 1):
        for password in itertools.product(characters, repeat=length):
            yield ''.join(password)

def crack_zip_password(zip_path, min_length, max_length, char_set, task_id):
    """Attempt to crack ZIP password"""
    total_attempts = 0
    max_attempts = 1000000  # Safety limit
    
    # Calculate approximate total (for progress)
    chars_count = len(char_set)
    approximate_total = sum(chars_count ** i for i in range(min_length, max_length + 1))
    approximate_total = min(approximate_total, max_attempts)
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            # Get first file name for testing
            test_file = zip_file.namelist()[0] if zip_file.namelist() else None
            
            for password in generate_passwords(min_length, max_length, char_set):
                if total_attempts >= max_attempts:
                    progress_data[task_id] = {
                        'progress': 100,
                        'status': 'failed',
                        'message': 'Maximum attempts reached. Password too complex.',
                        'attempts': total_attempts
                    }
                    return
                
                try:
                    # Try to extract first file with password
                    if test_file:
                        zip_file.extract(test_file, pwd=password.encode('utf-8'), path=tempfile.gettempdir())
                    # If successful, we found the password!
                    progress_data[task_id] = {
                        'progress': 100,
                        'status': 'success',
                        'password': password,
                        'attempts': total_attempts + 1
                    }
                    return
                except (RuntimeError, zipfile.BadZipFile):
                    # Password failed, continue
                    total_attempts += 1
                    progress = min(99, (total_attempts / approximate_total) * 100)
                    
                    # Update progress every 100 attempts to reduce overhead
                    if total_attempts % 100 == 0:
                        progress_data[task_id] = {
                            'progress': progress,
                            'status': 'running',
                            'attempts': total_attempts
                        }
                
                except Exception as e:
                    total_attempts += 1
                    progress_data[task_id] = {
                        'progress': progress,
                        'status': 'error',
                        'message': f'Error: {str(e)}',
                        'attempts': total_attempts
                    }
                    return
    
    except Exception as e:
        progress_data[task_id] = {
            'progress': 0,
            'status': 'error',
            'message': f'Error processing ZIP file: {str(e)}'
        }
        return
    
    # If we get here, password wasn't found
    progress_data[task_id] = {
        'progress': 100,
        'status': 'failed',
        'message': 'Password not found. Try increasing maximum length.',
        'attempts': total_attempts
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start password cracking"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.lower().endswith('.zip'):
        return jsonify({'error': 'Please upload a ZIP file'}), 400
    
    # Get parameters
    min_length = int(request.form.get('min_length', 1))
    max_length = int(request.form.get('max_length', 4))
    
    char_set_options = []
    if request.form.get('numeric'): char_set_options.append('numeric')
    if request.form.get('lowercase'): char_set_options.append('lowercase')
    if request.form.get('uppercase'): char_set_options.append('uppercase')
    if request.form.get('special'): char_set_options.append('special')
    
    if not char_set_options:
        char_set_options = ['numeric', 'lowercase']  # default
    
    # Validate parameters
    if min_length < 1 or max_length < min_length:
        return jsonify({'error': 'Invalid length parameters'}), 400
    
    if max_length > 8:
        return jsonify({'error': 'Maximum length cannot exceed 8 for safety reasons'}), 400
    
    # Save uploaded file
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)
    
    # Generate task ID
    task_id = str(int(time.time() * 1000))
    
    # Start cracking in background thread
    thread = Thread(target=crack_zip_password, args=(
        file_path, min_length, max_length, char_set_options, task_id
    ))
    thread.daemon = True
    thread.start()
    
    # Initial progress
    progress_data[task_id] = {
        'progress': 0,
        'status': 'running',
        'attempts': 0
    }
    
    return jsonify({'task_id': task_id})

@app.route('/progress/<task_id>')
def get_progress(task_id):
    """Get current progress for a task"""
    if task_id not in progress_data:
        return jsonify({'error': 'Task not found'}), 404
    
    return jsonify(progress_data[task_id])

@app.route('/cleanup', methods=['POST'])
def cleanup():
    """Clean up old progress data"""
    current_time = time.time()
    keys_to_remove = []
    
    for task_id, data in progress_data.items():
        # Remove tasks older than 1 hour
        if current_time - int(task_id) / 1000 > 3600:
            keys_to_remove.append(task_id)
    
    for key in keys_to_remove:
        del progress_data[key]
    
    return jsonify({'cleaned': len(keys_to_remove)})

if __name__ == '__main__':
    app.run(debug=True)