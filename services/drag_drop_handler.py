import tkinter as tk
from tkinter import ttk, messagebox
import os
import tempfile
from utils.aws_utils import run_aws_command

class DragDropHandler:
    def __init__(self, parent, s3_service):
        self.parent = parent
        self.s3_service = s3_service
        self.temp_dir = tempfile.mkdtemp()
        
        # Set up drag and drop bindings
        self.setup_drag_drop()
    
    def setup_drag_drop(self):
        """Set up drag and drop bindings for the S3 service object tree"""
        # Bind drag and drop events to the S3 object tree
        tree = self.s3_service.object_tree
        
        # Configure TkDND bindings if available
        try:
            # Try to load tkdnd
            self.parent.tk.call('package', 'require', 'tkdnd')
            
            # Set up the drag and drop bindings
            tree.drop_target_register('DND_Files')
            tree.dnd_bind('<<Drop>>', self.on_drop)
            
            # Add visual feedback for drag over
            tree.dnd_bind('<<DragEnter>>', lambda e: tree.config(background='#e0f0ff'))
            tree.dnd_bind('<<DragLeave>>', lambda e: tree.config(background='white'))
            
            # Add a label to indicate drag and drop is enabled
            label = ttk.Label(self.s3_service.frame, text="Drag and drop files here to upload")
            label.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        except tk.TclError:
            # TkDND not available, show a message
            print("TkDND not available. Drag and drop functionality disabled.")
            
            # Add a label to indicate how to install TkDND
            label = ttk.Label(
                self.s3_service.frame, 
                text="Drag and drop requires TkDND. Please install it for enhanced functionality.",
                foreground="red"
            )
            label.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
    
    def on_drop(self, event):
        """Handle file drop events"""
        # Get the dropped files
        files = self.parse_drop_data(event.data)
        
        if not files:
            return
        
        # Check if a bucket is selected
        if not self.s3_service.current_bucket:
            messagebox.showwarning("Warning", "Please select a bucket first.")
            return
        
        # Upload each file
        self.upload_files(files)
    
    def parse_drop_data(self, data):
        """Parse the drop data to extract file paths"""
        # Different platforms format the data differently
        if os.name == 'nt':  # Windows
            # Windows paths are separated by spaces and enclosed in {}
            files = []
            for item in data.split('} {'):
                item = item.strip('{}')
                if os.path.isfile(item):
                    files.append(item)
            return files
        else:  # Unix/Mac
            # Unix paths are separated by spaces
            files = []
            for item in data.split():
                if os.path.isfile(item):
                    files.append(item)
            return files
    
    def upload_files(self, files):
        """Upload multiple files to the current S3 bucket and prefix"""
        if not files:
            return
        
        # Get current bucket and prefix
        bucket = self.s3_service.current_bucket
        prefix = self.s3_service.current_prefix
        
        # Create a progress dialog
        progress_window = tk.Toplevel(self.parent)
        progress_window.title("Uploading Files")
        progress_window.geometry("400x200")
        
        # Add progress information
        ttk.Label(progress_window, text=f"Uploading {len(files)} files to {bucket}/{prefix}").pack(pady=10)
        
        # Add progress bar
        progress_var = tk.IntVar()
        progress = ttk.Progressbar(progress_window, variable=progress_var, maximum=len(files))
        progress.pack(fill=tk.X, padx=20, pady=10)
        
        # Add status label
        status_var = tk.StringVar(value="Preparing...")
        ttk.Label(progress_window, textvariable=status_var).pack(pady=5)
        
        # Start upload in a separate thread
        def upload_thread():
            success_count = 0
            for i, file_path in enumerate(files):
                try:
                    # Update status
                    file_name = os.path.basename(file_path)
                    status_var.set(f"Uploading {file_name}...")
                    progress_var.set(i)
                    progress_window.update()
                    
                    # Determine the S3 key (path in the bucket)
                    s3_key = prefix + file_name if prefix.endswith('/') or not prefix else prefix + '/' + file_name
                    
                    # Upload the file
                    success, result = run_aws_command(
                        ['s3', 'cp', file_path, f"s3://{bucket}/{s3_key}"],
                        use_cache=False,
                        json_output=False
                    )
                    
                    if success:
                        success_count += 1
                    else:
                        print(f"Failed to upload {file_name}: {result}")
                except Exception as e:
                    print(f"Error uploading {file_path}: {e}")
            
            # Update final status
            status_var.set(f"Completed: {success_count} of {len(files)} files uploaded successfully.")
            progress_var.set(len(files))
            
            # Add a close button
            ttk.Button(progress_window, text="Close", command=progress_window.destroy).pack(pady=10)
            
            # Refresh the file list
            self.s3_service.list_objects()
        
        # Start the upload thread
        threading.Thread(target=upload_thread).start()