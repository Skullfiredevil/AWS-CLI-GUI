import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import tempfile
import threading
from utils.aws_utils import run_aws_command

class CustomDragDrop:
    def __init__(self, parent, s3_service):
        self.parent = parent
        self.s3_service = s3_service
        self.temp_dir = tempfile.mkdtemp()
        
        # Set up the custom drag and drop alternative
        self.setup_custom_upload()
    
    def setup_custom_upload(self):
        """Set up a custom file upload area that doesn't rely on TkDND"""
        # Get the object tree from S3 service
        tree = self.s3_service.object_tree
        
        # Create a frame for the drop zone at the bottom of the S3 frame
        self.drop_frame = ttk.LabelFrame(self.s3_service.frame, text="File Upload Zone")
        self.drop_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        # Create a button to select files
        self.select_button = ttk.Button(
            self.drop_frame, 
            text="Select Files to Upload",
            command=self.select_files
        )
        self.select_button.pack(side=tk.TOP, pady=5)
        
        # Add a label with instructions
        ttk.Label(
            self.drop_frame,
            text="Select files to upload to the current bucket and folder",
            wraplength=300
        ).pack(side=tk.TOP, pady=5)
        
        # Add visual feedback for the drop zone
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(
            self.drop_frame,
            textvariable=self.status_var,
            foreground="green"
        )
        self.status_label.pack(side=tk.TOP, pady=5)
    
    def select_files(self):
        """Open a file dialog to select files for upload"""
        # Check if a bucket is selected
        if not self.s3_service.current_bucket:
            messagebox.showwarning("Warning", "Please select a bucket first.")
            return
        
        # Open file dialog to select multiple files
        files = filedialog.askopenfilenames(
            title="Select Files to Upload",
            filetypes=[("All Files", "*.*")]
        )
        
        if not files:
            return
        
        # Convert to list
        files_list = list(files)
        
        # Upload the selected files
        self.upload_files(files_list)
    
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
    
    def enable_drop_highlighting(self):
        """Enable visual feedback when files are dragged over the drop zone"""
        # This is a placeholder for future enhancement
        # Could be implemented with platform-specific solutions if needed
        pass