import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import json
import os
import threading
from utils.aws_utils import run_aws_command, run_command_async, batch_process, clear_caches
from services.custom_drag_drop import CustomDragDrop

class S3Service:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Create the main layout
        self.create_widgets()
        
        # Initialize variables
        self.current_bucket = None
        self.current_prefix = ""
        self.objects = []
        
        # Initialize custom drag and drop handler
        self.drag_drop_handler = CustomDragDrop(parent, self)
    
    def create_widgets(self):
        # Create a frame for the bucket list
        bucket_frame = ttk.LabelFrame(self.frame, text="S3 Buckets")
        bucket_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a frame for bucket operations
        bucket_ops_frame = ttk.Frame(bucket_frame)
        bucket_ops_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add buttons for bucket operations
        ttk.Button(bucket_ops_frame, text="List Buckets", command=self.list_buckets).pack(side=tk.LEFT, padx=2)
        ttk.Button(bucket_ops_frame, text="Create Bucket", command=self.create_bucket).pack(side=tk.LEFT, padx=2)
        ttk.Button(bucket_ops_frame, text="Delete Bucket", command=self.delete_bucket).pack(side=tk.LEFT, padx=2)
        
        # Create a listbox for buckets
        self.bucket_listbox = tk.Listbox(bucket_frame)
        self.bucket_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.bucket_listbox.bind("<<ListboxSelect>>", self.on_bucket_select)
        
        # Create a frame for object operations
        object_frame = ttk.LabelFrame(self.frame, text="Bucket Contents")
        object_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a frame for navigation
        nav_frame = ttk.Frame(object_frame)
        nav_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add navigation controls
        ttk.Button(nav_frame, text="Up", command=self.go_up).pack(side=tk.LEFT, padx=2)
        self.path_var = tk.StringVar()
        ttk.Label(nav_frame, textvariable=self.path_var).pack(side=tk.LEFT, padx=5)
        
        # Create a frame for object operations
        object_ops_frame = ttk.Frame(object_frame)
        object_ops_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add buttons for object operations
        ttk.Button(object_ops_frame, text="Upload File", command=self.upload_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(object_ops_frame, text="Download File", command=self.download_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(object_ops_frame, text="Delete Object", command=self.delete_object).pack(side=tk.LEFT, padx=2)
        ttk.Button(object_ops_frame, text="Create Folder", command=self.create_folder).pack(side=tk.LEFT, padx=2)
        
        # Create a treeview for objects
        self.object_tree = ttk.Treeview(object_frame, columns=("Size", "Last Modified"))
        self.object_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure treeview columns
        self.object_tree.heading("#0", text="Name")
        self.object_tree.heading("Size", text="Size")
        self.object_tree.heading("Last Modified", text="Last Modified")
        self.object_tree.column("#0", width=250)
        self.object_tree.column("Size", width=100)
        self.object_tree.column("Last Modified", width=150)
        
        # Bind double-click event for navigation
        self.object_tree.bind("<Double-1>", self.on_object_double_click)
    
    def list_buckets(self):
        try:
            # Run AWS CLI command to list buckets with caching
            success, data = run_aws_command(['s3api', 'list-buckets'], use_cache=True)
            
            if not success:
                messagebox.showerror("Error", f"Failed to list buckets: {data}")
                return
            
            # Clear the listbox
            self.bucket_listbox.delete(0, tk.END)
            
            # Parse the output and add buckets to the listbox
            for bucket in data.get('Buckets', []):
                bucket_name = bucket.get('Name')
                if bucket_name:
                    self.bucket_listbox.insert(tk.END, bucket_name)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list buckets: {e}")
    
    def create_bucket(self):
        # Open a dialog to get the bucket name
        dialog = tk.Toplevel(self.parent)
        dialog.title("Create Bucket")
        dialog.geometry("400x150")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Bucket Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        bucket_name_entry = ttk.Entry(dialog, width=30)
        bucket_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Region:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        region_entry = ttk.Entry(dialog, width=30)
        region_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        region_entry.insert(0, "us-east-1")
        
        def on_create():
            bucket_name = bucket_name_entry.get().strip()
            region = region_entry.get().strip()
            
            if not bucket_name:
                messagebox.showerror("Error", "Bucket name cannot be empty")
                return
            
            try:
                # Run AWS CLI command to create bucket
                cmd = ["aws", "s3api", "create-bucket", "--bucket", bucket_name]
                
                # Add region if not us-east-1
                if region != "us-east-1":
                    cmd.extend(["--create-bucket-configuration", f"LocationConstraint={region}"])
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to create bucket: {result.stderr}")
                else:
                    messagebox.showinfo("Success", f"Bucket '{bucket_name}' created successfully")
                    dialog.destroy()
                    self.list_buckets()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create bucket: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Create", command=on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_bucket(self):
        # Get the selected bucket
        selection = self.bucket_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a bucket to delete")
            return
        
        bucket_name = self.bucket_listbox.get(selection[0])
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete bucket '{bucket_name}'?\n\nNote: The bucket must be empty to be deleted."):
            return
        
        try:
            # Run AWS CLI command to delete bucket
            result = subprocess.run(["aws", "s3api", "delete-bucket", "--bucket", bucket_name], capture_output=True, text=True)
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to delete bucket: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Bucket '{bucket_name}' deleted successfully")
                self.list_buckets()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete bucket: {e}")
    
    def on_bucket_select(self, event):
        # Get the selected bucket
        selection = self.bucket_listbox.curselection()
        if not selection:
            return
        
        bucket_name = self.bucket_listbox.get(selection[0])
        self.current_bucket = bucket_name
        self.current_prefix = ""
        self.path_var.set(f"s3://{bucket_name}/")
        
        # List objects in the bucket
        self.list_objects()
    
    def list_objects(self):
        if not self.current_bucket:
            return
        
        try:
            # Build command arguments
            command = ['s3api', 'list-objects-v2', '--bucket', self.current_bucket]
            args = []
            
            # Add prefix if not empty
            if self.current_prefix:
                args.extend(["--prefix", self.current_prefix])
                # Add delimiter for folder-like behavior
                args.extend(["--delimiter", "/"])
            else:
                args.extend(["--delimiter", "/"])
            
            # Run AWS CLI command to list objects with caching
            success, data = run_aws_command(command + args, use_cache=True)
            
            if not success:
                messagebox.showerror("Error", f"Failed to list objects: {data}")
                return
            
            # Clear the treeview
            for item in self.object_tree.get_children():
                self.object_tree.delete(item)
            
            # Add common prefixes (folders)
            if "CommonPrefixes" in data:
                for prefix in data["CommonPrefixes"]:
                    folder_name = prefix["Prefix"].split("/")[-2] + "/"  # Get the folder name
                    self.object_tree.insert("", "end", text=folder_name, values=("Folder", ""), image="")
            
            # Add objects (files)
            if "Contents" in data:
                self.objects = data["Contents"]
                for obj in self.objects:
                    # Skip the current prefix itself
                    if obj["Key"] == self.current_prefix:
                        continue
                    
                    # Get the file name (without the prefix)
                    if self.current_prefix:
                        if not obj["Key"].startswith(self.current_prefix):
                            continue
                        file_name = obj["Key"][len(self.current_prefix):]
                    else:
                        file_name = obj["Key"]
                    
                    # Skip if it's a folder (ends with /)
                    if file_name.endswith("/"):
                        continue
                    
                    # Skip if it contains / (in a subfolder)
                    if "/" in file_name:
                        continue
                    
                    # Format size
                    size = self.format_size(obj["Size"])
                    
                    # Format last modified
                    last_modified = obj["LastModified"]
                    
                    self.object_tree.insert("", "end", text=file_name, values=(size, last_modified), image="")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list objects: {e}")
    
    def format_size(self, size_bytes):
        # Format size in human-readable format
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def go_up(self):
        if not self.current_bucket:
            return
        
        if not self.current_prefix:
            return
        
        # Remove the last folder from the prefix
        parts = self.current_prefix.split("/")
        if len(parts) > 1:
            self.current_prefix = "/".join(parts[:-2]) + "/" if len(parts) > 2 else ""
        else:
            self.current_prefix = ""
        
        self.path_var.set(f"s3://{self.current_bucket}/{self.current_prefix}")
        self.list_objects()
    
    def on_object_double_click(self, event):
        # Get the selected item
        item_id = self.object_tree.selection()[0]
        item_text = self.object_tree.item(item_id, "text")
        
        # Check if it's a folder
        if item_text.endswith("/"):
            self.current_prefix += item_text
            self.path_var.set(f"s3://{self.current_bucket}/{self.current_prefix}")
            self.list_objects()
    
    def upload_file(self):
        if not self.current_bucket:
            messagebox.showwarning("Warning", "Please select a bucket first")
            return
        
        # Open file dialog to select a file
        file_path = filedialog.askopenfilename(
            title="Select File to Upload",
            filetypes=[("All Files", "*.*")]
        )
        
        if not file_path:
            return  # User cancelled
        
        # Get the file name from the path
        file_name = os.path.basename(file_path)
        
        # Determine the S3 key (path in the bucket)
        s3_key = self.current_prefix + file_name
        
        # Create a progress dialog
        progress_window = tk.Toplevel(self.parent)
        progress_window.title("Uploading File")
        progress_window.geometry("300x100")
        progress_window.transient(self.parent)
        progress_window.grab_set()
        
        ttk.Label(progress_window, text=f"Uploading {file_name}...").pack(pady=10)
        progress_var = tk.StringVar(value="Starting upload...")
        ttk.Label(progress_window, textvariable=progress_var).pack(pady=5)
        
        def upload_complete(success, data):
            progress_window.destroy()
            if not success:
                messagebox.showerror("Error", f"Failed to upload file: {data}")
            else:
                messagebox.showinfo("Success", f"File '{file_name}' uploaded successfully")
                # Refresh the object list
                self.list_objects()
        
        try:
            # Run AWS CLI command to upload file asynchronously
            command = ['s3', 'cp', file_path, f"s3://{self.current_bucket}/{s3_key}"]
            run_command_async(command, json_output=False, callback=upload_complete)
            
            # Update progress message
            progress_var.set("Upload in progress...")
            
        except Exception as e:
            progress_window.destroy()
            messagebox.showerror("Error", f"Failed to upload file: {e}")
    
    def download_file(self):
        if not self.current_bucket:
            messagebox.showwarning("Warning", "Please select a bucket first")
            return
        
        # Get the selected object
        selection = self.object_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to download")
            return
        
        # Get the object key
        item_id = selection[0]
        file_name = self.object_tree.item(item_id, "text")
        
        # Check if it's a folder
        if file_name.endswith("/"):
            messagebox.showwarning("Warning", "Cannot download folders. Please select a file.")
            return
        
        # Determine the full S3 key
        s3_key = self.current_prefix + file_name
        
        # Open file dialog to select save location
        save_path = filedialog.asksaveasfilename(
            title="Save File As",
            initialfile=file_name,
            filetypes=[("All Files", "*.*")]
        )
        
        if not save_path:
            return  # User cancelled
        
        # Create a progress dialog
        progress_window = tk.Toplevel(self.parent)
        progress_window.title("Downloading File")
        progress_window.geometry("300x100")
        progress_window.transient(self.parent)
        progress_window.grab_set()
        
        ttk.Label(progress_window, text=f"Downloading {file_name}...").pack(pady=10)
        progress_var = tk.StringVar(value="Starting download...")
        ttk.Label(progress_window, textvariable=progress_var).pack(pady=5)
        
        def download_complete(success, data):
            progress_window.destroy()
            if not success:
                messagebox.showerror("Error", f"Failed to download file: {data}")
            else:
                messagebox.showinfo("Success", f"File '{file_name}' downloaded successfully")
        
        try:
            # Run AWS CLI command to download file asynchronously
            command = ['s3', 'cp', f"s3://{self.current_bucket}/{s3_key}", save_path]
            run_command_async(command, json_output=False, callback=download_complete)
            
            # Update progress message
            progress_var.set("Download in progress...")
            
        except Exception as e:
            progress_window.destroy()
            messagebox.showerror("Error", f"Failed to download file: {e}")
    
    def delete_object(self):
        # Get the selected item
        selection = self.object_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an object to delete")
            return
        
        item_id = selection[0]
        object_name = self.object_tree.item(item_id, "text")
        
        # Construct the S3 key
        s3_key = self.current_prefix + object_name
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete '{object_name}'?"):
            return
        
        try:
            # Run AWS CLI command to delete object
            if object_name.endswith("/"):  # It's a folder
                # List all objects with this prefix
                result = subprocess.run(
                    ["aws", "s3", "ls", f"s3://{self.current_bucket}/{s3_key}", "--recursive"],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to list objects in folder: {result.stderr}")
                    return
                
                # Check if folder is empty
                if result.stdout.strip():
                    if not messagebox.askyesno("Warning", "This folder is not empty. Delete all contents?"):
                        return
                    
                    # Delete all objects in the folder
                    result = subprocess.run(
                        ["aws", "s3", "rm", f"s3://{self.current_bucket}/{s3_key}", "--recursive"],
                        capture_output=True,
                        text=True
                    )
                else:
                    # Delete the folder marker object
                    result = subprocess.run(
                        ["aws", "s3", "rm", f"s3://{self.current_bucket}/{s3_key}"],
                        capture_output=True,
                        text=True
                    )
            else:  # It's a file
                result = subprocess.run(
                    ["aws", "s3", "rm", f"s3://{self.current_bucket}/{s3_key}"],
                    capture_output=True,
                    text=True
                )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to delete object: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Object '{object_name}' deleted successfully")
                self.list_objects()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete object: {e}")
    
    def create_folder(self):
        if not self.current_bucket:
            messagebox.showwarning("Warning", "Please select a bucket first")
            return
        
        # Open a dialog to get the folder name
        dialog = tk.Toplevel(self.parent)
        dialog.title("Create Folder")
        dialog.geometry("400x100")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Folder Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        folder_name_entry = ttk.Entry(dialog, width=30)
        folder_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        def on_create():
            folder_name = folder_name_entry.get().strip()
            
            if not folder_name:
                messagebox.showerror("Error", "Folder name cannot be empty")
                return
            
            # Add trailing slash if not present
            if not folder_name.endswith("/"):
                folder_name += "/"
            
            # Construct the S3 key
            s3_key = self.current_prefix + folder_name
            
            try:
                # Run AWS CLI command to create folder (by creating an empty object with a trailing slash)
                result = subprocess.run(
                    ["aws", "s3api", "put-object", "--bucket", self.current_bucket, "--key", s3_key],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to create folder: {result.stderr}")
                else:
                    messagebox.showinfo("Success", f"Folder '{folder_name}' created successfully")
                    dialog.destroy()
                    self.list_objects()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create folder: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Create", command=on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)