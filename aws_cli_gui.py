#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import subprocess
import json
import threading

# Import service modules
from services.s3_service import S3Service
from services.ec2_service import EC2Service
from services.iam_service import IAMService
from services.wizard_service import WizardService
from utils.aws_utils import run_aws_command, run_command_async, get_aws_config

class AwsCliGui:
    def __init__(self, root):
        self.root = root
        self.root.title("AWS CLI GUI")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Set up the main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Check if AWS CLI is installed and configured
        if not self.check_aws_cli():
            messagebox.showerror("Error", "AWS CLI is not installed or configured properly. Please install and configure AWS CLI before using this application.")
            sys.exit(1)
        
        # Initialize service modules
        self.s3_service = S3Service(self.notebook)
        self.ec2_service = EC2Service(self.notebook)
        self.iam_service = IAMService(self.notebook)
        self.wizard_service = WizardService(self.notebook)
        
        # Add tabs to the notebook
        self.notebook.add(self.s3_service.frame, text="S3")
        self.notebook.add(self.ec2_service.frame, text="EC2")
        self.notebook.add(self.iam_service.frame, text="IAM")
        self.notebook.add(self.wizard_service.frame, text="Wizards")
        
        # Create a status bar
        self.status_bar = ttk.Label(self.root, text="Ready", anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create menu
        self.create_menu()
    
    def create_menu(self):
        menu_bar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="AWS Configuration", command=self.open_aws_config)
        tools_menu.add_command(label="Script Editor", command=self.open_script_editor)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.open_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menu_bar)
    
    def check_aws_cli(self):
        try:
            # Run 'aws --version' to check if AWS CLI is installed
            result = subprocess.run(["aws", "--version"], capture_output=True, text=True)
            if result.returncode != 0:
                return False
            
            # Check if AWS credentials are configured using our utility function
            success, _ = run_aws_command(['sts', 'get-caller-identity'], use_cache=True)
            return success
        except Exception as e:
            print(f"Error checking AWS CLI: {e}")
            return False
    
    def open_aws_config(self):
        # Open AWS configuration dialog
        config_window = tk.Toplevel(self.root)
        config_window.title("AWS Configuration")
        config_window.geometry("500x300")
        
        ttk.Label(config_window, text="AWS Configuration", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create a frame for the form
        form_frame = ttk.Frame(config_window)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # AWS Profile
        ttk.Label(form_frame, text="AWS Profile:").grid(row=0, column=0, sticky=tk.W, pady=5)
        profile_entry = ttk.Entry(form_frame, width=30)
        profile_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        profile_entry.insert(0, "default")
        
        # AWS Region
        ttk.Label(form_frame, text="AWS Region:").grid(row=1, column=0, sticky=tk.W, pady=5)
        region_entry = ttk.Entry(form_frame, width=30)
        region_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        region_entry.insert(0, "us-east-1")
        
        # Buttons
        button_frame = ttk.Frame(config_window)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Button(button_frame, text="Save", command=lambda: self.save_aws_config(profile_entry.get(), region_entry.get(), config_window)).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=config_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def save_aws_config(self, profile, region, window):
        try:
            # Set AWS profile and region using environment variables
            os.environ["AWS_PROFILE"] = profile
            os.environ["AWS_REGION"] = region
            
            # Update status bar
            self.status_bar.config(text=f"AWS Configuration updated: Profile={profile}, Region={region}")
            
            # Close the window
            window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save AWS configuration: {e}")
    
    def open_script_editor(self):
        # Open script editor window
        editor_window = tk.Toplevel(self.root)
        editor_window.title("AWS Script Editor")
        editor_window.geometry("700x500")
        
        # Create a text editor
        editor_frame = ttk.Frame(editor_window)
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add a toolbar
        toolbar = ttk.Frame(editor_frame)
        toolbar.pack(fill=tk.X, pady=5)
        
        ttk.Button(toolbar, text="New", command=lambda: self.clear_editor(text_editor)).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Open", command=lambda: self.open_script(text_editor, editor_window)).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Save", command=lambda: self.save_script(text_editor, editor_window)).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Run", command=lambda: self.run_script(text_editor)).pack(side=tk.LEFT, padx=2)
        
        # Add text editor with line numbers
        text_editor = tk.Text(editor_frame, wrap=tk.WORD, undo=True)
        text_editor.pack(fill=tk.BOTH, expand=True)
        
        # Add a status bar
        status_bar = ttk.Label(editor_window, text="Ready", anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def clear_editor(self, editor):
        editor.delete(1.0, tk.END)
    
    def open_script(self, editor, window):
        file_path = filedialog.askopenfilename(
            title="Open Script",
            filetypes=[("Python Files", "*.py"), ("Shell Scripts", "*.sh"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, "r") as file:
                    content = file.read()
                    editor.delete(1.0, tk.END)
                    editor.insert(tk.END, content)
                window.title(f"AWS Script Editor - {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file: {e}")
    
    def save_script(self, editor, window):
        file_path = filedialog.asksaveasfilename(
            title="Save Script",
            filetypes=[("Python Files", "*.py"), ("Shell Scripts", "*.sh"), ("All Files", "*.*")],
            defaultextension=".py"
        )
        
        if file_path:
            try:
                content = editor.get(1.0, tk.END)
                with open(file_path, "w") as file:
                    file.write(content)
                window.title(f"AWS Script Editor - {os.path.basename(file_path)}")
                messagebox.showinfo("Success", "Script saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")
    
    def run_script(self, editor):
        # Get the script content
        script_content = editor.get(1.0, tk.END)
        
        # Create a temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as temp_file:
            temp_file_path = temp_file.name
            temp_file.write(script_content.encode())
        
        try:
            # Run the script
            result = subprocess.run([sys.executable, temp_file_path], capture_output=True, text=True)
            
            # Show the output
            output_window = tk.Toplevel(self.root)
            output_window.title("Script Output")
            output_window.geometry("600x400")
            
            output_text = tk.Text(output_window, wrap=tk.WORD)
            output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            if result.stdout:
                output_text.insert(tk.END, "=== STDOUT ===\n")
                output_text.insert(tk.END, result.stdout)
            
            if result.stderr:
                output_text.insert(tk.END, "\n=== STDERR ===\n")
                output_text.insert(tk.END, result.stderr)
            
            output_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run script: {e}")
        finally:
            # Remove the temporary file
            os.unlink(temp_file_path)
    
    def open_documentation(self):
        # Open documentation window
        doc_window = tk.Toplevel(self.root)
        doc_window.title("AWS CLI GUI Documentation")
        doc_window.geometry("700x500")
        
        # Create a notebook for documentation sections
        doc_notebook = ttk.Notebook(doc_window)
        doc_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General tab
        general_frame = ttk.Frame(doc_notebook)
        doc_notebook.add(general_frame, text="General")
        
        general_text = tk.Text(general_frame, wrap=tk.WORD)
        general_text.pack(fill=tk.BOTH, expand=True)
        general_text.insert(tk.END, """# AWS CLI GUI Documentation

## Overview
AWS CLI GUI provides a graphical interface for managing AWS resources using the AWS CLI.

## Requirements
- Python 3.6 or higher
- Tkinter
- AWS CLI installed and configured

## Getting Started
1. Ensure AWS CLI is installed and configured
2. Launch the application
3. Use the tabs to navigate between different AWS services
""")
        general_text.config(state=tk.DISABLED)
        
        # S3 tab
        s3_frame = ttk.Frame(doc_notebook)
        doc_notebook.add(s3_frame, text="S3")
        
        s3_text = tk.Text(s3_frame, wrap=tk.WORD)
        s3_text.pack(fill=tk.BOTH, expand=True)
        s3_text.insert(tk.END, """# S3 Operations

## Listing Buckets
Click the 'List Buckets' button to display all available S3 buckets.

## Uploading Files
1. Select a bucket from the list
2. Click 'Upload File'
3. Choose a file from your local system
4. The file will be uploaded to the selected bucket

## Downloading Files
1. Select a bucket from the list
2. Browse the bucket contents
3. Select a file
4. Click 'Download File'
5. Choose a location to save the file
""")
        s3_text.config(state=tk.DISABLED)
        
        # EC2 tab
        ec2_frame = ttk.Frame(doc_notebook)
        doc_notebook.add(ec2_frame, text="EC2")
        
        ec2_text = tk.Text(ec2_frame, wrap=tk.WORD)
        ec2_text.pack(fill=tk.BOTH, expand=True)
        ec2_text.insert(tk.END, """# EC2 Operations

## Listing Instances
Click the 'List Instances' button to display all EC2 instances.

## Creating Instances
1. Click 'Create Instance'
2. Fill in the required information
3. Click 'Create'

## Managing Instances
1. Select an instance from the list
2. Use the buttons to start, stop, or terminate the instance
""")
        ec2_text.config(state=tk.DISABLED)
    
    def show_about(self):
        # Open about dialog
        about_window = tk.Toplevel(self.root)
        about_window.title("About AWS CLI GUI")
        about_window.geometry("400x300")
        about_window.resizable(False, False)
        
        # Add application icon/logo placeholder
        logo_frame = ttk.Frame(about_window)
        logo_frame.pack(pady=10)
        
        # Application title
        ttk.Label(about_window, text="AWS CLI GUI", font=("TkDefaultFont", 16, "bold")).pack(pady=5)
        
        # Version information
        ttk.Label(about_window, text="Version 1.0.0").pack()
        
        # Description
        description = ttk.Label(about_window, text="A graphical user interface for the AWS Command Line Interface", wraplength=350, justify="center")
        description.pack(pady=10)
        
        # Copyright information
        ttk.Label(about_window, text="© 2023 AWS CLI GUI Project").pack(pady=5)
        
        # Close button
        ttk.Button(about_window, text="Close", command=about_window.destroy).pack(pady=10)