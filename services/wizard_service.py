import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from utils.aws_utils import run_aws_command

class WizardService:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Initialize variables
        self.current_step = 0
        self.wizard_data = {}
        self.steps = []
        self.wizard_type = None
        
        # Create the main layout
        self.create_widgets()
    
    def create_widgets(self):
        # Create main container
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create wizard selection frame
        selection_frame = ttk.LabelFrame(main_container, text="Select Wizard")
        selection_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add wizard options
        self.wizard_var = tk.StringVar()
        ttk.Radiobutton(selection_frame, text="Create EC2 Instance", variable=self.wizard_var, 
                       value="ec2_create").pack(anchor=tk.W, padx=10, pady=5)
        ttk.Radiobutton(selection_frame, text="Set Up S3 Website", variable=self.wizard_var, 
                       value="s3_website").pack(anchor=tk.W, padx=10, pady=5)
        ttk.Radiobutton(selection_frame, text="Create IAM User with Policies", variable=self.wizard_var, 
                       value="iam_user").pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Button(selection_frame, text="Start Wizard", command=self.start_wizard).pack(anchor=tk.W, padx=10, pady=10)
        
        # Create wizard content frame
        self.wizard_frame = ttk.LabelFrame(main_container, text="Wizard")
        self.wizard_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initially hide the wizard content
        self.wizard_content = ttk.Frame(self.wizard_frame)
        self.wizard_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create navigation buttons
        nav_frame = ttk.Frame(self.wizard_frame)
        nav_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)
        
        self.prev_button = ttk.Button(nav_frame, text="Previous", command=self.previous_step, state=tk.DISABLED)
        self.prev_button.pack(side=tk.LEFT, padx=5)
        
        self.next_button = ttk.Button(nav_frame, text="Next", command=self.next_step, state=tk.DISABLED)
        self.next_button.pack(side=tk.RIGHT, padx=5)
        
        # Create progress indicator
        self.progress_var = tk.IntVar(value=0)
        self.progress = ttk.Progressbar(self.wizard_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)
        
        # Create status label
        self.status_label = ttk.Label(self.wizard_frame, text="Select a wizard to begin")
        self.status_label.pack(side=tk.BOTTOM, anchor=tk.W, padx=5)
    
    def start_wizard(self):
        # Get selected wizard type
        self.wizard_type = self.wizard_var.get()
        if not self.wizard_type:
            messagebox.showwarning("Warning", "Please select a wizard type first.")
            return
        
        # Clear previous wizard data
        self.wizard_data = {}
        self.current_step = 0
        
        # Clear wizard content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        # Set up steps based on wizard type
        if self.wizard_type == "ec2_create":
            self.setup_ec2_wizard()
        elif self.wizard_type == "s3_website":
            self.setup_s3_website_wizard()
        elif self.wizard_type == "iam_user":
            self.setup_iam_user_wizard()
        
        # Update UI
        self.update_wizard_ui()
        
        # Enable navigation
        self.next_button.config(state=tk.NORMAL)
        self.prev_button.config(state=tk.DISABLED)
    
    def setup_ec2_wizard(self):
        self.steps = [
            {"name": "Select AMI", "function": self.ec2_select_ami},
            {"name": "Choose Instance Type", "function": self.ec2_choose_instance_type},
            {"name": "Configure Security", "function": self.ec2_configure_security},
            {"name": "Review and Launch", "function": self.ec2_review_and_launch},
            {"name": "Launch Status", "function": self.ec2_launch_status}
        ]
    
    def setup_s3_website_wizard(self):
        self.steps = [
            {"name": "Create Bucket", "function": self.s3_create_bucket},
            {"name": "Configure Website", "function": self.s3_configure_website},
            {"name": "Upload Content", "function": self.s3_upload_content},
            {"name": "Set Permissions", "function": self.s3_set_permissions},
            {"name": "Review and Finish", "function": self.s3_review_and_finish}
        ]
    
    def setup_iam_user_wizard(self):
        self.steps = [
            {"name": "Create User", "function": self.iam_create_user},
            {"name": "Set Permissions", "function": self.iam_set_permissions},
            {"name": "Create Access Keys", "function": self.iam_create_access_keys},
            {"name": "Review and Finish", "function": self.iam_review_and_finish}
        ]
    
    def update_wizard_ui(self):
        # Update progress
        total_steps = len(self.steps)
        if total_steps > 0:
            progress_value = int((self.current_step / total_steps) * 100)
            self.progress_var.set(progress_value)
        
        # Update status label
        if 0 <= self.current_step < len(self.steps):
            self.status_label.config(text=f"Step {self.current_step + 1} of {len(self.steps)}: {self.steps[self.current_step]['name']}")
        
        # Call the function for the current step
        if 0 <= self.current_step < len(self.steps):
            self.steps[self.current_step]['function']()
    
    def next_step(self):
        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            self.update_wizard_ui()
            
            # Enable/disable navigation buttons
            self.prev_button.config(state=tk.NORMAL)
            if self.current_step == len(self.steps) - 1:
                self.next_button.config(text="Finish", command=self.finish_wizard)
        else:
            self.finish_wizard()
    
    def previous_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.update_wizard_ui()
            
            # Enable/disable navigation buttons
            if self.current_step == 0:
                self.prev_button.config(state=tk.DISABLED)
            self.next_button.config(text="Next", command=self.next_step)
    
    def finish_wizard(self):
        messagebox.showinfo("Wizard Complete", "The wizard has been completed successfully!")
        
        # Reset wizard
        self.current_step = 0
        self.wizard_data = {}
        self.steps = []
        
        # Clear wizard content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        # Disable navigation
        self.next_button.config(state=tk.DISABLED, text="Next", command=self.next_step)
        self.prev_button.config(state=tk.DISABLED)
        
        # Reset progress
        self.progress_var.set(0)
        self.status_label.config(text="Select a wizard to begin")
    
    # EC2 Wizard Step Functions
    def ec2_select_ami(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Select Amazon Machine Image (AMI)", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Get AMIs
        try:
            success, data = run_aws_command(['ec2', 'describe-images', '--owners', 'amazon', '--filters', 'Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2', 'Name=state,Values=available'], use_cache=True)
            
            if success and 'Images' in data:
                # Sort by creation date
                images = sorted(data['Images'], key=lambda x: x.get('CreationDate', ''), reverse=True)[:10]
                
                # Create a listbox for AMIs
                frame = ttk.Frame(self.wizard_content)
                frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                ttk.Label(frame, text="Available AMIs:").pack(anchor=tk.W)
                
                self.ami_listbox = tk.Listbox(frame, height=10)
                self.ami_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
                
                # Add AMIs to listbox
                self.ami_data = {}
                for image in images:
                    ami_id = image.get('ImageId', '')
                    name = image.get('Name', 'Unknown')
                    description = image.get('Description', 'No description')
                    display_text = f"{ami_id} - {name}"
                    self.ami_listbox.insert(tk.END, display_text)
                    self.ami_data[display_text] = ami_id
                
                # Add a description text area
                ttk.Label(frame, text="Description:").pack(anchor=tk.W, pady=(10, 0))
                self.ami_description = tk.Text(frame, height=5, wrap=tk.WORD)
                self.ami_description.pack(fill=tk.X, pady=5)
                self.ami_description.config(state=tk.DISABLED)
                
                # Bind selection event
                self.ami_listbox.bind('<<ListboxSelect>>', self.on_ami_select)
            else:
                ttk.Label(self.wizard_content, text="Failed to retrieve AMIs. Please check your AWS configuration.").pack(pady=10)
        except Exception as e:
            ttk.Label(self.wizard_content, text=f"Error: {str(e)}").pack(pady=10)
    
    def on_ami_select(self, event):
        # Get selected AMI
        selection = self.ami_listbox.curselection()
        if selection:
            index = selection[0]
            ami_display = self.ami_listbox.get(index)
            ami_id = self.ami_data.get(ami_display, '')
            
            # Store selected AMI
            self.wizard_data['ami_id'] = ami_id
            
            # Update description
            self.ami_description.config(state=tk.NORMAL)
            self.ami_description.delete(1.0, tk.END)
            self.ami_description.insert(tk.END, f"Selected AMI: {ami_id}\n\nThis will be used to create your EC2 instance.")
            self.ami_description.config(state=tk.DISABLED)
    
    def ec2_choose_instance_type(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Choose Instance Type", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create a frame for instance types
        frame = ttk.Frame(self.wizard_content)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Common instance types
        instance_types = [
            {"id": "t2.micro", "description": "1 vCPU, 1 GiB RAM - Free tier eligible"},
            {"id": "t2.small", "description": "1 vCPU, 2 GiB RAM"},
            {"id": "t2.medium", "description": "2 vCPU, 4 GiB RAM"},
            {"id": "m5.large", "description": "2 vCPU, 8 GiB RAM"},
            {"id": "c5.large", "description": "2 vCPU, 4 GiB RAM - Compute optimized"}
        ]
        
        # Create radio buttons for instance types
        self.instance_type_var = tk.StringVar()
        for i, instance in enumerate(instance_types):
            ttk.Radiobutton(
                frame, 
                text=f"{instance['id']} - {instance['description']}", 
                variable=self.instance_type_var, 
                value=instance['id']
            ).pack(anchor=tk.W, padx=10, pady=5)
        
        # Set default value
        self.instance_type_var.set("t2.micro")
        
        # Store the selected instance type
        self.wizard_data['instance_type'] = "t2.micro"
        
        # Add a callback for when the selection changes
        self.instance_type_var.trace_add("write", self.on_instance_type_change)
    
    def on_instance_type_change(self, *args):
        # Store the selected instance type
        self.wizard_data['instance_type'] = self.instance_type_var.get()