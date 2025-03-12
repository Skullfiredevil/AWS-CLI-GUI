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

    def ec2_configure_security(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Configure Security", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create frame for security group settings
        security_frame = ttk.LabelFrame(self.wizard_content, text="Security Group")
        security_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Security group name
        name_frame = ttk.Frame(security_frame)
        name_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(name_frame, text="Security Group Name:").pack(side=tk.LEFT, padx=5)
        sg_name_var = tk.StringVar(value=f"wizard-sg-{self.wizard_data.get('instance_type', 'default')}")
        sg_name_entry = ttk.Entry(name_frame, textvariable=sg_name_var, width=30)
        sg_name_entry.pack(side=tk.LEFT, padx=5)
        
        # Security group description
        desc_frame = ttk.Frame(security_frame)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(desc_frame, text="Description:").pack(side=tk.LEFT, padx=5)
        sg_desc_var = tk.StringVar(value="Security group created by AWS CLI GUI Wizard")
        sg_desc_entry = ttk.Entry(desc_frame, textvariable=sg_desc_var, width=40)
        sg_desc_entry.pack(side=tk.LEFT, padx=5)
        
        # Inbound rules frame
        rules_frame = ttk.LabelFrame(self.wizard_content, text="Inbound Rules")
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Common ports
        common_ports = [
            {"name": "SSH", "port": 22, "protocol": "tcp", "description": "SSH access"},
            {"name": "HTTP", "port": 80, "protocol": "tcp", "description": "Web access"},
            {"name": "HTTPS", "port": 443, "protocol": "tcp", "description": "Secure web access"},
            {"name": "RDP", "port": 3389, "protocol": "tcp", "description": "Remote Desktop"}
        ]
        
        # Create checkboxes for common ports
        self.port_vars = {}
        for port in common_ports:
            var = tk.BooleanVar(value=True if port["name"] == "SSH" else False)
            self.port_vars[port["name"]] = var
            ttk.Checkbutton(
                rules_frame,
                text=f"{port['name']} (Port {port['port']}) - {port['description']}",
                variable=var
            ).pack(anchor=tk.W, padx=10, pady=2)
        
        # Store the security group configuration
        self.wizard_data.update({
            "security_group_name": sg_name_var.get(),
            "security_group_description": sg_desc_var.get(),
            "security_group_ports": self.port_vars
        })

    def ec2_review_and_launch(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Review and Launch", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create a frame for the review information
        review_frame = ttk.Frame(self.wizard_content)
        review_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Display instance configuration
        ttk.Label(review_frame, text="Instance Configuration", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        # AMI Information
        ami_frame = ttk.LabelFrame(review_frame, text="Amazon Machine Image (AMI)")
        ami_frame.pack(fill=tk.X, pady=5)
        
        ami_id = self.wizard_data.get('ami_id', 'Not selected')
        ami_name = self.wizard_data.get('ami_name', 'Not selected')
        ttk.Label(ami_frame, text=f"AMI ID: {ami_id}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(ami_frame, text=f"AMI Name: {ami_name}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Instance Type
        type_frame = ttk.LabelFrame(review_frame, text="Instance Type")
        type_frame.pack(fill=tk.X, pady=5)
        
        instance_type = self.wizard_data.get('instance_type', 'Not selected')
        ttk.Label(type_frame, text=f"Type: {instance_type}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Security Group
        sg_frame = ttk.LabelFrame(review_frame, text="Security Group")
        sg_frame.pack(fill=tk.X, pady=5)
        
        sg_name = self.wizard_data.get('security_group_name', 'Not configured')
        sg_desc = self.wizard_data.get('security_group_description', 'Not configured')
        ttk.Label(sg_frame, text=f"Name: {sg_name}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(sg_frame, text=f"Description: {sg_desc}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Display enabled ports
        ttk.Label(sg_frame, text="Enabled Ports:").pack(anchor=tk.W, padx=5, pady=2)
        port_vars = self.wizard_data.get('security_group_ports', {})
        for port_name, var in port_vars.items():
            if var.get():
                ttk.Label(sg_frame, text=f"- {port_name}").pack(anchor=tk.W, padx=15, pady=1)
        
        # Add a confirmation checkbox
        self.confirm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            review_frame,
            text="I acknowledge that I have reviewed the instance configuration",
            variable=self.confirm_var,
            command=self.update_launch_button
        ).pack(pady=10)
        
        # Add launch button
        self.launch_button = ttk.Button(
            review_frame,
            text="Launch Instance",
            command=self.launch_instance,
            state=tk.DISABLED
        )
        self.launch_button.pack(pady=5)
    
    def update_launch_button(self):
        # Enable/disable launch button based on confirmation
        if self.confirm_var.get():
            self.launch_button.config(state=tk.NORMAL)
        else:
            self.launch_button.config(state=tk.DISABLED)
    
    def launch_instance(self):
        # Store the confirmation in wizard data
        self.wizard_data['confirmed'] = self.confirm_var.get()
        
        # Move to the next step (launch status)
        self.next_step()

    def ec2_launch_status(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Launch Status", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create status frame
        status_frame = ttk.Frame(self.wizard_content)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create security group
        ttk.Label(status_frame, text="Creating security group...").pack(anchor=tk.W, pady=2)
        try:
            # Create security group
            success, sg_data = run_aws_command([
                'ec2', 'create-security-group',
                '--group-name', self.wizard_data['security_group_name'],
                '--description', self.wizard_data['security_group_description']
            ])
            
            if not success:
                raise Exception(f"Failed to create security group: {sg_data}")
            
            sg_id = sg_data['GroupId']
            ttk.Label(status_frame, text=f"✓ Security group created: {sg_id}").pack(anchor=tk.W, pady=2)
            
            # Add security group rules
            port_vars = self.wizard_data['security_group_ports']
            for port_name, var in port_vars.items():
                if var.get():
                    port_mapping = {
                        'SSH': 22,
                        'HTTP': 80,
                        'HTTPS': 443,
                        'RDP': 3389
                    }
                    port = port_mapping.get(port_name)
                    if port:
                        success, _ = run_aws_command([
                            'ec2', 'authorize-security-group-ingress',
                            '--group-id', sg_id,
                            '--protocol', 'tcp',
                            '--port', str(port),
                            '--cidr', '0.0.0.0/0'
                        ])
                        
                        if success:
                            ttk.Label(status_frame, text=f"✓ Added {port_name} rule (port {port})").pack(anchor=tk.W, pady=2)
            
            # Launch EC2 instance
            ttk.Label(status_frame, text="\nLaunching EC2 instance...").pack(anchor=tk.W, pady=2)
            success, instance_data = run_aws_command([
                'ec2', 'run-instances',
                '--image-id', self.wizard_data['ami_id'],
                '--instance-type', self.wizard_data['instance_type'],
                '--security-group-ids', sg_id,
                '--count', '1'
            ])
            
            if not success:
                raise Exception(f"Failed to launch instance: {instance_data}")
            
            instance_id = instance_data['Instances'][0]['InstanceId']
            ttk.Label(status_frame, text=f"✓ Instance launched: {instance_id}").pack(anchor=tk.W, pady=2)
            
            # Add name tag to instance
            success, _ = run_aws_command([
                'ec2', 'create-tags',
                '--resources', instance_id,
                '--tags', 'Key=Name,Value=Wizard Created Instance'
            ])
            
            if success:
                ttk.Label(status_frame, text="✓ Added name tag to instance").pack(anchor=tk.W, pady=2)
            
            # Show success message
            success_msg = ttk.Label(status_frame, text="\n✓ Instance launch completed successfully!", font=("TkDefaultFont", 10, "bold"))
            success_msg.pack(anchor=tk.W, pady=10)
            
            # Store instance ID in wizard data
            self.wizard_data['instance_id'] = instance_id
            
        except Exception as e:
            # Show error message
            error_msg = ttk.Label(status_frame, text=f"\n❌ Error: {str(e)}", foreground="red")
            error_msg.pack(anchor=tk.W, pady=10)
        
        # Add finish button
        ttk.Button(status_frame, text="Close Wizard", command=self.finish_wizard).pack(pady=10)

    def s3_create_bucket(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Create S3 Bucket", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create input frame
        input_frame = ttk.Frame(self.wizard_content)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Bucket name input
        ttk.Label(input_frame, text="Bucket Name:").pack(anchor=tk.W, pady=2)
        bucket_name_var = tk.StringVar()
        bucket_name_entry = ttk.Entry(input_frame, textvariable=bucket_name_var, width=40)
        bucket_name_entry.pack(anchor=tk.W, pady=2)
        ttk.Label(input_frame, text="Note: Bucket name must be globally unique and DNS-compatible", 
                 font=("TkDefaultFont", 8)).pack(anchor=tk.W)
        
        # Region selection
        ttk.Label(input_frame, text="Region:").pack(anchor=tk.W, pady=(10,2))
        region_var = tk.StringVar(value="us-east-1")
        region_combo = ttk.Combobox(input_frame, textvariable=region_var, width=30)
        region_combo['values'] = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"
        ]
        region_combo.pack(anchor=tk.W, pady=2)
        
        # Store the variables in wizard data
        self.wizard_data.update({
            "bucket_name": bucket_name_var,
            "region": region_var
        })
    
    def s3_configure_website(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Configure Website", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create configuration frame
        config_frame = ttk.Frame(self.wizard_content)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Index document
        ttk.Label(config_frame, text="Index Document:").pack(anchor=tk.W, pady=2)
        index_var = tk.StringVar(value="index.html")
        index_entry = ttk.Entry(config_frame, textvariable=index_var, width=30)
        index_entry.pack(anchor=tk.W, pady=2)
        
        # Error document
        ttk.Label(config_frame, text="Error Document (optional):").pack(anchor=tk.W, pady=(10,2))
        error_var = tk.StringVar(value="error.html")
        error_entry = ttk.Entry(config_frame, textvariable=error_var, width=30)
        error_entry.pack(anchor=tk.W, pady=2)
        
        # Store the variables in wizard data
        self.wizard_data.update({
            "index_document": index_var,
            "error_document": error_var
        })
    
    def s3_upload_content(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Upload Website Content", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create upload frame
        upload_frame = ttk.Frame(self.wizard_content)
        upload_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # File list
        self.file_list = tk.Listbox(upload_frame, selectmode=tk.MULTIPLE, height=10)
        self.file_list.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Buttons frame
        button_frame = ttk.Frame(upload_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        def add_files():
            files = filedialog.askopenfilenames(
                title="Select Website Files",
                filetypes=[("HTML files", "*.html"), ("CSS files", "*.css"),
                           ("JavaScript files", "*.js"), ("All files", "*.*")]
            )
            for file in files:
                self.file_list.insert(tk.END, file)
        
        ttk.Button(button_frame, text="Add Files", command=add_files).pack(side=tk.LEFT, padx=5)
        
        def remove_selected():
            selected = self.file_list.curselection()
            for index in reversed(selected):
                self.file_list.delete(index)
        
        ttk.Button(button_frame, text="Remove Selected", command=remove_selected).pack(side=tk.LEFT, padx=5)
        
        # Store the file list widget in wizard data
        self.wizard_data['file_list'] = self.file_list
    
    def s3_set_permissions(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Set Website Permissions", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create permissions frame
        perm_frame = ttk.Frame(self.wizard_content)
        perm_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Public access settings
        public_access_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            perm_frame,
            text="Enable public access (Required for static website)",
            variable=public_access_var
        ).pack(anchor=tk.W, pady=5)
        
        # Show bucket policy
        ttk.Label(perm_frame, text="Bucket Policy:", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(10,5))
        
        policy_text = tk.Text(perm_frame, height=10, width=50)
        policy_text.pack(fill=tk.X, pady=5)
        
        bucket_name = self.wizard_data["bucket_name"].get()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}/*"]
            }]
        }
        
        policy_text.insert("1.0", json.dumps(policy, indent=4))
        policy_text.config(state=tk.DISABLED)
        
        # Store the variables in wizard data
        self.wizard_data.update({
            "public_access": public_access_var,
            "bucket_policy": policy
        })
    
    def s3_review_and_finish(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Review and Finish", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create review frame
        review_frame = ttk.Frame(self.wizard_content)
        review_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Display configuration summary
        ttk.Label(review_frame, text="Website Configuration", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        bucket_name = self.wizard_data["bucket_name"].get()
        region = self.wizard_data["region"].get()
        index_doc = self.wizard_data["index_document"].get()
        error_doc = self.wizard_data["error_document"].get()
        
        ttk.Label(review_frame, text=f"Bucket Name: {bucket_name}").pack(anchor=tk.W, pady=2)
        ttk.Label(review_frame, text=f"Region: {region}").pack(anchor=tk.W, pady=2)
        ttk.Label(review_frame, text=f"Index Document: {index_doc}").pack(anchor=tk.W, pady=2)
        ttk.Label(review_frame, text=f"Error Document: {error_doc}").pack(anchor=tk.W, pady=2)
        
        # Display selected files
        ttk.Label(review_frame, text="\nFiles to Upload:", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=5)
        for i in range(self.wizard_data['file_list'].size()):
            ttk.Label(review_frame, text=f"- {os.path.basename(self.wizard_data['file_list'].get(i))}").pack(anchor=tk.W, pady=1)
        
        # Add confirmation checkbox
        self.confirm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            review_frame,
            text="I confirm the website configuration",
            variable=self.confirm_var,
            command=self.update_finish_button
        ).pack(pady=10)
        
        # Add finish button
        self.finish_button = ttk.Button(
            review_frame,
            text="Create Website",
            command=self.create_website,
            state=tk.DISABLED
        )
        self.finish_button.pack(pady=5)
    
    def update_finish_button(self):
        if self.confirm_var.get():
            self.finish_button.config(state=tk.NORMAL)
        else:
            self.finish_button.config(state=tk.DISABLED)
    
    def create_website(self):
        # Get configuration values
        bucket_name = self.wizard_data["bucket_name"].get()
        region = self.wizard_data["region"].get()
        index_doc = self.wizard_data["index_document"].get()
        error_doc = self.wizard_data["error_document"].get()
        
        try:
            # Create bucket
            success, _ = run_aws_command([
                's3api', 'create-bucket',
                '--bucket', bucket_name,
                '--create-bucket-configuration',
                f'LocationConstraint={region}' if region != 'us-east-1' else '{}'
            ])
            
            if not success:
                raise Exception("Failed to create bucket")
            
            # Enable website hosting
            success, _ = run_aws_command([
                's3api', 'put-bucket-website',
                '--bucket', bucket_name,
                '--website-configuration',
                json.dumps({
                    "IndexDocument": {"Suffix": index_doc},
                    "ErrorDocument": {"Key": error_doc}
                })
            ])
            
            if not success:
                raise Exception("Failed to configure website")
            
            # Set bucket policy
            if self.wizard_data["public_access"].get():
                success, _ = run_aws_command([
                    's3api', 'put-bucket-policy',
                    '--bucket', bucket_name,
                    '--policy', json.dumps(self.wizard_data["bucket_policy"])
                ])
                
                if not success:
                    raise Exception("Failed to set bucket policy")
            
            # Upload files
            for i in range(self.wizard_data['file_list'].size()):
                file_path = self.wizard_data['file_list'].get(i)
                file_name = os.path.basename(file_path)
                
                success, _ = run_aws_command([
                    's3', 'cp',
                    file_path,
                    f's3://{bucket_name}/{file_name}'
                ])
                
                if not success:
                    raise Exception(f"Failed to upload {file_name}")
            
            # Show success message with website URL
            website_url = f"http://{bucket_name}.s3-website-{region}.amazonaws.com"
            messagebox.showinfo(
                "Success",
                f"Website created successfully!\n\nWebsite URL:\n{website_url}"
            )
            
            # Close the wizard
            self.finish_wizard()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create website: {str(e)}")

    def iam_create_user(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Create IAM User", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create input frame
        input_frame = ttk.Frame(self.wizard_content)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Username input
        ttk.Label(input_frame, text="Username:").pack(anchor=tk.W, pady=2)
        username_var = tk.StringVar()
        username_entry = ttk.Entry(input_frame, textvariable=username_var, width=30)
        username_entry.pack(anchor=tk.W, pady=2)
        
        # Console access
        console_access_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            input_frame,
            text="Enable AWS Management Console access",
            variable=console_access_var
        ).pack(anchor=tk.W, pady=5)
        
        # Password frame (only shown if console access is enabled)
        password_frame = ttk.Frame(input_frame)
        
        def toggle_password_frame():
            if console_access_var.get():
                password_frame.pack(fill=tk.X, pady=5)
            else:
                password_frame.pack_forget()
        
        console_access_var.trace('w', lambda *args: toggle_password_frame())
        
        # Password options
        password_var = tk.StringVar(value="auto")
        ttk.Radiobutton(password_frame, text="Auto-generate password", 
                       variable=password_var, value="auto").pack(anchor=tk.W)
        ttk.Radiobutton(password_frame, text="Custom password", 
                       variable=password_var, value="custom").pack(anchor=tk.W)
        
        # Custom password entry
        custom_password_var = tk.StringVar()
        custom_password_entry = ttk.Entry(password_frame, textvariable=custom_password_var, 
                                        width=30, show="*")
        
        def toggle_password_entry():
            if password_var.get() == "custom":
                custom_password_entry.pack(anchor=tk.W, pady=5)
            else:
                custom_password_entry.pack_forget()
        
        password_var.trace('w', lambda *args: toggle_password_entry())
        
        # Force password change
        force_change_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            password_frame,
            text="Require password change at next sign-in",
            variable=force_change_var
        ).pack(anchor=tk.W, pady=5)
        
        # Show password frame if console access is initially enabled
        toggle_password_frame()
        
        # Store the variables in wizard data
        self.wizard_data.update({
            "username": username_var,
            "console_access": console_access_var,
            "password_type": password_var,
            "custom_password": custom_password_var,
            "force_change": force_change_var
        })
    
    def iam_set_permissions(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Set User Permissions", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create permissions frame
        perm_frame = ttk.Frame(self.wizard_content)
        perm_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Permission type selection
        ttk.Label(perm_frame, text="Permission Type:", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        perm_type_var = tk.StringVar(value="managed")
        ttk.Radiobutton(perm_frame, text="AWS Managed Policies", 
                       variable=perm_type_var, value="managed").pack(anchor=tk.W)
        ttk.Radiobutton(perm_frame, text="Custom Policy", 
                       variable=perm_type_var, value="custom").pack(anchor=tk.W)
        
        # Managed policies frame
        managed_frame = ttk.Frame(perm_frame)
        managed_frame.pack(fill=tk.X, pady=10)
        
        # Common managed policies
        common_policies = [
            ("AmazonS3ReadOnlyAccess", "Read-only access to all S3 buckets"),
            ("AmazonEC2FullAccess", "Full access to EC2 resources"),
            ("AWSLambdaBasicExecutionRole", "Basic Lambda execution permissions"),
            ("AmazonRDSReadOnlyAccess", "Read-only access to RDS resources")
        ]
        
        self.policy_vars = {}
        for policy, description in common_policies:
            var = tk.BooleanVar()
            self.policy_vars[policy] = var
            ttk.Checkbutton(
                managed_frame,
                text=f"{policy} - {description}",
                variable=var
            ).pack(anchor=tk.W, pady=2)
        
        # Custom policy frame
        custom_frame = ttk.Frame(perm_frame)
        
        def toggle_policy_frames():
            if perm_type_var.get() == "managed":
                managed_frame.pack(fill=tk.X, pady=10)
                custom_frame.pack_forget()
            else:
                managed_frame.pack_forget()
                custom_frame.pack(fill=tk.X, pady=10)
        
        perm_type_var.trace('w', lambda *args: toggle_policy_frames())
        
        # Custom policy editor
        ttk.Label(custom_frame, text="Custom Policy JSON:").pack(anchor=tk.W)
        
        policy_text = tk.Text(custom_frame, height=10, width=50)
        policy_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Default custom policy template
        default_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::example-bucket"]
            }]
        }
        policy_text.insert("1.0", json.dumps(default_policy, indent=4))
        
        # Store the variables in wizard data
        self.wizard_data.update({
            "permission_type": perm_type_var,
            "managed_policies": self.policy_vars,
            "custom_policy": policy_text
        })
    
    def iam_create_access_keys(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Create Access Keys", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create access keys frame
        keys_frame = ttk.Frame(self.wizard_content)
        keys_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Access key option
        create_keys_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            keys_frame,
            text="Create access key for programmatic access",
            variable=create_keys_var
        ).pack(anchor=tk.W, pady=5)
        
        # Warning message
        ttk.Label(
            keys_frame,
            text="Note: Access keys grant programmatic access to AWS resources.",
            font=("TkDefaultFont", 9)
        ).pack(anchor=tk.W, pady=5)
        
        ttk.Label(
            keys_frame,
            text="The secret access key will only be shown once after creation.",
            font=("TkDefaultFont", 9)
        ).pack(anchor=tk.W)
        
        # Store the variables in wizard data
        self.wizard_data["create_access_keys"] = create_keys_var
    
    def iam_review_and_finish(self):
        # Clear previous content
        for widget in self.wizard_content.winfo_children():
            widget.destroy()
        
        ttk.Label(self.wizard_content, text="Review and Create User", font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create review frame
        review_frame = ttk.Frame(self.wizard_content)
        review_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Display configuration summary
        ttk.Label(review_frame, text="User Configuration", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        username = self.wizard_data["username"].get()
        console_access = self.wizard_data["console_access"].get()
        
        ttk.Label(review_frame, text=f"Username: {username}").pack(anchor=tk.W, pady=2)
        ttk.Label(review_frame, text=f"Console Access: {'Enabled' if console_access else 'Disabled'}").pack(anchor=tk.W, pady=2)
        
        if console_access:
            password_type = self.wizard_data["password_type"].get()
            force_change = self.wizard_data["force_change"].get()
            ttk.Label(review_frame, text=f"Password: {'Auto-generated' if password_type == 'auto' else 'Custom'}").pack(anchor=tk.W, pady=2)
            ttk.Label(review_frame, text=f"Force Password Change: {'Yes' if force_change else 'No'}").pack(anchor=tk.W, pady=2)
        
        # Display permissions
        ttk.Label(review_frame, text="\nPermissions", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        perm_type = self.wizard_data["permission_type"].get()
        ttk.Label(review_frame, text=f"Type: {'AWS Managed Policies' if perm_type == 'managed' else 'Custom Policy'}").pack(anchor=tk.W, pady=2)
        
        if perm_type == "managed":
            ttk.Label(review_frame, text="Selected Policies:").pack(anchor=tk.W, pady=2)
            for policy, var in self.wizard_data["managed_policies"].items():
                if var.get():
                    ttk.Label(review_frame, text=f"- {policy}").pack(anchor=tk.W, padx=10, pady=1)
        
        # Display access key choice
        create_keys = self.wizard_data["create_access_keys"].get()
        ttk.Label(review_frame, text=f"\nCreate Access Keys: {'Yes' if create_keys else 'No'}").pack(anchor=tk.W, pady=5)
        
        # Add confirmation checkbox
        self.confirm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            review_frame,
            text="I confirm the user configuration",
            variable=self.confirm_var,
            command=self.update_create_button
        ).pack(pady=10)
        
        # Add create button
        self.create_button = ttk.Button(
            review_frame,
            text="Create User",
            command=self.create_iam_user,
            state=tk.DISABLED
        )
        self.create_button.pack(pady=5)
    
    def update_create_button(self):
        if self.confirm_var.get():
            self.create_button.config(state=tk.NORMAL)
        else:
            self.create_button.config(state=tk.DISABLED)
    
    def create_iam_user(self):
        try:
            username = self.wizard_data["username"].get()
            
            # Create user
            success, user_data = run_aws_command([
                'iam', 'create-user',
                '--user-name', username
            ])
            
            if not success:
                raise Exception("Failed to create user")
            
            # Set up console access if enabled
            if self.wizard_data["console_access"].get():
                password = self.wizard_data["custom_password"].get() if self.wizard_data["password_type"].get() == "custom" else None
                force_change = self.wizard_data["force_change"].get()
                
                success, login_data = run_aws_command([
                    'iam', 'create-login-profile',
                    '--user-name', username,
                    '--password', password if password else 'Auto-generated-password-123!',
                    '--password-reset-required' if force_change else ''
                ])
                
                if not success:
                    raise Exception("Failed to create login profile")
            
            # Attach policies
            if self.wizard_data["permission_type"].get() == "managed":
                for policy, var in self.wizard_data["managed_policies"].items():
                    if var.get():
                        success, _ = run_aws_command([
                            'iam', 'attach-user-policy',
                            '--user-name', username,
                            '--policy-arn', f'arn:aws:iam::aws:policy/{policy}'
                        ])
                        
                        if not success:
                            raise Exception(f"Failed to attach policy: {policy}")
            else:
                # Create custom policy
                policy_name = f"{username}-custom-policy"
                success, _ = run_aws_command([
                    'iam', 'create-policy',
                    '--policy-name', policy_name,
                    '--policy-document', self.wizard_data["custom_policy"].get("1.0", tk.END)
                ])
                
                if not success:
                    raise Exception("Failed to create custom policy")
            
            # Create access keys if requested
            if self.wizard_data["create_access_keys"].get():
                success, keys_data = run_aws_command([
                    'iam', 'create-access-key',
                    '--user-name', username
                ])
                
                if not success:
                    raise Exception("Failed to create access keys")
                    
                # Store the access key data for display in the review step
                self.wizard_data["access_keys"] = keys_data.get("AccessKey", {})
                
            # If everything succeeded, move to the next step
            self.next_step()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create IAM user: {str(e)}")
            return