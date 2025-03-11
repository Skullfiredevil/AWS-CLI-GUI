import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import os

class EC2Service:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Create the main layout
        self.create_widgets()
        
        # Initialize variables
        self.instances = []
        self.selected_instance = None
    
    def create_widgets(self):
        # Create a frame for instance list
        instance_frame = ttk.LabelFrame(self.frame, text="EC2 Instances")
        instance_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a frame for instance operations
        instance_ops_frame = ttk.Frame(instance_frame)
        instance_ops_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add buttons for instance operations
        ttk.Button(instance_ops_frame, text="List Instances", command=self.list_instances).pack(side=tk.LEFT, padx=2)
        ttk.Button(instance_ops_frame, text="Create Instance", command=self.create_instance).pack(side=tk.LEFT, padx=2)
        ttk.Button(instance_ops_frame, text="Refresh", command=self.list_instances).pack(side=tk.LEFT, padx=2)
        
        # Create a treeview for instances
        self.instance_tree = ttk.Treeview(instance_frame, columns=("ID", "Type", "State", "Public IP"))
        self.instance_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure treeview columns
        self.instance_tree.heading("#0", text="Name")
        self.instance_tree.heading("ID", text="Instance ID")
        self.instance_tree.heading("Type", text="Instance Type")
        self.instance_tree.heading("State", text="State")
        self.instance_tree.heading("Public IP", text="Public IP")
        self.instance_tree.column("#0", width=150)
        self.instance_tree.column("ID", width=120)
        self.instance_tree.column("Type", width=100)
        self.instance_tree.column("State", width=80)
        self.instance_tree.column("Public IP", width=120)
        
        # Bind selection event
        self.instance_tree.bind("<<TreeviewSelect>>", self.on_instance_select)
        
        # Create a frame for instance details
        details_frame = ttk.LabelFrame(self.frame, text="Instance Details")
        details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a frame for instance actions
        action_frame = ttk.Frame(details_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add buttons for instance actions
        self.start_button = ttk.Button(action_frame, text="Start", command=self.start_instance, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, padx=2)
        
        self.stop_button = ttk.Button(action_frame, text="Stop", command=self.stop_instance, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=2)
        
        self.terminate_button = ttk.Button(action_frame, text="Terminate", command=self.terminate_instance, state=tk.DISABLED)
        self.terminate_button.pack(side=tk.LEFT, padx=2)
        
        # Create a text widget for instance details
        self.details_text = tk.Text(details_frame, wrap=tk.WORD, height=20, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.details_text.config(state=tk.DISABLED)
    
    def list_instances(self):
        try:
            # Run AWS CLI command to list instances
            result = subprocess.run(
                ["aws", "ec2", "describe-instances"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list instances: {result.stderr}")
                return
            
            # Parse the JSON output
            data = json.loads(result.stdout)
            
            # Clear the treeview
            for item in self.instance_tree.get_children():
                self.instance_tree.delete(item)
            
            # Reset instance list
            self.instances = []
            
            # Process the instances
            for reservation in data.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    # Store the instance data
                    self.instances.append(instance)
                    
                    # Get instance properties
                    instance_id = instance.get("InstanceId", "")
                    instance_type = instance.get("InstanceType", "")
                    state = instance.get("State", {}).get("Name", "")
                    public_ip = instance.get("PublicIpAddress", "N/A")
                    
                    # Get instance name from tags
                    name = "Unnamed"
                    for tag in instance.get("Tags", []):
                        if tag.get("Key") == "Name":
                            name = tag.get("Value")
                            break
                    
                    # Add to treeview
                    self.instance_tree.insert("", "end", text=name, values=(instance_id, instance_type, state, public_ip))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list instances: {e}")
    
    def on_instance_select(self, event):
        # Get the selected item
        selection = self.instance_tree.selection()
        if not selection:
            return
        
        # Get the instance ID
        item_id = selection[0]
        instance_id = self.instance_tree.item(item_id, "values")[0]
        
        # Find the instance data
        for instance in self.instances:
            if instance.get("InstanceId") == instance_id:
                self.selected_instance = instance
                break
        
        # Update the details text
        self.update_instance_details()
        
        # Update button states based on instance state
        state = self.selected_instance.get("State", {}).get("Name", "")
        
        if state == "running":
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.terminate_button.config(state=tk.NORMAL)
        elif state == "stopped":
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.terminate_button.config(state=tk.NORMAL)
        elif state == "pending" or state == "stopping":
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.DISABLED)
            self.terminate_button.config(state=tk.DISABLED)
        else:
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.NORMAL)
            self.terminate_button.config(state=tk.NORMAL)
    
    def update_instance_details(self):
        if not self.selected_instance:
            return
        
        # Enable text widget for editing
        self.details_text.config(state=tk.NORMAL)
        
        # Clear the text widget
        self.details_text.delete(1.0, tk.END)
        
        # Format the instance details
        details = f"Instance ID: {self.selected_instance.get('InstanceId', 'N/A')}\n"
        details += f"Instance Type: {self.selected_instance.get('InstanceType', 'N/A')}\n"
        details += f"State: {self.selected_instance.get('State', {}).get('Name', 'N/A')}\n"
        details += f"Public IP: {self.selected_instance.get('PublicIpAddress', 'N/A')}\n"
        details += f"Private IP: {self.selected_instance.get('PrivateIpAddress', 'N/A')}\n"
        details += f"VPC ID: {self.selected_instance.get('VpcId', 'N/A')}\n"
        details += f"Subnet ID: {self.selected_instance.get('SubnetId', 'N/A')}\n"
        details += f"AMI ID: {self.selected_instance.get('ImageId', 'N/A')}\n"
        details += f"Launch Time: {self.selected_instance.get('LaunchTime', 'N/A')}\n\n"
        
        # Add security groups
        details += "Security Groups:\n"
        for sg in self.selected_instance.get("SecurityGroups", []):
            details += f"  - {sg.get('GroupName', 'N/A')} ({sg.get('GroupId', 'N/A')})\n"
        
        # Add tags
        details += "\nTags:\n"
        for tag in self.selected_instance.get("Tags", []):
            details += f"  - {tag.get('Key', 'N/A')}: {tag.get('Value', 'N/A')}\n"
        
        # Insert the details
        self.details_text.insert(tk.END, details)
        
        # Disable text widget
        self.details_text.config(state=tk.DISABLED)
    
    def create_instance(self):
        # Open a dialog to get instance details
        dialog = tk.Toplevel(self.parent)
        dialog.title("Create EC2 Instance")
        dialog.geometry("500x400")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        # Create a notebook for different sections
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Basic settings tab
        basic_frame = ttk.Frame(notebook)
        notebook.add(basic_frame, text="Basic Settings")
        
        ttk.Label(basic_frame, text="AMI ID:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ami_entry = ttk.Entry(basic_frame, width=30)
        ami_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ami_entry.insert(0, "ami-0c55b159cbfafe1f0")  # Default Amazon Linux 2 AMI
        
        ttk.Label(basic_frame, text="Instance Type:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        instance_type_combo = ttk.Combobox(basic_frame, width=30)
        instance_type_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        instance_type_combo['values'] = ('t2.micro', 't2.small', 't2.medium', 't3.micro', 't3.small', 't3.medium')
        instance_type_combo.current(0)  # Default to t2.micro
        
        ttk.Label(basic_frame, text="Key Pair:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        key_pair_entry = ttk.Entry(basic_frame, width=30)
        key_pair_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(basic_frame, text="Instance Name:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        name_entry = ttk.Entry(basic_frame, width=30)
        name_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        name_entry.insert(0, "My EC2 Instance")
        
        # Network settings tab
        network_frame = ttk.Frame(notebook)
        notebook.add(network_frame, text="Network Settings")
        
        ttk.Label(network_frame, text="VPC:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        vpc_entry = ttk.Entry(network_frame, width=30)
        vpc_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(network_frame, text="Subnet:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        subnet_entry = ttk.Entry(network_frame, width=30)
        subnet_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(network_frame, text="Security Group:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        sg_entry = ttk.Entry(network_frame, width=30)
        sg_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Storage settings tab
        storage_frame = ttk.Frame(notebook)
        notebook.add(storage_frame, text="Storage Settings")
        
        ttk.Label(storage_frame, text="Volume Size (GB):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        volume_size_entry = ttk.Entry(storage_frame, width=10)
        volume_size_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        volume_size_entry.insert(0, "8")
        
        ttk.Label(storage_frame, text="Volume Type:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        volume_type_combo = ttk.Combobox(storage_frame, width=15)
        volume_type_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        volume_type_combo['values'] = ('gp2', 'gp3', 'io1', 'st1', 'sc1', 'standard')
        volume_type_combo.current(0)  # Default to gp2
        
        # Add buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Launch", command=lambda: self.launch_instance(
            ami_entry.get(),
            instance_type_combo.get(),
            key_pair_entry.get(),
            name_entry.get(),
            vpc_entry.get(),
            subnet_entry.get(),
            sg_entry.get(),
            volume_size_entry.get(),
            volume_type_combo.get(),
            dialog
        )).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
    
    def launch_instance(self, ami_id, instance_type, key_pair, name, vpc_id, subnet_id, security_group, volume_size, volume_type, dialog):
        # Validate inputs
        if not ami_id:
            messagebox.showerror("Error", "AMI ID is required")
            return
        
        if not instance_type:
            messagebox.showerror("Error", "Instance type is required")
            return
        
        try:
            # Prepare command
            cmd = ["aws", "ec2", "run-instances", "--image-id", ami_id, "--instance-type", instance_type]
            
            # Add key pair if provided
            if key_pair:
                cmd.extend(["--key-name", key_pair])
            
            # Add network settings if provided
            if subnet_id:
                cmd.extend(["--subnet-id", subnet_id])
            
            if security_group:
                cmd.extend(["--security-group-ids", security_group])
            
            # Add block device mapping for volume size and type
            if volume_size:
                block_device_mapping = f"[{{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{{\"VolumeSize\":{volume_size},\"VolumeType\":\"{volume_type or 'gp2'}\"}}}}]"
                cmd.extend(["--block-device-mappings", block_device_mapping])
            
            # Add tags if name is provided
            if name:
                tags = f"[{{\"Key\":\"Name\",\"Value\":\"{name}\"}}]"
                cmd.extend(["--tag-specifications", f"ResourceType=instance,Tags={tags}"])
            
            # Show progress dialog
            progress_window = tk.Toplevel(self.parent)
            progress_window.title("Launching Instance")
            progress_window.geometry("300x100")
            progress_window.transient(self.parent)
            progress_window.grab_set()
            
            ttk.Label(progress_window, text="Launching EC2 instance...").pack(pady=5)
            progress_bar = ttk.Progressbar(progress_window, mode="indeterminate")
            progress_bar.pack(fill=tk.X, padx=10, pady=10)
            progress_bar.start()
            
            # Update the UI
            progress_window.update()
            
            # Run the command
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Close the progress dialog
            progress_window.destroy()
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to launch instance: {result.stderr}")
            else:
                # Parse the response
                response = json.loads(result.stdout)
                instance_id = response.get("Instances", [{}])[0].get("InstanceId", "")
                
                if instance_id:
                    messagebox.showinfo("Success", f"Instance '{instance_id}' launched successfully")
                    dialog.destroy()
                    self.list_instances()
                else:
                    messagebox.showerror("Error", "Failed to get instance ID from response")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch instance: {e}")
    
    def start_instance(self):
        if not self.selected_instance:
            return
        
        instance_id = self.selected_instance.get("InstanceId")
        
        try:
            # Run AWS CLI command to start instance
            result = subprocess.run(
                ["aws", "ec2", "start-instances", "--instance-ids", instance_id],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to start instance: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Instance '{instance_id}' is starting")
                self.list_instances()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start instance: {e}")
    
    def stop_instance(self):
        if not self.selected_instance:
            return
        
        instance_id = self.selected_instance.get("InstanceId")
        
        # Confirm stop
        if not messagebox.askyesno("Confirm", f"Are you sure you want to stop instance '{instance_id}'?"):
            return
        
        try:
            # Run AWS CLI command to stop instance
            result = subprocess.run(
                ["aws", "ec2", "stop-instances", "--instance-ids", instance_id],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to stop instance: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Instance '{instance_id}' is stopping")
                self.list_instances()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop instance: {e}")
    
    def terminate_instance(self):
        if not self.selected_instance:
            return
        
        instance_id = self.selected_instance.get("InstanceId")
        
        # Confirm termination
        if not messagebox.askyesno("Confirm", f"Are you sure you want to terminate instance '{instance_id}'?\n\nWARNING: This action cannot be undone!"):
            return
        
        try:
            # Run AWS CLI command to terminate instance
            result = subprocess.run(
                ["aws", "ec2", "terminate-instances", "--instance-ids", instance_id],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to terminate instance: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Instance '{instance_id}' is terminating")
                self.list_instances()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to terminate instance: {e}")