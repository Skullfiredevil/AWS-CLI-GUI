import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import os

class IAMService:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        
        # Create the main layout
        self.create_widgets()
        
        # Initialize variables
        self.users = []
        self.roles = []
        self.policies = []
        self.selected_user = None
        self.selected_role = None
        self.selected_policy = None
    
    def create_widgets(self):
        # Create a notebook for IAM resources
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs for different IAM resources
        self.create_users_tab()
        self.create_roles_tab()
        self.create_policies_tab()
    
    def create_users_tab(self):
        # Create a frame for the Users tab
        users_frame = ttk.Frame(self.notebook)
        self.notebook.add(users_frame, text="Users")
        
        # Split the frame into two parts
        users_list_frame = ttk.LabelFrame(users_frame, text="IAM Users")
        users_list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        user_details_frame = ttk.LabelFrame(users_frame, text="User Details")
        user_details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add buttons for user operations
        user_ops_frame = ttk.Frame(users_list_frame)
        user_ops_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(user_ops_frame, text="List Users", command=self.list_users).pack(side=tk.LEFT, padx=2)
        ttk.Button(user_ops_frame, text="Create User", command=self.create_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(user_ops_frame, text="Delete User", command=self.delete_user).pack(side=tk.LEFT, padx=2)
        
        # Create a treeview for users
        self.users_tree = ttk.Treeview(users_list_frame, columns=("ARN", "Created"))
        self.users_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure treeview columns
        self.users_tree.heading("#0", text="User Name")
        self.users_tree.heading("ARN", text="ARN")
        self.users_tree.heading("Created", text="Created")
        self.users_tree.column("#0", width=150)
        self.users_tree.column("ARN", width=300)
        self.users_tree.column("Created", width=150)
        
        # Bind selection event
        self.users_tree.bind("<<TreeviewSelect>>", self.on_user_select)
        
        # Add buttons for user actions
        user_action_frame = ttk.Frame(user_details_frame)
        user_action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.create_access_key_button = ttk.Button(user_action_frame, text="Create Access Key", command=self.create_access_key, state=tk.DISABLED)
        self.create_access_key_button.pack(side=tk.LEFT, padx=2)
        
        self.attach_policy_button = ttk.Button(user_action_frame, text="Attach Policy", command=self.attach_user_policy, state=tk.DISABLED)
        self.attach_policy_button.pack(side=tk.LEFT, padx=2)
        
        # Create a text widget for user details
        self.user_details_text = tk.Text(user_details_frame, wrap=tk.WORD, height=20, width=50)
        self.user_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.user_details_text.config(state=tk.DISABLED)
    
    def create_roles_tab(self):
        # Create a frame for the Roles tab
        roles_frame = ttk.Frame(self.notebook)
        self.notebook.add(roles_frame, text="Roles")
        
        # Split the frame into two parts
        roles_list_frame = ttk.LabelFrame(roles_frame, text="IAM Roles")
        roles_list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        role_details_frame = ttk.LabelFrame(roles_frame, text="Role Details")
        role_details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add buttons for role operations
        role_ops_frame = ttk.Frame(roles_list_frame)
        role_ops_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(role_ops_frame, text="List Roles", command=self.list_roles).pack(side=tk.LEFT, padx=2)
        ttk.Button(role_ops_frame, text="Create Role", command=self.create_role).pack(side=tk.LEFT, padx=2)
        ttk.Button(role_ops_frame, text="Delete Role", command=self.delete_role).pack(side=tk.LEFT, padx=2)
        
        # Create a treeview for roles
        self.roles_tree = ttk.Treeview(roles_list_frame, columns=("ARN", "Created"))
        self.roles_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure treeview columns
        self.roles_tree.heading("#0", text="Role Name")
        self.roles_tree.heading("ARN", text="ARN")
        self.roles_tree.heading("Created", text="Created")
        self.roles_tree.column("#0", width=150)
        self.roles_tree.column("ARN", width=300)
        self.roles_tree.column("Created", width=150)
        
        # Bind selection event
        self.roles_tree.bind("<<TreeviewSelect>>", self.on_role_select)
        
        # Add buttons for role actions
        role_action_frame = ttk.Frame(role_details_frame)
        role_action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.attach_role_policy_button = ttk.Button(role_action_frame, text="Attach Policy", command=self.attach_role_policy, state=tk.DISABLED)
        self.attach_role_policy_button.pack(side=tk.LEFT, padx=2)
        
        # Create a text widget for role details
        self.role_details_text = tk.Text(role_details_frame, wrap=tk.WORD, height=20, width=50)
        self.role_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.role_details_text.config(state=tk.DISABLED)
    
    def create_policies_tab(self):
        # Create a frame for the Policies tab
        policies_frame = ttk.Frame(self.notebook)
        self.notebook.add(policies_frame, text="Policies")
        
        # Split the frame into two parts
        policies_list_frame = ttk.LabelFrame(policies_frame, text="IAM Policies")
        policies_list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        policy_details_frame = ttk.LabelFrame(policies_frame, text="Policy Details")
        policy_details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add buttons for policy operations
        policy_ops_frame = ttk.Frame(policies_list_frame)
        policy_ops_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(policy_ops_frame, text="List Policies", command=self.list_policies).pack(side=tk.LEFT, padx=2)
        ttk.Button(policy_ops_frame, text="Create Policy", command=self.create_policy).pack(side=tk.LEFT, padx=2)
        ttk.Button(policy_ops_frame, text="Delete Policy", command=self.delete_policy).pack(side=tk.LEFT, padx=2)
        
        # Create a treeview for policies
        self.policies_tree = ttk.Treeview(policies_list_frame, columns=("ARN", "Type"))
        self.policies_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure treeview columns
        self.policies_tree.heading("#0", text="Policy Name")
        self.policies_tree.heading("ARN", text="ARN")
        self.policies_tree.heading("Type", text="Type")
        self.policies_tree.column("#0", width=200)
        self.policies_tree.column("ARN", width=300)
        self.policies_tree.column("Type", width=100)
        
        # Bind selection event
        self.policies_tree.bind("<<TreeviewSelect>>", self.on_policy_select)
        
        # Create a text widget for policy details
        self.policy_details_text = tk.Text(policy_details_frame, wrap=tk.WORD, height=20, width=50)
        self.policy_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.policy_details_text.config(state=tk.DISABLED)
    
    # User operations
    def list_users(self):
        try:
            # Run AWS CLI command to list users
            result = subprocess.run(
                ["aws", "iam", "list-users"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list users: {result.stderr}")
                return
            
            # Parse the JSON output
            data = json.loads(result.stdout)
            
            # Clear the treeview
            for item in self.users_tree.get_children():
                self.users_tree.delete(item)
            
            # Reset users list
            self.users = []
            
            # Process the users
            for user in data.get("Users", []):
                # Store the user data
                self.users.append(user)
                
                # Get user properties
                user_name = user.get("UserName", "")
                arn = user.get("Arn", "")
                created = user.get("CreateDate", "")[:10]  # Just the date part
                
                # Add to treeview
                self.users_tree.insert("", "end", text=user_name, values=(arn, created))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list users: {e}")
    
    def on_user_select(self, event):
        # Get the selected item
        selection = self.users_tree.selection()
        if not selection:
            return
        
        # Get the user name
        item_id = selection[0]
        user_name = self.users_tree.item(item_id, "text")
        
        # Find the user data
        for user in self.users:
            if user.get("UserName") == user_name:
                self.selected_user = user
                break
        
        # Update the details text
        self.update_user_details()
        
        # Enable action buttons
        self.create_access_key_button.config(state=tk.NORMAL)
        self.attach_policy_button.config(state=tk.NORMAL)
    
    def update_user_details(self):
        if not self.selected_user:
            return
        
        # Enable text widget for editing
        self.user_details_text.config(state=tk.NORMAL)
        
        # Clear the text widget
        self.user_details_text.delete(1.0, tk.END)
        
        # Get user name
        user_name = self.selected_user.get("UserName", "")
        
        try:
            # Get user details
            result = subprocess.run(
                ["aws", "iam", "get-user", "--user-name", user_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.user_details_text.insert(tk.END, f"Error getting user details: {result.stderr}")
                self.user_details_text.config(state=tk.DISABLED)
                return
            
            user_data = json.loads(result.stdout).get("User", {})
            
            # Format the user details
            details = f"User Name: {user_data.get('UserName', 'N/A')}\n"
            details += f"ARN: {user_data.get('Arn', 'N/A')}\n"
            details += f"User ID: {user_data.get('UserId', 'N/A')}\n"
            details += f"Created: {user_data.get('CreateDate', 'N/A')}\n\n"
            
            # Get attached policies
            result = subprocess.run(
                ["aws", "iam", "list-attached-user-policies", "--user-name", user_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                policies_data = json.loads(result.stdout).get("AttachedPolicies", [])
                details += "Attached Policies:\n"
                
                if policies_data:
                    for policy in policies_data:
                        details += f"  - {policy.get('PolicyName', 'N/A')}\n"
                else:
                    details += "  No policies attached\n"
            else:
                details += "  Error getting attached policies\n"
            
            # Insert the details
            self.user_details_text.insert(tk.END, details)
        except Exception as e:
            self.user_details_text.insert(tk.END, f"Error: {e}")
        
        # Disable text widget
        self.user_details_text.config(state=tk.DISABLED)
    
    def create_user(self):
        # Open a dialog to get user details
        dialog = tk.Toplevel(self.parent)
        dialog.title("Create IAM User")
        dialog.geometry("400x200")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="User Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        user_name_entry = ttk.Entry(dialog, width=30)
        user_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        def on_create():
            user_name = user_name_entry.get().strip()
            
            if not user_name:
                messagebox.showerror("Error", "User name cannot be empty")
                return
            
            try:
                # Run AWS CLI command to create user
                result = subprocess.run(
                    ["aws", "iam", "create-user", "--user-name", user_name],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to create user: {result.stderr}")
                else:
                    messagebox.showinfo("Success", f"User '{user_name}' created successfully")
                    dialog.destroy()
                    self.list_users()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create user: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Create", command=on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_user(self):
        # Get the selected user
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user to delete")
            return
        
        item_id = selection[0]
        user_name = self.users_tree.item(item_id, "text")
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete user '{user_name}'?"):
            return
        
        try:
            # First, detach all policies
            result = subprocess.run(
                ["aws", "iam", "list-attached-user-policies", "--user-name", user_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                policies_data = json.loads(result.stdout).get("AttachedPolicies", [])
                
                for policy in policies_data:
                    policy_arn = policy.get("PolicyArn")
                    subprocess.run(
                        ["aws", "iam", "detach-user-policy", "--user-name", user_name, "--policy-arn", policy_arn],
                        capture_output=True,
                        text=True
                    )
            
            # Delete access keys
            result = subprocess.run(
                ["aws", "iam", "list-access-keys", "--user-name", user_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                keys_data = json.loads(result.stdout).get("AccessKeyMetadata", [])
                
                for key in keys_data:
                    access_key_id = key.get("AccessKeyId")
                    subprocess.run(
                        ["aws", "iam", "delete-access-key", "--user-name", user_name, "--access-key-id", access_key_id],
                        capture_output=True,
                        text=True
                    )
            
            # Finally, delete the user
            result = subprocess.run(
                ["aws", "iam", "delete-user", "--user-name", user_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to delete user: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"User '{user_name}' deleted successfully")
                self.list_users()
                
                # Clear the details text
                self.user_details_text.config(state=tk.NORMAL)
                self.user_details_text.delete(1.0, tk.END)
                self.user_details_text.config(state=tk.DISABLED)
                
                # Disable action buttons
                self.create_access_key_button.config(state=tk.DISABLED)
                self.attach_policy_button.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete user: {e}")
    
    def create_access_key(self):
        if not self.selected_user:
            messagebox.showwarning("Warning", "Please select a user first")
            return
        
        user_name = self.selected_user.get("UserName")
        
        try:
            # Run AWS CLI command to create access key
            result = subprocess.run(
                ["aws", "iam", "create-access-key", "--user-name", user_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to create access key: {result.stderr}")
                return
            
            # Parse the JSON output
            data = json.loads(result.stdout).get("AccessKey", {})
            
            # Show the access key details
            access_key_id = data.get("AccessKeyId", "")
            secret_access_key = data.get("SecretAccessKey", "")
            
            # Create a dialog to display the keys
            dialog = tk.Toplevel(self.parent)
            dialog.title("Access Key Created")
            dialog.geometry("500x200")
            dialog.transient(self.parent)
            dialog.grab_set()
            
            ttk.Label(dialog, text="Access Key ID:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
            id_entry = ttk.Entry(dialog, width=40)
            id_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
            id_entry.insert(0, access_key_id)
            id_entry.config(state="readonly")
            
            ttk.Label(dialog, text="Secret Access Key:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
            secret_entry = ttk.Entry(dialog, width=40)
            secret_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
            secret_entry.insert(0, secret_access_key)
            secret_entry.config(state="readonly")
            
            ttk.Label(dialog, text="IMPORTANT: This is the only time the secret key will be available.").grid(row=2, column=0, columnspan=2, padx=5, pady=5)
            
            button_frame = ttk.Frame(dialog)
            button_frame.grid(row=3, column=0, columnspan=2, pady=10)
            
            def copy_to_clipboard(text):
                dialog.clipboard_clear()
                dialog.clipboard_append(text)
                messagebox.showinfo("Copied", "Copied to clipboard")
            
            ttk.Button(button_frame, text="Copy Access Key ID", command=lambda: copy_to_clipboard(access_key_id)).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Copy Secret Key", command=lambda: copy_to_clipboard(secret_access_key)).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
            
            # Update the user details
            self.update_user_details()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create access key: {e}")
    
    def attach_policy(self):
        if not self.selected_user:
            messagebox.showwarning("Warning", "Please select a user first")
            return
        
        # Create a dialog to select policies
        dialog = tk.Toplevel(self.parent)
        dialog.title("Attach Policy")
        dialog.geometry("500x400")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        # Function to handle policy attachment
        def on_attach():
            # Implementation for attaching policy
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Attach", command=on_attach).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    # Role operations
    def list_roles(self):
        try:
            # Run AWS CLI command to list roles
            result = subprocess.run(
                ["aws", "iam", "list-roles"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list roles: {result.stderr}")
                return
            
            # Parse the JSON output
            data = json.loads(result.stdout)
            
            # Clear the treeview
            for item in self.roles_tree.get_children():
                self.roles_tree.delete(item)
            
            # Reset roles list
            self.roles = []
            
            # Process the roles
            for role in data.get("Roles", []):
                # Store the role data
                self.roles.append(role)
                
                # Get role properties
                role_name = role.get("RoleName", "")
                arn = role.get("Arn", "")
                created = role.get("CreateDate", "")[:10]  # Just the date part
                
                # Add to treeview
                self.roles_tree.insert("", "end", text=role_name, values=(arn, created))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list roles: {e}")
    
    def on_role_select(self, event):
        # Get the selected item
        selection = self.roles_tree.selection()
        if not selection:
            return
        
        # Get the role name
        item_id = selection[0]
        role_name = self.roles_tree.item(item_id, "text")
        
        # Find the role data
        for role in self.roles:
            if role.get("RoleName") == role_name:
                self.selected_role = role
                break
        
        # Update the details text
        self.update_role_details()
        
        # Enable action buttons
        self.attach_role_policy_button.config(state=tk.NORMAL)
    
    def update_role_details(self):
        if not self.selected_role:
            return
        
        # Enable text widget for editing
        self.role_details_text.config(state=tk.NORMAL)
        
        # Clear the text widget
        self.role_details_text.delete(1.0, tk.END)
        
        # Get role name
        role_name = self.selected_role.get("RoleName", "")
        
        try:
            # Get role details
            result = subprocess.run(
                ["aws", "iam", "get-role", "--role-name", role_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.role_details_text.insert(tk.END, f"Error getting role details: {result.stderr}")
                self.role_details_text.config(state=tk.DISABLED)
                return
            
            role_data = json.loads(result.stdout).get("Role", {})
            
            # Format the role details
            details = f"Role Name: {role_data.get('RoleName', 'N/A')}\n"
            details += f"ARN: {role_data.get('Arn', 'N/A')}\n"
            details += f"Role ID: {role_data.get('RoleId', 'N/A')}\n"
            details += f"Created: {role_data.get('CreateDate', 'N/A')}\n\n"
            
            # Get attached policies
            result = subprocess.run(
                ["aws", "iam", "list-attached-role-policies", "--role-name", role_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                policies_data = json.loads(result.stdout).get("AttachedPolicies", [])
                details += "Attached Policies:\n"
                
                if policies_data:
                    for policy in policies_data:
                        details += f"  - {policy.get('PolicyName', 'N/A')}\n"
                else:
                    details += "  No policies attached\n"
            else:
                details += "  Error getting attached policies\n"
            
            # Insert the details
            self.role_details_text.insert(tk.END, details)
        except Exception as e:
            self.role_details_text.insert(tk.END, f"Error: {e}")
        
        # Disable text widget
        self.role_details_text.config(state=tk.DISABLED)
    
    def create_role(self):
        # Open a dialog to get role details
        dialog = tk.Toplevel(self.parent)
        dialog.title("Create IAM Role")
        dialog.geometry("500x300")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Role Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        role_name_entry = ttk.Entry(dialog, width=30)
        role_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Description:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        description_entry = ttk.Entry(dialog, width=30)
        description_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Trust Policy:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.NW)
        trust_policy_text = tk.Text(dialog, width=40, height=10)
        trust_policy_text.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        trust_policy_text.insert(tk.END, '''{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {\n        "Service": "ec2.amazonaws.com"\n      },\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}''')
        
        def on_create():
            role_name = role_name_entry.get().strip()
            description = description_entry.get().strip()
            trust_policy = trust_policy_text.get(1.0, tk.END).strip()
            
            if not role_name:
                messagebox.showerror("Error", "Role name cannot be empty")
                return
            
            try:
                # Run AWS CLI command to create role
                result = subprocess.run(
                    ["aws", "iam", "create-role", "--role-name", role_name, "--description", description, "--assume-role-policy-document", trust_policy],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to create role: {result.stderr}")
                else:
                    messagebox.showinfo("Success", f"Role '{role_name}' created successfully")
                    dialog.destroy()
                    self.list_roles()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create role: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Create", command=on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_role(self):
        # Get the selected role
        selection = self.roles_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a role to delete")
            return
        
        item_id = selection[0]
        role_name = self.roles_tree.item(item_id, "text")
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete role '{role_name}'?"):
            return
        
        try:
            # First, detach all policies
            result = subprocess.run(
                ["aws", "iam", "list-attached-role-policies", "--role-name", role_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                policies_data = json.loads(result.stdout).get("AttachedPolicies", [])
                
                for policy in policies_data:
                    policy_arn = policy.get("PolicyArn")
                    subprocess.run(
                        ["aws", "iam", "detach-role-policy", "--role-name", role_name, "--policy-arn", policy_arn],
                        capture_output=True,
                        text=True
                    )
            
            # Delete the role
            result = subprocess.run(
                ["aws", "iam", "delete-role", "--role-name", role_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to delete role: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Role '{role_name}' deleted successfully")
                self.list_roles()
                
                # Clear the details text
                self.role_details_text.config(state=tk.NORMAL)
                self.role_details_text.delete(1.0, tk.END)
                self.role_details_text.config(state=tk.DISABLED)
                
                # Disable action buttons
                self.attach_role_policy_button.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete role: {e}")
    
    def attach_role_policy(self):
        if not self.selected_role:
            messagebox.showwarning("Warning", "Please select a role first")
            return
        
        role_name = self.selected_role.get("RoleName")
        
        # Create a dialog to select a policy
        dialog = tk.Toplevel(self.parent)
        dialog.title("Attach Policy")
        dialog.geometry("500x400")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Select a policy to attach:").pack(padx=10, pady=10, anchor=tk.W)
        
        # Create a frame for the policy list
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create a treeview for policies
        policy_tree = ttk.Treeview(list_frame, columns=("ARN",))
        policy_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=policy_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        policy_tree.configure(yscrollcommand=scrollbar.set)
        
        # Configure treeview columns
        policy_tree.heading("#0", text="Policy Name")
        policy_tree.heading("ARN", text="ARN")
        policy_tree.column("#0", width=200)
        policy_tree.column("ARN", width=300)
        
        # Load policies
        try:
            result = subprocess.run(
                ["aws", "iam", "list-policies", "--scope", "All"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list policies: {result.stderr}")
            else:
                data = json.loads(result.stdout)
                for policy in data.get("Policies", []):
                    policy_name = policy.get("PolicyName", "")
                    policy_arn = policy.get("Arn", "")
                    policy_tree.insert("", "end", text=policy_name, values=(policy_arn,))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list policies: {e}")
        
        def on_attach():
            selection = policy_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a policy to attach")
                return
            
            item_id = selection[0]
            policy_arn = policy_tree.item(item_id, "values")[0]
            
            try:
                # Run AWS CLI command to attach policy
                result = subprocess.run(
                    ["aws", "iam", "attach-role-policy", "--role-name", role_name, "--policy-arn", policy_arn],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to attach policy: {result.stderr}")
                else:
                    messagebox.showinfo("Success", "Policy attached successfully")
                    dialog.destroy()
                    self.update_role_details()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to attach policy: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Attach", command=on_attach).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    # Policy operations
    def list_policies(self):
        try:
            # Run AWS CLI command to list policies
            result = subprocess.run(
                ["aws", "iam", "list-policies", "--scope", "All"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list policies: {result.stderr}")
                return
            
            # Parse the JSON output
            data = json.loads(result.stdout)
            
            # Clear the treeview
            for item in self.policies_tree.get_children():
                self.policies_tree.delete(item)
            
            # Reset policies list
            self.policies = []
            
            # Process the policies
            for policy in data.get("Policies", []):
                # Store the policy data
                self.policies.append(policy)
                
                # Get policy properties
                policy_name = policy.get("PolicyName", "")
                arn = policy.get("Arn", "")
                policy_type = "AWS Managed" if policy.get("IsAttachable") else "Customer Managed"
                
                # Add to treeview
                self.policies_tree.insert("", "end", text=policy_name, values=(arn, policy_type))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list policies: {e}")
    
    def on_policy_select(self, event):
        # Get the selected item
        selection = self.policies_tree.selection()
        if not selection:
            return
        
        # Get the policy name and ARN
        item_id = selection[0]
        policy_name = self.policies_tree.item(item_id, "text")
        policy_arn = self.policies_tree.item(item_id, "values")[0]
        
        # Find the policy data
        for policy in self.policies:
            if policy.get("PolicyName") == policy_name:
                self.selected_policy = policy
                break
        
        # Update the details text
        self.update_policy_details(policy_arn)
    
    def update_policy_details(self, policy_arn):
        if not policy_arn:
            return
        
        # Enable text widget for editing
        self.policy_details_text.config(state=tk.NORMAL)
        
        # Clear the text widget
        self.policy_details_text.delete(1.0, tk.END)
        
        try:
            # Get policy version
            result = subprocess.run(
                ["aws", "iam", "get-policy", "--policy-arn", policy_arn],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.policy_details_text.insert(tk.END, f"Error getting policy details: {result.stderr}")
                self.policy_details_text.config(state=tk.DISABLED)
                return
            
            policy_data = json.loads(result.stdout).get("Policy", {})
            default_version_id = policy_data.get("DefaultVersionId")
            
            # Get policy document
            result = subprocess.run(
                ["aws", "iam", "get-policy-version", "--policy-arn", policy_arn, "--version-id", default_version_id],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.policy_details_text.insert(tk.END, f"Error getting policy version: {result.stderr}")
                self.policy_details_text.config(state=tk.DISABLED)
                return
            
            version_data = json.loads(result.stdout).get("PolicyVersion", {})
            document = version_data.get("Document", {})
            
            # Format the policy details
            details = f"Policy Name: {policy_data.get('PolicyName', 'N/A')}\n"
            details += f"ARN: {policy_data.get('Arn', 'N/A')}\n"
            details += f"Description: {policy_data.get('Description', 'N/A')}\n"
            details += f"Created: {policy_data.get('CreateDate', 'N/A')}\n\n"
            details += "Policy Document:\n"
            
            # Format the JSON document
            if isinstance(document, dict):
                document_str = json.dumps(document, indent=2)
                details += document_str
            else:
                details += str(document)
            
            # Insert the details
            self.policy_details_text.insert(tk.END, details)
        except Exception as e:
            self.policy_details_text.insert(tk.END, f"Error: {e}")
        
        # Disable text widget
        self.policy_details_text.config(state=tk.DISABLED)
    
    def create_policy(self):
        # Open a dialog to get policy details
        dialog = tk.Toplevel(self.parent)
        dialog.title("Create IAM Policy")
        dialog.geometry("600x500")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Policy Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        policy_name_entry = ttk.Entry(dialog, width=30)
        policy_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Description:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        description_entry = ttk.Entry(dialog, width=30)
        description_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Policy Document:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.NW)
        policy_document_text = tk.Text(dialog, width=50, height=20)
        policy_document_text.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        policy_document_text.insert(tk.END, '''{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": [\n        "s3:ListBucket"\n      ],\n      "Resource": "*"\n    }\n  ]\n}''')
        
        def on_create():
            policy_name = policy_name_entry.get().strip()
            description = description_entry.get().strip()
            policy_document = policy_document_text.get(1.0, tk.END).strip()
            
            if not policy_name:
                messagebox.showerror("Error", "Policy name cannot be empty")
                return
            
            try:
                # Run AWS CLI command to create policy
                result = subprocess.run(
                    ["aws", "iam", "create-policy", "--policy-name", policy_name, "--description", description, "--policy-document", policy_document],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to create policy: {result.stderr}")
                else:
                    messagebox.showinfo("Success", f"Policy '{policy_name}' created successfully")
                    dialog.destroy()
                    self.list_policies()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create policy: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Create", command=on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_policy(self):
        # Get the selected policy
        selection = self.policies_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a policy to delete")
            return
        
        item_id = selection[0]
        policy_name = self.policies_tree.item(item_id, "text")
        policy_arn = self.policies_tree.item(item_id, "values")[0]
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete policy '{policy_name}'?"):
            return
        
        try:
            # Delete the policy
            result = subprocess.run(
                ["aws", "iam", "delete-policy", "--policy-arn", policy_arn],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to delete policy: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Policy '{policy_name}' deleted successfully")
                self.list_policies()
                
                # Clear the details text
                self.policy_details_text.config(state=tk.NORMAL)
                self.policy_details_text.delete(1.0, tk.END)
                self.policy_details_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete policy: {e}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create access key: {e}")
    
    def attach_user_policy(self):
        if not self.selected_user:
            messagebox.showwarning("Warning", "Please select a user first")
            return
        
        user_name = self.selected_user.get("UserName")
        
        # Create a dialog to select a policy
        dialog = tk.Toplevel(self.parent)
        dialog.title("Attach Policy")
        dialog.geometry("500x400")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Select a policy to attach:").pack(padx=10, pady=10, anchor=tk.W)
        
        # Create a frame for the policy list
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create a treeview for policies
        policy_tree = ttk.Treeview(list_frame, columns=("ARN",))
        policy_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=policy_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        policy_tree.configure(yscrollcommand=scrollbar.set)
        
        # Configure treeview columns
        policy_tree.heading("#0", text="Policy Name")
        policy_tree.heading("ARN", text="ARN")
        policy_tree.column("#0", width=200)
        policy_tree.column("ARN", width=300)
        
        # Load policies
        try:
            result = subprocess.run(
                ["aws", "iam", "list-policies", "--scope", "All"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list policies: {result.stderr}")
            else:
                data = json.loads(result.stdout)
                for policy in data.get("Policies", []):
                    policy_name = policy.get("PolicyName", "")
                    policy_arn = policy.get("Arn", "")
                    policy_tree.insert("", "end", text=policy_name, values=(policy_arn,))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list policies: {e}")
        
        def on_attach():
            selection = policy_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a policy to attach")
                return
            
            item_id = selection[0]
            policy_arn = policy_tree.item(item_id, "values")[0]
            
            try:
                # Run AWS CLI command to attach policy
                result = subprocess.run(
                    ["aws", "iam", "attach-user-policy", "--user-name", user_name, "--policy-arn", policy_arn],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to attach policy: {result.stderr}")
                else:
                    messagebox.showinfo("Success", "Policy attached successfully")
                    dialog.destroy()
                    self.update_user_details()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to attach policy: {e}")
                
            # Update the user details
            self.update_user_details()
    
    def attach_policy(self):
        if not self.selected_user:
            messagebox.showwarning("Warning", "Please select a user first")
            return
        
        # Create a dialog to select policies
        dialog = tk.Toplevel(self.parent)
        dialog.title("Attach Policy")
        dialog.geometry("500x400")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        # Function to handle policy attachment
        def on_attach():
            # Implementation for attaching policy
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Attach", command=on_attach).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    # Role operations
    def list_roles(self):
        try:
            # Run AWS CLI command to list roles
            result = subprocess.run(
                ["aws", "iam", "list-roles"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list roles: {result.stderr}")
                return
            
            # Parse the JSON output
            data = json.loads(result.stdout)
            
            # Clear the treeview
            for item in self.roles_tree.get_children():
                self.roles_tree.delete(item)
            
            # Reset roles list
            self.roles = []
            
            # Process the roles
            for role in data.get("Roles", []):
                # Store the role data
                self.roles.append(role)
                
                # Get role properties
                role_name = role.get("RoleName", "")
                arn = role.get("Arn", "")
                created = role.get("CreateDate", "")[:10]  # Just the date part
                
                # Add to treeview
                self.roles_tree.insert("", "end", text=role_name, values=(arn, created))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list roles: {e}")
    
    def on_role_select(self, event):
        # Get the selected item
        selection = self.roles_tree.selection()
        if not selection:
            return
        
        # Get the role name
        item_id = selection[0]
        role_name = self.roles_tree.item(item_id, "text")
        
        # Find the role data
        for role in self.roles:
            if role.get("RoleName") == role_name:
                self.selected_role = role
                break
        
        # Update the details text
        self.update_role_details()
        
        # Enable action buttons
        self.attach_role_policy_button.config(state=tk.NORMAL)
    
    def update_role_details(self):
        if not self.selected_role:
            return
        
        # Enable text widget for editing
        self.role_details_text.config(state=tk.NORMAL)
        
        # Clear the text widget
        self.role_details_text.delete(1.0, tk.END)
        
        # Get role name
        role_name = self.selected_role.get("RoleName", "")
        
        try:
            # Get role details
            result = subprocess.run(
                ["aws", "iam", "get-role", "--role-name", role_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.role_details_text.insert(tk.END, f"Error getting role details: {result.stderr}")
                self.role_details_text.config(state=tk.DISABLED)
                return
            
            role_data = json.loads(result.stdout).get("Role", {})
            
            # Format the role details
            details = f"Role Name: {role_data.get('RoleName', 'N/A')}\n"
            details += f"ARN: {role_data.get('Arn', 'N/A')}\n"
            details += f"Role ID: {role_data.get('RoleId', 'N/A')}\n"
            details += f"Created: {role_data.get('CreateDate', 'N/A')}\n\n"
            
            # Get attached policies
            result = subprocess.run(
                ["aws", "iam", "list-attached-role-policies", "--role-name", role_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                policies_data = json.loads(result.stdout).get("AttachedPolicies", [])
                details += "Attached Policies:\n"
                
                if policies_data:
                    for policy in policies_data:
                        details += f"  - {policy.get('PolicyName', 'N/A')}\n"
                else:
                    details += "  No policies attached\n"
            else:
                details += "  Error getting attached policies\n"
            
            # Insert the details
            self.role_details_text.insert(tk.END, details)
        except Exception as e:
            self.role_details_text.insert(tk.END, f"Error: {e}")
        
        # Disable text widget
        self.role_details_text.config(state=tk.DISABLED)
    
    def create_role(self):
        # Open a dialog to get role details
        dialog = tk.Toplevel(self.parent)
        dialog.title("Create IAM Role")
        dialog.geometry("500x300")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Role Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        role_name_entry = ttk.Entry(dialog, width=30)
        role_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Description:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        description_entry = ttk.Entry(dialog, width=30)
        description_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Trust Policy:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.NW)
        trust_policy_text = tk.Text(dialog, width=40, height=10)
        trust_policy_text.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        trust_policy_text.insert(tk.END, '''{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {\n        "Service": "ec2.amazonaws.com"\n      },\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}''')
        
        def on_create():
            role_name = role_name_entry.get().strip()
            description = description_entry.get().strip()
            trust_policy = trust_policy_text.get(1.0, tk.END).strip()
            
            if not role_name:
                messagebox.showerror("Error", "Role name cannot be empty")
                return
            
            try:
                # Run AWS CLI command to create role
                result = subprocess.run(
                    ["aws", "iam", "create-role", "--role-name", role_name, "--description", description, "--assume-role-policy-document", trust_policy],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to create role: {result.stderr}")
                else:
                    messagebox.showinfo("Success", f"Role '{role_name}' created successfully")
                    dialog.destroy()
                    self.list_roles()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create role: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Create", command=on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_role(self):
        # Get the selected role
        selection = self.roles_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a role to delete")
            return
        
        item_id = selection[0]
        role_name = self.roles_tree.item(item_id, "text")
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete role '{role_name}'?"):
            return
        
        try:
            # First, detach all policies
            result = subprocess.run(
                ["aws", "iam", "list-attached-role-policies", "--role-name", role_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                policies_data = json.loads(result.stdout).get("AttachedPolicies", [])
                
                for policy in policies_data:
                    policy_arn = policy.get("PolicyArn")
                    subprocess.run(
                        ["aws", "iam", "detach-role-policy", "--role-name", role_name, "--policy-arn", policy_arn],
                        capture_output=True,
                        text=True
                    )
            
            # Delete the role
            result = subprocess.run(
                ["aws", "iam", "delete-role", "--role-name", role_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to delete role: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Role '{role_name}' deleted successfully")
                self.list_roles()
                
                # Clear the details text
                self.role_details_text.config(state=tk.NORMAL)
                self.role_details_text.delete(1.0, tk.END)
                self.role_details_text.config(state=tk.DISABLED)
                
                # Disable action buttons
                self.attach_role_policy_button.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete role: {e}")
    
    def attach_role_policy(self):
        if not self.selected_role:
            messagebox.showwarning("Warning", "Please select a role first")
            return
        
        role_name = self.selected_role.get("RoleName")
        
        # Create a dialog to select a policy
        dialog = tk.Toplevel(self.parent)
        dialog.title("Attach Policy")
        dialog.geometry("500x400")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Select a policy to attach:").pack(padx=10, pady=10, anchor=tk.W)
        
        # Create a frame for the policy list
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create a treeview for policies
        policy_tree = ttk.Treeview(list_frame, columns=("ARN",))
        policy_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=policy_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        policy_tree.configure(yscrollcommand=scrollbar.set)
        
        # Configure treeview columns
        policy_tree.heading("#0", text="Policy Name")
        policy_tree.heading("ARN", text="ARN")
        policy_tree.column("#0", width=200)
        policy_tree.column("ARN", width=300)
        
        # Load policies
        try:
            result = subprocess.run(
                ["aws", "iam", "list-policies", "--scope", "All"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list policies: {result.stderr}")
            else:
                data = json.loads(result.stdout)
                for policy in data.get("Policies", []):
                    policy_name = policy.get("PolicyName", "")
                    policy_arn = policy.get("Arn", "")
                    policy_tree.insert("", "end", text=policy_name, values=(policy_arn,))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list policies: {e}")
        
        def on_attach():
            selection = policy_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a policy to attach")
                return
            
            item_id = selection[0]
            policy_arn = policy_tree.item(item_id, "values")[0]
            
            try:
                # Run AWS CLI command to attach policy
                result = subprocess.run(
                    ["aws", "iam", "attach-role-policy", "--role-name", role_name, "--policy-arn", policy_arn],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to attach policy: {result.stderr}")
                else:
                    messagebox.showinfo("Success", "Policy attached successfully")
                    dialog.destroy()
                    self.update_role_details()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to attach policy: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Attach", command=on_attach).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    # Policy operations
    def list_policies(self):
        try:
            # Run AWS CLI command to list policies
            result = subprocess.run(
                ["aws", "iam", "list-policies", "--scope", "All"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to list policies: {result.stderr}")
                return
            
            # Parse the JSON output
            data = json.loads(result.stdout)
            
            # Clear the treeview
            for item in self.policies_tree.get_children():
                self.policies_tree.delete(item)
            
            # Reset policies list
            self.policies = []
            
            # Process the policies
            for policy in data.get("Policies", []):
                # Store the policy data
                self.policies.append(policy)
                
                # Get policy properties
                policy_name = policy.get("PolicyName", "")
                arn = policy.get("Arn", "")
                policy_type = "AWS Managed" if policy.get("IsAttachable") else "Customer Managed"
                
                # Add to treeview
                self.policies_tree.insert("", "end", text=policy_name, values=(arn, policy_type))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list policies: {e}")
    
    def on_policy_select(self, event):
        # Get the selected item
        selection = self.policies_tree.selection()
        if not selection:
            return
        
        # Get the policy name and ARN
        item_id = selection[0]
        policy_name = self.policies_tree.item(item_id, "text")
        policy_arn = self.policies_tree.item(item_id, "values")[0]
        
        # Find the policy data
        for policy in self.policies:
            if policy.get("PolicyName") == policy_name:
                self.selected_policy = policy
                break
        
        # Update the details text
        self.update_policy_details(policy_arn)
    
    def update_policy_details(self, policy_arn):
        if not policy_arn:
            return
        
        # Enable text widget for editing
        self.policy_details_text.config(state=tk.NORMAL)
        
        # Clear the text widget
        self.policy_details_text.delete(1.0, tk.END)
        
        try:
            # Get policy version
            result = subprocess.run(
                ["aws", "iam", "get-policy", "--policy-arn", policy_arn],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.policy_details_text.insert(tk.END, f"Error getting policy details: {result.stderr}")
                self.policy_details_text.config(state=tk.DISABLED)
                return
            
            policy_data = json.loads(result.stdout).get("Policy", {})
            default_version_id = policy_data.get("DefaultVersionId")
            
            # Get policy document
            result = subprocess.run(
                ["aws", "iam", "get-policy-version", "--policy-arn", policy_arn, "--version-id", default_version_id],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.policy_details_text.insert(tk.END, f"Error getting policy version: {result.stderr}")
                self.policy_details_text.config(state=tk.DISABLED)
                return
            
            version_data = json.loads(result.stdout).get("PolicyVersion", {})
            document = version_data.get("Document", {})
            
            # Format the policy details
            details = f"Policy Name: {policy_data.get('PolicyName', 'N/A')}\n"
            details += f"ARN: {policy_data.get('Arn', 'N/A')}\n"
            details += f"Description: {policy_data.get('Description', 'N/A')}\n"
            details += f"Created: {policy_data.get('CreateDate', 'N/A')}\n\n"
            details += "Policy Document:\n"
            
            # Format the JSON document
            if isinstance(document, dict):
                document_str = json.dumps(document, indent=2)
                details += document_str
            else:
                details += str(document)
            
            # Insert the details
            self.policy_details_text.insert(tk.END, details)
        except Exception as e:
            self.policy_details_text.insert(tk.END, f"Error: {e}")
        
        # Disable text widget
        self.policy_details_text.config(state=tk.DISABLED)
    
    def create_policy(self):
        # Open a dialog to get policy details
        dialog = tk.Toplevel(self.parent)
        dialog.title("Create IAM Policy")
        dialog.geometry("600x500")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Policy Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        policy_name_entry = ttk.Entry(dialog, width=30)
        policy_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Description:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        description_entry = ttk.Entry(dialog, width=30)
        description_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(dialog, text="Policy Document:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.NW)
        policy_document_text = tk.Text(dialog, width=50, height=20)
        policy_document_text.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        policy_document_text.insert(tk.END, '''{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": [\n        "s3:ListBucket"\n      ],\n      "Resource": "*"\n    }\n  ]\n}''')
        
        def on_create():
            policy_name = policy_name_entry.get().strip()
            description = description_entry.get().strip()
            policy_document = policy_document_text.get(1.0, tk.END).strip()
            
            if not policy_name:
                messagebox.showerror("Error", "Policy name cannot be empty")
                return
            
            try:
                # Run AWS CLI command to create policy
                result = subprocess.run(
                    ["aws", "iam", "create-policy", "--policy-name", policy_name, "--description", description, "--policy-document", policy_document],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    messagebox.showerror("Error", f"Failed to create policy: {result.stderr}")
                else:
                    messagebox.showinfo("Success", f"Policy '{policy_name}' created successfully")
                    dialog.destroy()
                    self.list_policies()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create policy: {e}")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Create", command=on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_policy(self):
        # Get the selected policy
        selection = self.policies_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a policy to delete")
            return
        
        item_id = selection[0]
        policy_name = self.policies_tree.item(item_id, "text")
        policy_arn = self.policies_tree.item(item_id, "values")[0]
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete policy '{policy_name}'?"):
            return
        
        try:
            # Delete the policy
            result = subprocess.run(
                ["aws", "iam", "delete-policy", "--policy-arn", policy_arn],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to delete policy: {result.stderr}")
            else:
                messagebox.showinfo("Success", f"Policy '{policy_name}' deleted successfully")
                self.list_policies()
                
                # Clear the details text
                self.policy_details_text.config(state=tk.NORMAL)
                self.policy_details_text.delete(1.0, tk.END)
                self.policy_details_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete policy: {e}")