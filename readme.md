# AWS CLI GUI

A comprehensive graphical user interface for the AWS Command Line Interface, providing an intuitive way to manage your AWS resources without memorizing complex CLI commands.

## Overview

AWS CLI GUI wraps the powerful AWS CLI tool in a user-friendly interface, making AWS resource management accessible to users who prefer graphical interfaces over command-line tools. The application provides dedicated modules for managing different AWS services including S3, EC2, and IAM.

## Features

### S3 Management
- **Bucket Operations**: List, create, and delete S3 buckets
- **Object Management**: Upload, download, and delete files
- **Folder Support**: Create and navigate folders within buckets
- **Drag and Drop**: Intuitive file uploads via drag and drop interface

### EC2 Management
- **Instance Listing**: View all your EC2 instances with detailed information
- **Instance Control**: Start, stop, and terminate instances
- **Instance Creation**: Launch new instances with customizable configurations
- **Detailed Information**: View comprehensive instance details including security groups and tags

### IAM Management
- **User Management**: Create, list, and delete IAM users
- **Role Management**: Create, list, and delete IAM roles
- **Policy Management**: Create, list, and manage IAM policies
- **Access Key Management**: Create and manage access keys for users
- **Policy Attachment**: Attach policies to users and roles

### Additional Tools
- **AWS Configuration**: Easily configure AWS profiles and regions
- **Script Editor**: Create, edit, and run AWS automation scripts
- **Wizard Interface**: Step-by-step guidance for complex operations
- **Documentation**: Built-in help and documentation

## Requirements

- **Python 3.6+**: The application is built with Python
- **Tkinter**: Used for the GUI components (included with most Python installations)
- **AWS CLI**: Must be installed and configured on your system
- **AWS Account**: Active AWS account with appropriate permissions

## Installation

1. **Install Python**: Ensure Python 3.6 or higher is installed on your system
2. **Install AWS CLI**: Follow the [official AWS CLI installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
3. **Configure AWS CLI**: Run `aws configure` to set up your AWS credentials
4. **Clone the Repository**:
   ```
   git clone https://github.com/skullfiredevil/AWS-CLI-GUI.git
   cd AWS-CLI-GUI
   ```
5. **Run the Application**:
   ```
   python3 main.py
   ```

## Usage Guide

### Getting Started

1. **Launch the application** by running `python3 main.py`
2. **Navigate between services** using the tabbed interface
3. **Configure AWS settings** through the Tools > AWS Configuration menu

### S3 Operations

#### Managing Buckets
1. Go to the **S3 tab**
2. Click **List Buckets** to see all available buckets
3. Select a bucket to view its contents
4. Use **Create Bucket** or **Delete Bucket** buttons for bucket management

#### Working with Files
1. Select a bucket from the list
2. Navigate through folders by double-clicking
3. Use **Upload File** to add files to the current location
4. Select a file and click **Download File** to save it locally
5. Use **Create Folder** to create new directories
6. **Drag and drop** files directly into the bucket contents area

### EC2 Operations

#### Managing Instances
1. Go to the **EC2 tab**
2. Click **List Instances** to see all your EC2 instances
3. Select an instance to view detailed information
4. Use the **Start**, **Stop**, or **Terminate** buttons to control the instance state

#### Creating New Instances
1. Click **Create Instance**
2. Fill in the required details (AMI ID, instance type, etc.)
3. Configure security groups and other settings
4. Click **Create** to launch the instance

### IAM Operations

#### User Management
1. Go to the **IAM tab** and select the **Users** sub-tab
2. Click **List Users** to see all IAM users
3. Use **Create User** to add new users
4. Select a user and click **Create Access Key** to generate credentials
5. Use **Attach Policy** to assign permissions to users

#### Role Management
1. Select the **Roles** sub-tab
2. Click **List Roles** to see all IAM roles
3. Use **Create Role** to add new roles
4. Select a role and click **Attach Policy** to assign permissions

#### Policy Management
1. Select the **Policies** sub-tab
2. Click **List Policies** to see all policies
3. Filter policies by name or type (AWS Managed/Customer Managed)
4. Use **Create Policy** to define new permission sets

### Using the Script Editor

1. Go to **Tools > Script Editor**
2. Create a new script or open an existing one
3. Write your AWS automation script (Python or shell script)
4. Click **Run** to execute the script
5. View the output in the results window

## Troubleshooting

### Common Issues

- **AWS CLI Not Found**: Ensure AWS CLI is installed and in your system PATH
- **Authentication Errors**: Verify your AWS credentials are correctly configured
- **Permission Denied**: Check that your AWS user has the necessary permissions
- **Region Issues**: Confirm you're operating in the intended AWS region

### Getting Help

- Use the built-in documentation via **Help > Documentation**
- Check the **About** section for version information
- For advanced issues, refer to the AWS CLI documentation

## Contributing

Contributions are welcome! If you'd like to add new features or improve existing ones, please submit a pull request.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Acknowledgments

- Thanks to the AWS CLI team for providing a robust command-line interface
- Thanks to the Python community for extensive libraries and support
