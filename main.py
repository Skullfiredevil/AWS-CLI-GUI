#!/usr/bin/env python3

import tkinter as tk
from aws_cli_gui import AwsCliGui

def main():
    # Create the root window
    root = tk.Tk()
    
    # Initialize the application
    app = AwsCliGui(root)
    
    # Start the main event loop
    root.mainloop()

if __name__ == "__main__":
    main()