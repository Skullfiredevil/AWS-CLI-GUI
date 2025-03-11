import subprocess
import json
import os
import threading
import time
from functools import lru_cache

# Cache timeout in seconds
CACHE_TIMEOUT = 60

# Cache for AWS CLI results
class TimedCache:
    def __init__(self, timeout=CACHE_TIMEOUT):
        self.cache = {}
        self.timeout = timeout
    
    def get(self, key):
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.timeout:
                return value
            # Cache expired
            del self.cache[key]
        return None
    
    def set(self, key, value):
        self.cache[key] = (value, time.time())
    
    def clear(self):
        self.cache.clear()

# Initialize caches
aws_command_cache = TimedCache()

# Run AWS CLI command with caching
def run_aws_command(command, args=None, use_cache=True, json_output=True):
    """
    Run an AWS CLI command with caching support
    
    Args:
        command (list): AWS command as a list (e.g., ['s3', 'ls'])
        args (list, optional): Additional arguments
        use_cache (bool): Whether to use cache for this command
        json_output (bool): Whether to parse JSON output
    
    Returns:
        tuple: (success, data) where success is a boolean and data is the command output
    """
    # Build the full command
    cmd = ["aws"] + command
    if json_output:
        cmd.append("--output") 
        cmd.append("json")
    if args:
        cmd.extend(args)
    
    # Create a cache key from the command
    cache_key = ' '.join(cmd)
    
    # Check cache if enabled
    if use_cache:
        cached_result = aws_command_cache.get(cache_key)
        if cached_result is not None:
            return cached_result
    
    try:
        # Run the command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return False, result.stderr
        
        # Parse JSON if requested
        if json_output:
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                return False, "Failed to parse JSON output"
        else:
            data = result.stdout
        
        # Cache the successful result if caching is enabled
        if use_cache:
            aws_command_cache.set(cache_key, (True, data))
        
        return True, data
    except Exception as e:
        return False, str(e)

# Run a command in a separate thread
def run_command_async(command, args=None, callback=None, json_output=True):
    """
    Run an AWS CLI command asynchronously
    
    Args:
        command (list): AWS command as a list
        args (list, optional): Additional arguments
        callback (function): Function to call with results (success, data)
        json_output (bool): Whether to parse JSON output
    
    Returns:
        threading.Thread: The thread running the command
    """
    def _run_command():
        success, data = run_aws_command(command, args, use_cache=False, json_output=json_output)
        if callback:
            callback(success, data)
    
    thread = threading.Thread(target=_run_command)
    thread.daemon = True
    thread.start()
    return thread

# Batch process AWS resources
def batch_process(items, process_func, batch_size=10, callback=None):
    """
    Process a large number of AWS resources in batches
    
    Args:
        items (list): List of items to process
        process_func (function): Function to process each item
        batch_size (int): Number of items to process in parallel
        callback (function): Function to call after each batch completes
    """
    results = []
    total_items = len(items)
    processed = 0
    
    for i in range(0, total_items, batch_size):
        batch = items[i:i+batch_size]
        batch_results = []
        threads = []
        
        # Process batch in parallel
        for item in batch:
            def _callback(success, data, item=item):
                batch_results.append((item, success, data))
            
            thread = process_func(item, _callback)
            threads.append(thread)
        
        # Wait for all threads in this batch to complete
        for thread in threads:
            thread.join()
        
        results.extend(batch_results)
        processed += len(batch)
        
        if callback:
            callback(processed, total_items, batch_results)
    
    return results

# Clear all caches
def clear_caches():
    """
    Clear all AWS command caches
    """
    aws_command_cache.clear()

# Get AWS credentials and configuration
@lru_cache(maxsize=1)
def get_aws_config():
    """
    Get current AWS configuration (cached)
    
    Returns:
        dict: AWS configuration including region, profile, etc.
    """
    config = {
        'region': os.environ.get('AWS_REGION', 'us-east-1'),
        'profile': os.environ.get('AWS_PROFILE', 'default')
    }
    
    # Try to get caller identity
    success, data = run_aws_command(['sts', 'get-caller-identity'], use_cache=True)
    if success:
        config['account_id'] = data.get('Account')
        config['user_arn'] = data.get('Arn')
    
    return config