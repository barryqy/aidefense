#!/usr/bin/env python3
"""
Generate a malicious pickle file for testing AI Defense Model Scanner.

This creates a pickle file that contains a malicious pattern commonly seen
in supply chain attacks: executing shell commands during model loading.

DO NOT unpickle this file directly - it will execute code on your system!
Only use it for scanning with AI Defense.
"""
import pickle
import numpy as np


class MaliciousModel:
    """
    A class that mimics a legitimate model but contains malicious code.
    When unpickled, it will execute a shell command via posix.system.
    """
    
    def __init__(self):
        # Legitimate-looking model data
        self.params = np.array([1.45, 23.1, 24.99])
    
    def __reduce__(self):
        # This is the exploit: when unpickling, it executes a shell command
        # The scanner should detect this as UNSAFE_IMPORT and CODE_EXECUTION
        import posix
        return (posix.system, ('touch evil_file.txt | echo "Do not use pickle !!!" > evil_file.txt',))


def generate_malicious_file(filename='malicious_model.pkl'):
    """Generate the malicious pickle file."""
    
    # Create a list containing a numpy array and the malicious class
    # This mimics real-world scenarios where model parameters are stored
    data = [MaliciousModel()]
    
    # Save to pickle file
    with open(filename, 'wb') as f:
        pickle.dump(data, f)
    
    return filename


if __name__ == '__main__':
    import sys
    import os
    
    filename = sys.argv[1] if len(sys.argv) > 1 else 'malicious_model.pkl'
    
    print("=" * 70)
    print("MALICIOUS MODEL GENERATOR")
    print("=" * 70)
    print(f"\n⚠️  WARNING: This creates a malicious pickle file!\n")
    print("The file contains:")
    print("  • posix.system() call (UNSAFE_IMPORT)")
    print("  • Shell command execution (CODE_EXECUTION)")
    print("  • __reduce__ exploit (REDUCE_EXPLOIT)")
    print("\n" + "=" * 70)
    
    result = generate_malicious_file(filename)
    file_size = os.path.getsize(result)
    
    print(f"\n✅ Created: {result} ({file_size} bytes)")
    print(f"\n🔍 Now scan it with:")
    print(f"   python3 scan_file.py {result}")
    print("\n⚠️  DO NOT unpickle this file directly!")
    print("=" * 70)

