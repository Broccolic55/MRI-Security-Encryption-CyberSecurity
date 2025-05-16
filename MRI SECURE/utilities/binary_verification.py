"""
Binary Verification Utility

This script verifies the exact binary equivalence between original and 
decrypted files to ensure perfect fidelity in the encryption and decryption process.
"""

import os
import sys
import hashlib
import argparse
import difflib
from datetime import datetime

def compare_files(original_file, decrypted_file, report_file=None):
    """
    Compare two files byte by byte and report any differences
    
    Args:
        original_file (str): Path to original file
        decrypted_file (str): Path to decrypted file
        report_file (str, optional): Path to save report
    
    Returns:
        bool: True if files are identical, False otherwise
    """
    if not os.path.exists(original_file):
        print(f"Error: Original file not found: {original_file}")
        return False
    
    if not os.path.exists(decrypted_file):
        print(f"Error: Decrypted file not found: {decrypted_file}")
        return False
    
    # Get file sizes
    orig_size = os.path.getsize(original_file)
    decr_size = os.path.getsize(decrypted_file)
    
    # Compare file sizes
    if orig_size != decr_size:
        print(f"❌ Size mismatch: Original={orig_size} bytes, Decrypted={decr_size} bytes")
        size_match = False
    else:
        print(f"✓ Size match: Both files are {orig_size} bytes")
        size_match = True
    
    # Calculate and compare MD5 hashes
    with open(original_file, 'rb') as f:
        orig_hash = hashlib.md5(f.read()).hexdigest()
        
    with open(decrypted_file, 'rb') as f:
        decr_hash = hashlib.md5(f.read()).hexdigest()
    
    if orig_hash != decr_hash:
        print(f"❌ Hash mismatch: Original={orig_hash}, Decrypted={decr_hash}")
        hash_match = False
    else:
        print(f"✓ Hash match: Both files have MD5={orig_hash}")
        hash_match = True
    
    # If sizes don't match or hashes don't match, do a detailed comparison
    results = []
    if not (size_match and hash_match):
        print("Performing detailed binary comparison...")
        results.append(f"Detailed binary comparison - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        results.append(f"Original file: {original_file} ({orig_size} bytes, MD5: {orig_hash})")
        results.append(f"Decrypted file: {decrypted_file} ({decr_size} bytes, MD5: {decr_hash})")
        results.append("-" * 80)
        
        # Read files as binary
        with open(original_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
            orig_data = f1.read()
            decr_data = f2.read()
        
        # Find first difference
        min_len = min(len(orig_data), len(decr_data))
        diff_positions = []
        
        for i in range(min_len):
            if orig_data[i] != decr_data[i]:
                diff_positions.append(i)
                if len(diff_positions) <= 20:  # Limit to first 20 differences
                    results.append(f"Difference at position {i}: Original=0x{orig_data[i]:02x}, Decrypted=0x{decr_data[i]:02x}")
        
        if len(diff_positions) > 20:
            results.append(f"... and {len(diff_positions) - 20} more differences")
        
        results.append(f"\nTotal differences: {len(diff_positions)} bytes")
        
        # Print results
        for line in results:
            print(line)
            
        # Save report if requested
        if report_file:
            with open(report_file, 'w') as f:
                f.write("\n".join(results))
            print(f"Detailed report saved to {report_file}")
    
    return size_match and hash_match

def main():
    parser = argparse.ArgumentParser(description='Verify binary equivalence between original and decrypted files')
    parser.add_argument('original', help='Path to original file')
    parser.add_argument('decrypted', help='Path to decrypted file')
    parser.add_argument('-r', '--report', help='Path to save detailed report')
    
    args = parser.parse_args()
    
    result = compare_files(args.original, args.decrypted, args.report)
    if result:
        print("\n SUCCESS: Files are binary-identical!")
        sys.exit(0)
    else:
        print("\n FAILURE: Files are different!")
        sys.exit(1)

if __name__ == "__main__":
    main()
