# email_verifier.py

import pandas as pd
import re
import dns.resolver
import argparse
import sys
import os

# --- Constants and Configuration ---
# Basic regex for email syntax validation.
# This is a common pattern but doesn't cover all edge cases or RFC complexities.
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# --- Email Validation Logic ---

def validate_email_address(email_address: str) -> str:
    """
    Performs a series of checks to validate an email address.
    Checks include syntax, domain existence (A/AAAA records), and MX records.

    Args:
        email_address (str): The email address to validate.

    Returns:
        str: A status string indicating the validation result (e.g., "Valid",
             "Invalid Syntax", "Domain Not Found", "No MX Records", "Error").
    """
    if not isinstance(email_address, str):
        return "Invalid Type"
    
    email_address = email_address.strip()
    if not email_address:
        return "Empty Email"

    # 1. Basic Regex Syntax Check
    if not re.match(EMAIL_REGEX, email_address):
        return "Invalid Syntax"

    # Split email into local part and domain
    try:
        _, domain = email_address.split('@')
    except ValueError:
        # Should be caught by regex, but as a safeguard
        return "Invalid Format"

    # 2. Domain Existence Check (A or AAAA records) and MX Record Check
    try:
        # Check for A (IPv4) or AAAA (IPv6) records for the domain
        # This confirms the domain generally exists and is resolvable
        try:
            dns.resolver.resolve(domain, 'A')
        except dns.resolver.NoAnswer:
            try:
                dns.resolver.resolve(domain, 'AAAA')
            except dns.resolver.NoAnswer:
                # If neither A nor AAAA records are found, the domain might not exist or be misconfigured
                return "Domain No A/AAAA Record"
        
        # Check for MX (Mail Exchange) records
        # This confirms the domain is configured to receive emails
        try:
            dns.resolver.resolve(domain, 'MX')
            return "Valid"
        except dns.resolver.NoAnswer:
            # Domain exists, but no MX records found, so it can't receive mail
            return "No MX Records"
        except dns.resolver.NXDOMAIN:
            # This case should ideally be caught by the A/AAAA check, but as a safeguard
            return "Domain Not Found"
        except dns.resolver.Timeout:
            return "DNS Timeout"
        except Exception as e:
            return f"DNS Error: {e}"

    except dns.resolver.NXDOMAIN:
        # The domain itself does not exist
        return "Domain Not Found"
    except dns.resolver.NoNameservers:
        # No nameservers could be found for the domain
        return "No Nameservers"
    except dns.resolver.Timeout:
        # DNS query timed out
        return "DNS Timeout"
    except Exception as e:
        # Catch any other unexpected errors during DNS resolution
        return f"Unexpected Error: {e}"

# --- Main Execution Logic ---

def main():
    """
    Parses command-line arguments, reads a CSV, validates emails,
    and writes the results to a new CSV file.
    """
    parser = argparse.ArgumentParser(
        description="Enhance lead quality by validating email addresses in a CSV file."
    )
    parser.add_argument(
        "--input_file",
        type=str,
        required=True,
        help="Path to the input CSV file containing lead data."
    )
    parser.add_argument(
        "--email_column",
        type=str,
        required=True,
        help="The name of the column containing email addresses in the input CSV."
    )
    parser.add_argument(
        "--output_file",
        type=str,
        default=None,
        help="Optional: Path for the output CSV file. If not provided, "
             "it will append '_validated' to the input filename."
    )

    args = parser.parse_args()

    input_file = args.input_file
    email_column = args.email_column
    output_file = args.output_file

    # Generate default output filename if not provided
    if output_file is None:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_validated{ext}"

    print(f"Loading data from: {input_file}")
    print(f"Email column to validate: '{email_column}'")

    try:
        # Read the input CSV file into a pandas DataFrame
        df = pd.read_csv(input_file)
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except pd.errors.EmptyDataError:
        print(f"Error: Input file '{input_file}' is empty.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)

    # Check if the specified email column exists
    if email_column not in df.columns:
        print(f"Error: Email column '{email_column}' not found in the input CSV.")
        print(f"Available columns: {', '.join(df.columns)}")
        sys.exit(1)

    print("Starting email validation...")
    # Apply the email validation function to the specified column
    # .fillna('') is used to treat NaN values as empty strings for validation
    df['Email_Validation_Status'] = df[email_column].fillna('').apply(validate_email_address)

    print(f"Validation complete. Saving results to: {output_file}")
    try:
        # Save the DataFrame with the new validation status to a new CSV file
        df.to_csv(output_file, index=False)
        print("Process finished successfully.")
    except Exception as e:
        print(f"Error saving output file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
