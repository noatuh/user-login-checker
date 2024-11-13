import csv

def read_data_remove_bom(file_path):
    """Reads employee login data from a CSV file and removes any BOM characters."""
    data = []
    with open(file_path, mode='r', encoding='utf-8-sig') as file:  # Handle BOM
        reader = csv.DictReader(file)
        for row in reader:
            data.append(row)
    return data

def write_suspicious_data(data, output_file):
    """Filters and writes suspicious login data to a new CSV file and prints a summary."""
    suspicious_users = []
    for record in data:
        login_count = int(record['Logins'])
        if login_count >= 100:
            last_name = record['Last Name']
            first_name = record['First Name']
            login_count_excess = login_count - 100
            suspicious_users.append({
                'name': f"{last_name}; {first_name}",
                'login_count': login_count,
                'login_count_excess': login_count_excess
            })
    
    # Write to CSV
    with open(output_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['name', 'login_count', 'login_count_excess'])
        writer.writeheader()
        writer.writerows(suspicious_users)
    
    # Print table
    print(f"{'First Name':<15}{'Last Name':<15}{'Login Count':<15}")
    for user in suspicious_users:
        name_split = user['name'].split('; ')
        print(f"{name_split[1]:<15}{name_split[0]:<15}{user['login_count']:<15}")
    
    return len(suspicious_users)

def main_bom_handled():
    """Main function to process and analyze login data with BOM handled."""
    input_file = 'emp_logins.csv'  # Replace with the correct file path if needed
    output_file = 'affected_users.csv'
    
    # Read data with BOM handling
    data = read_data_remove_bom(input_file)
    
    # Process and write suspicious logins
    total_suspicious = write_suspicious_data(data, output_file)
    
    # Display total suspicious users
    print(f"\nTotal number of employees with suspicious login attempts: {total_suspicious}")

# Run the script
if __name__ == "__main__":
    main_bom_handled()
