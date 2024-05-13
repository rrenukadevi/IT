import csv

# Function to check if an IP address is malicious
def is_malicious(ip_address):
    # Placeholder for malicious IP detection logic
    # Example: Check if the IP address is on a blacklist
    # For demonstration purposes, let's assume IP addresses ending with '.1' are malicious
    return ip_address.endswith('.1')

# Function to read traffic data from a dataset file and sort IP addresses using grid sorting
def read_traffic_data(file_path, column_name='sourceIPAddress'):
    ip_addresses = []
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Assuming each row represents a packet
            ip_address = row[column_name]  # Adjust column name accordingly
            ip_addresses.append(ip_address)
    
    # Grid sorting: Split IP addresses into four parts (octets) and sort based on each octet
    ip_addresses.sort(key=lambda ip: tuple(map(int, ip.split('.'))))
    
    return ip_addresses

# Main function for the generation phase
def generation_phase():
    # Define dataset file path
    dataset_file = r'C:\Users\HP\Desktop\dataset_sdn.csv'  # Change this to the path of your dataset file
    
    # Read and sort source IP addresses from the dataset file
    ip_addresses = read_traffic_data(dataset_file)
    
    # Print the malicious IP addresses
    print("Sorted Malicious IP Addresses:")
    for ip_address in ip_addresses:
        if is_malicious(ip_address):
            print(ip_address)

# Run the generation phase
if __name__ == "__main__":
    generation_phase()
