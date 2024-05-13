import csv
import time
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk

# Function to extract features from the input dataset
def extract_features(traffic_batch):
    # Placeholder for feature extraction logic
    pktcount = sum(packet['pktcount'] for packet in traffic_batch)
    pktrate = sum(packet['pktrate'] for packet in traffic_batch)
    Protocol = set(packet['Protocol'] for packet in traffic_batch)
    sourceIPAddress = set(packet['sourceIPAddress'] for packet in traffic_batch)
    TimeBin = len(traffic_batch)
    
    features = {
        'pktcount': pktcount,
        'pktrate': pktrate,
        'Protocol': Protocol,
        'sourceIPAddress': sourceIPAddress,
        'TimeBin': TimeBin  
        # Add more features as needed
    }
    return features

# Function to read traffic data from a dataset file
def read_traffic_data(file_path):
    traffic_data = []
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Assuming each row represents a packet
            packet = {
                'dur': float(row['dur']),
                'pktcount': int(row['pktcount']),
                'pktrate': int(row['pktrate']),
                'Protocol': row['Protocol'],
                'sourceIPAddress': row['sourceIPAddress']
            }
            traffic_data.append(packet)
    return traffic_data

# Function to validate user credentials
def validate_credentials(username, password):
    # Add your authentication logic here
    # For simplicity, always return True for now
    return True

# Function to start the traffic profile generation phase
def start_generation_phase():
    root_login.destroy()  # Close the login window
    generation_phase()

# Function to display login page
def display_login_page():
    global root, root_login, username_entry, password_entry
    
    root.withdraw()  # Hide the initial GUI window
    
    root_login = tk.Toplevel()
    root_login.title("Login Page")
    
    # Create labels and entry fields for username and password
    tk.Label(root_login, text="Username:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
    username_entry = tk.Entry(root_login)
    username_entry.grid(row=0, column=1, padx=10, pady=5)
    
    # Set default value for username entry
    username_entry.insert(0, "YourUsername")  # Change "YourUsername" to the desired default value
    
    tk.Label(root_login, text="Password:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
    password_entry = tk.Entry(root_login, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)
    
    # Set default value for password entry
    password_entry.insert(0, "YourPassword")  # Change "YourPassword" to the desired default value
    
    # Create login button
    login_button = tk.Button(root_login, text="Login", command=login)
    login_button.grid(row=2, column=0, columnspan=2, pady=10)
    
    root_login.mainloop()

# Function to perform login
def login():
    username = username_entry.get()
    password = password_entry.get()
    
    # Validate credentials
    if validate_credentials(username, password):
        start_generation_phase()
    else:
        messagebox.showerror("Error", "Invalid username or password")

# Function to display traffic profile
def display_traffic_profile(traffic_profile):
    print("Traffic Profile for Batch:", traffic_profile)
    # Simulating delay before displaying the next profile
    time.sleep(5)  # Adjust as needed for the desired delay

# Main function for the generation phase
def generation_phase():
    # Define dataset file path
    dataset_file = r'C:\Users\HP\Desktop\dataset_sdn.csv'  # Change this to the path of your dataset file
    
    # Read traffic data from the dataset file
    traffic_data = read_traffic_data(dataset_file)
    
    # Define batch size
    batch_size = 5
    
    # Infinite loop to continuously monitor traffic
    while True:
        # Generate traffic data for the batch
        traffic_batch = traffic_data[:batch_size]
        
        # Extract features from the input dataset
        traffic_profile = extract_features(traffic_batch)
        
        # Display the traffic profile for this batch
        display_traffic_profile(traffic_profile)
        
        # Remove processed data from the dataset
        traffic_data = traffic_data[batch_size:]
        
        # If there is no more data, reset the dataset
        if not traffic_data:
            traffic_data = read_traffic_data(dataset_file)

# Function to create and display the initial GUI
def display_initial_gui():
    global root
    
    root = tk.Tk()
    root.title("Traffic Profile Generation")

    # Display project title
    title_label = tk.Label(root, text="DDOS ATTACK DETECTION AND CLASSIFICATION ", font=("Helvetica", 16))
    title_label.pack()

    # Load and display the image
    image_path = r"C:\Users\HP\Desktop\image.jpg"  # Update with your image path
    img = Image.open(image_path)
    img = img.resize((400, 400), Image.LANCZOS)
    photo = ImageTk.PhotoImage(img)
    label = tk.Label(root, image=photo)
    label.image = photo  # Keep a reference to the image
    label.pack() 

    # Display project aim
    aim_label = tk.Label(root, text="The project aims to detect and classify Distributed"
                         "Denial of Service (DDoS) attacks at the victim's end, utilizing"
                         "a vantage point that monitors all traffic to and from the victim."
                         "It employs a modular approach comprising Generation phase, detection Phase,"
                         "classification Phase and Adaptation and Explanation phase..", font=("Helvetica", 12))
    aim_label.pack()

    # Button to proceed to login page
    proceed_button = tk.Button(root, text="Login", command=display_login_page)
    proceed_button.pack(pady=10)

    root.mainloop()

# Run the program
if __name__ == "__main__":
    display_initial_gui()
