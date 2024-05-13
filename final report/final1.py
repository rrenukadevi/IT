import csv
import time
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from sklearn.neighbors import KDTree, KNeighborsClassifier

class Rule:
    def init(self, condition=None):
        self.condition = condition
        self.condition_exists = True  # Placeholder

class DetectionModel:
    def init(self):
        self.searching_area_set = set()
        self.root = None
    
    def update(self, rule):
        pass  # Placeholder

# Function to extract features from the input dataset
def extract_features(traffic_batch):
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

# Function for mapping via traffic measurement
def map_traffic_measurement(D, D_new):
    D_normalized = np.zeros_like(D)
    for i in range(D.shape[1]):
        l = max(D_new[:, i]) - min(D_new[:, i])
        D_normalized[:, i] = l * (D[:, i] - min(D[:, i])) / (max(D[:, i]) - min(D[:, i]))
    return D_normalized

# Function for online updating for KD-tree
def online_update_KD_tree(traffic_samples):
    # Placeholder for online updating of KD-tree
    print("Online updating for KD-tree")

# Function for integration with existing thresholds/rules
def integrate_existing_rules(existing_rules, detection_model):
    for rule in existing_rules:
        if hasattr(detection_model, 'searching_area_set') and rule.condition in detection_model.searching_area_set:
            detection_model.searching_area_set.remove(rule.condition)
        elif hasattr(rule, 'condition_exists') and rule.condition_exists:
            detection_model.update(rule)
        else:
            detection_model.root.right_child = detection_model
            detection_model.root = rule.condition
            detection_model.root.left_child = "FILTER action"
    return detection_model

# Function to plot a pie chart
def plot_pie_chart(data, title):
    labels = data.keys()
    sizes = data.values()
    
    # Filter out NaN values
    sizes = [size for size in sizes if not np.isnan(size)]
    
    # Check if there's any valid data to plot
    if not sizes:
        print("No valid data to plot the pie chart.")
        return
    
    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=['skyblue', 'lightcoral', 'lightgreen'])
    plt.axis('equal')
    plt.title(title)
    plt.show()

# Function to calculate anomaly index
def calculate_anomaly_index(Nm, N1):
    κ = 0.5 + (1 - 0.5) * Nm / (N1 + Nm)
    return κ

# Main function for the generation phase
def generation_phase():
    # Define dataset file path
    dataset_file = r'C:\Users\HP\Desktop\dataset_sdn.csv'  # Change this to the path of your dataset file
    
    # Read traffic data from the dataset file
    traffic_data = read_traffic_data(dataset_file)
    
    # Define batch size and time interval (in seconds)
    batch_size = 5
    time_interval = 5  # Each batch is 5 seconds
    
    # Generate traffic profiles continuously until interrupted by the user
    try:
        while True:
            start_time = time.time()  # Record start time of the batch

            # Generate traffic data for the batch
            traffic_batch = traffic_data[:batch_size]

            # Extract features from the input dataset
            traffic_profile = extract_features(traffic_batch)

            # Display the traffic profile for this batch
            print("Traffic Profile for Batch:", traffic_profile)

            # Remove processed data from the dataset
            traffic_data = traffic_data[batch_size:]

            # If there is no more data, reset the dataset
            if not traffic_data:
                traffic_data = read_traffic_data(dataset_file)

            # Calculate time elapsed for the batch
            elapsed_time = time.time() - start_time

            # Sleep for the remaining time in the interval
            time.sleep(max(0, time_interval - elapsed_time))
    
    except KeyboardInterrupt:
        print("Traffic profile generation stopped by user input. Proceeding to the next phase...")

# Function for the detection phase
def detection_phase(dataset_file):
    dataset = pd.read_csv(dataset_file, encoding='utf-8')
    X = dataset[['pktcount', 'dur']].values
    protocol = dataset['Protocol'].values
    protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2}
    X_protocol = np.array([protocol_map[p] for p in protocol]).reshape(-1, 1)
    X_combined = np.concatenate((X, X_protocol), axis=1)
    y = dataset['label'].values
    knn_classifier = KNeighborsClassifier(n_neighbors=3)
    knn_classifier.fit(X_combined, y)
    kd_tree = KDTree(X_combined)
    new_profile = np.array([[500000, 1200, protocol_map['TCP']]])
    knn_prediction = knn_classifier.predict(new_profile.reshape(1, -1))
    print("KNN Prediction:", "Malicious" if knn_prediction[0] == 1 else "Normal")
    distances, indices = kd_tree.query(new_profile, k=3)
    malicious_neighbors = np.sum(y[indices] == 1)
    normal_neighbors = np.sum(y[indices] == 0)
    kd_prediction = 1 if malicious_neighbors > normal_neighbors else 0
    print("KD-tree Prediction:", "Malicious" if kd_prediction == 1 else "Normal")
    anomaly_index = calculate_anomaly_index(malicious_neighbors, normal_neighbors)
    print("Anomaly Index (κ):", anomaly_index)
    plot_pie_chart({'Normal': np.sum(y == 0), 'Malicious': np.sum(y == 1)}, 'Traffic Profile Labels')
    icmp_count = np.sum(protocol == 'ICMP')
    tcp_count = np.sum(protocol == 'TCP')
    udp_count = np.sum(protocol == 'UDP')
    plot_pie_chart({'ICMP': icmp_count, 'TCP': tcp_count, 'UDP': udp_count}, 'Traffic Profiles')

# Function for classification phase
def classification_phase(csv_file, risk_profile):
    traffic_profiles = build_traffic_profiles(csv_file)
    malicious_ips = classify_ip_addresses(traffic_profiles, risk_profile)
    print("Malicious IP addresses for DDoS traffic filtering:")
    for ip in malicious_ips:
        print(ip)

# Function to build traffic profiles for each IP address
def build_traffic_profiles(csv_file):
    traffic_profiles = {}
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            ip_address = row['sourceIPAddress']
            if ip_address not in traffic_profiles:
                traffic_profiles[ip_address] = 0
            traffic_profiles[ip_address] += int(row['pktcount'])
    return traffic_profiles

# Function to classify IP addresses based on risk degree
def classify_ip_addresses(traffic_profiles, risk_profile):
    delta = risk_profile[1]  # Risk profile delta value
    malicious_ips = set()
    
    for ip, pktcount in traffic_profiles.items():
        if pktcount >= delta:
            malicious_ips.add(ip)
    
    return malicious_ips

# Function for explanation phase
def explanation_phase():
    import matplotlib.pyplot as plt
    import numpy as np

    # Step 1: Use risk profile to provide a traceable summary about the current attack
    def risk_profile_summary(risk_profile, max_possible_intensity):
        m, delta = risk_profile
        intensity_percentage = (delta / max_possible_intensity) * 100  # Assuming max_possible_intensity is known
        print("Risk Profile Summary:")
        print("Primary cause of attack:", m)
        print("Intensity of attack:", intensity_percentage, "%")

    # Step 2: Generate status graph to provide a concise representation of attack stage
    def generate_status_graph(attack_stage, anomaly_index):
        plt.figure(figsize=(8, 6))
        plt.plot(attack_stage, label='Attack Stage')
        plt.plot(anomaly_index, label='Anomaly Index')
        plt.xlabel('Time')
        plt.ylabel('Value')
        plt.title('Status Graph')
        plt.legend()
        plt.show()

    # Step 3: Calculate the confidence level of detection results by using anomaly index
    def calculate_anomaly_index(malicious_traffic, legitimate_traffic):
        # Placeholder values, replace with actual calculations
        anomaly_index = np.random.rand(len(malicious_traffic))
        return anomaly_index

    # Example risk profile (m, δ)
    risk_profile = ("number of inbound ICMP packets", 8500)
    max_possible_intensity = 10000  # Assuming max_possible_intensity is known

    # Example data for status graph
    attack_stage = np.random.rand(10)
    anomaly_index = np.random.rand(10)

    # Example data for explanation
    attack_data = np.random.rand(100, 5)

    # Step 1: Risk Profile Summary
    risk_profile_summary(risk_profile, max_possible_intensity)

    # Step 2: Generate Status Graph
    generate_status_graph(attack_stage, anomaly_index)

    # Step 3: Calculate Anomaly Index
    malicious_traffic = np.random.rand(10)
    legitimate_traffic = np.random.rand(10)
    anomaly_index = calculate_anomaly_index(malicious_traffic, legitimate_traffic)
    print("Anomaly Index:", anomaly_index)

# Main function for the adaptation phase
def adaptation_phase():
    import numpy as np

    # Function for mapping via traffic measurement
    def map_traffic_measurement(D, D_new):
        D_normalized = np.zeros_like(D)
        for i in range(D.shape[1]):
            l = max(D_new[:, i]) - min(D_new[:, i])
            D_normalized[:, i] = l * (D[:, i] - min(D[:, i])) / (max(D[:, i]) - min(D[:, i]))
        return D_normalized

    # Function for online updating for KD-tree
    def online_update_KD_tree(traffic_samples):
        # Placeholder for online updating of KD-tree
        print("Online updating for KD-tree")

    # Function for integration with existing thresholds/rules
    def integrate_existing_rules(existing_rules, detection_model):
        for rule in existing_rules:
            if hasattr(detection_model, 'searching_area_set') and rule.condition in detection_model.searching_area_set:
                detection_model.searching_area_set.remove(rule.condition)
            elif hasattr(rule, 'condition_exists') and rule.condition_exists:
                detection_model.update(rule)
            else:
                detection_model.root.right_child = detection_model
                detection_model.root = rule.condition
                detection_model.root.left_child = "FILTER action"
        return detection_model

    # Example data
    D = np.random.rand(100, 5)  # Original training dataset
    D_new = np.random.rand(50, 5)  # Sampled traffic from new network environment
    traffic_samples = np.random.rand(20, 5)  # Labeled traffic samples for online learning

    # Step 1: Mapping via Traffic Measurement
    D_normalized = map_traffic_measurement(D, D_new)
    print("Mapped training data to the new network environment:", D_normalized)

    # Step 2: Online Updating for KD-tree
    online_update_KD_tree(traffic_samples)

    # Step 3: Integration with Existing Thresholds/Rules
    class Rule:
        def __init__(self, condition=None):
            self.condition = condition
            self.condition_exists = True  # Placeholder

    class DetectionModel:
        def __init__(self):
            self.searching_area_set = set()
            self.root = None


    existing_rules = [
        Rule("traffic.packets_per_second > 2_000_000"),
        Rule("traffic.kbs_per_second > 1_800_000"),
        Rule("traffic.in_out_ratio > 80"),
        Rule("traffic.external_ips > 15_000")
    ]  # Existing detection rules

    # Example detection model
    class DetectionModel:
        def init(self):
            self.searching_area_set = set()
            self.root = None
        
        def update(self, rule):
            pass  # Placeholder

    detection_model = DetectionModel()
    integrated_model = integrate_existing_rules(existing_rules, detection_model)
    print("Integrated detection model with existing rules:", integrated_model)

# Call all phases
if __name__ =="__main__":
    dataset_file = r'C:\Users\HP\Desktop\dataset_sdn.csv'  # Update with the actual file path
    generation_phase()
    detection_phase(dataset_file)
    risk_profile = ("number of inbound ICMP packets", 8500)  # Placeholder risk profile
    classification_phase(dataset_file, risk_profile)
    explanation_phase()
    adaptation_phase()
