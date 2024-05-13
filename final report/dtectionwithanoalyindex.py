import matplotlib.pyplot as plt
import numpy as np
from sklearn.neighbors import KDTree, KNeighborsClassifier

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
def calculate_anomaly_index(nm, ni, ρ):
    κ = ρ + (1 - ρ) * nm / (ni + nm)
    return κ

# Example traffic profiles obtained from the generation phase (replace with your actual traffic profiles)
traffic_profiles = {
    1: {'pktcount': 433037, 'dur': 960.0, 'protocol': 'TCP'},
    2: {'pktcount': 23885, 'dur': 50.0, 'protocol': 'UDP'},
    3: {'pktcount': 451665, 'dur': 1000.0, 'protocol': 'ICMP'},
    4: {'pktcount': 631975, 'dur': 1400.0, 'protocol': 'TCP'},
    5: {'pktcount': 125000, 'dur': 40.0, 'protocol': 'UDP'},
}

# Convert traffic profiles to feature matrix
X = np.array([[profile['pktcount'], profile['dur']] for profile in traffic_profiles.values()])

# Define labels for classification (0: normal, 1: malicious)
y = np.array([0, 0, 1, 1, 0])  # Example labels, replace with your actual labels

# Train KNN classifier
knn_classifier = KNeighborsClassifier(n_neighbors=3)
knn_classifier.fit(X, y)

# Train KD-tree
kd_tree = KDTree(X)

# Example traffic profile to classify
new_profile = np.array([[500000, 1200]])  # Replace with your actual traffic profile

# Predict using KNN classifier
knn_prediction = knn_classifier.predict(new_profile)
print("KNN Prediction:", "Malicious" if knn_prediction[0] == 1 else "Normal")

# Query KD-tree
distances, indices = kd_tree.query(new_profile, k=3)  # Adjust k value as needed
malicious_neighbors = np.sum(y[indices] == 1)
normal_neighbors = np.sum(y[indices] == 0)
kd_prediction = 1 if malicious_neighbors > normal_neighbors else 0
print("KD-tree Prediction:", "Malicious" if kd_prediction == 1 else "Normal")

# Calculate anomaly index
ρ = 0.5  # Base value of ρ
nm = 2  # Number of malicious traffic profiles within the window
ni = 3  # Number of legitimate traffic profiles within the window
anomaly_index = calculate_anomaly_index(nm, ni, ρ)
print("Anomaly Index (κ):", anomaly_index)

# Classify malicious traffic profiles into ICMP, TCP, and UDP floods
if knn_prediction[0] == 1:
    # Initialize counters for each protocol
    icmp_count = 0
    tcp_count = 0
    udp_count = 0
    
    # Count occurrences of each protocol
    for profile in traffic_profiles.values():
        if profile['protocol'] == 'ICMP':
            icmp_count += 1
        elif profile['protocol'] == 'TCP':
            tcp_count += 1
        elif profile['protocol'] == 'UDP':
            udp_count += 1
    
    total_count = icmp_count + tcp_count + udp_count

    # Calculate percentages
    tcp_percentage = (tcp_count / total_count) * 100
    udp_percentage = (udp_count / total_count) * 100
    icmp_percentage = (icmp_count / total_count) * 100
    
    # Plot the pie chart for different types of flood attacks
    plot_pie_chart({'ICMP Flood': icmp_percentage, 'TCP Flood': tcp_percentage, 'UDP Flood': udp_percentage}, 'Classification of Malicious Traffic Profiles')
else:
    print("No malicious traffic profiles to classify.")

# Plot the pie chart for classified traffic profiles
plot_pie_chart({'Normal': len(traffic_profiles) - knn_prediction[0], 'Malicious': knn_prediction[0]}, 'Classification of Traffic Profiles')
