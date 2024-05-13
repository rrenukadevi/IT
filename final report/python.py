import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog  # Import filedialog module for file selection
import subprocess
from PIL import Image, ImageTk  # Import modules from PIL

def run_python_script(dataset_file):
    # Call your Python file or function here
    subprocess.call(["python", "final1.py", dataset_file])
    # You can modify the above line based on how you want to execute your Python file

def login():
    username = username_entry.get()
    password = password_entry.get()
    
    # Here you can perform authentication logic
    # For simplicity, let's assume correct username is "admin" and password is "password"
    if username == "admin" and password == "password":
        messagebox.showinfo("Login Successful")
        # Open file dialog to choose dataset file
        global file
        file = filedialog.askopenfilename(title="Choose Dataset File", filetypes=[("CSV Files", "*.csv")])
        if file:
            messagebox.showinfo("Dataset", "Dataset Loaded")
        else:
            messagebox.showerror("Error", "Please load dataset")
    else:
        messagebox.showinfo("Login Failed", "Invalid username or password")

def run():
    if file:
        run_python_script(file)
    else:
        messagebox.showinfo("Error", "Please load dataset")

file = ""

# Create a new Tkinter window
window = tk.Tk()
window.title("DDOS Using Explainable AI")

# Load and display the image
image = Image.open("C:/Users/HP/Desktop/img.png")  # Update with your image file path
image = image.resize((500, 300))  # Resize the image if necessary
photo = ImageTk.PhotoImage(image)

# Create a label to display the image
image_label = ttk.Label(window, image=photo)
image_label.pack()

# Create a frame for login widgets
login_frame = ttk.Frame(window)
login_frame.pack(padx=20, pady=20)

# Create a label for username
username_label = ttk.Label(login_frame, text="Username:")
username_label.grid(row=0, column=0, padx=5, pady=5)

# Create an entry field for username
username_entry = ttk.Entry(login_frame)
username_entry.grid(row=0, column=1, padx=5, pady=5)

# Create a label for password
password_label = ttk.Label(login_frame, text="Password:")
password_label.grid(row=1, column=0, padx=5, pady=5)

# Create an entry field for password
password_entry = ttk.Entry(login_frame, show="*")
password_entry.grid(row=1, column=1, padx=5, pady=5)

# Create a login button
login_button = ttk.Button(login_frame, text="Login", command=login)
login_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

# Create a frame for run button
run_frame = ttk.Frame(window)
run_frame.pack(padx=20, pady=20)

# Create a run button
run_button = ttk.Button(run_frame, text="Run", command=run)
run_button.pack(padx=5, pady=5)

# Start the Tkinter event loop
window.mainloop()
