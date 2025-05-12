import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog, Menu
import threading
import queue
from ids import run_ids_capture
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timedelta
from tkVideoPlayer import TkinterVideo
from PIL import Image, ImageTk


# Initialize Firebase
if not firebase_admin._apps:
    cred = credentials.Certificate("E:/gp/serviceAccountKey.json")
    firebase_admin.initialize_app(cred)
db = firestore.client()

# Queue for inter-thread communication
packet_queue = queue.Queue()
capture_thread = None
stop_event = threading.Event()

# Protocol counter
protocol_counter = Counter()

# Storage for original treeview data
original_data = []

# Function to change theme
def change_theme():
    if root.cget('bg') == 'black':  # If dark theme
        set_light_theme()
    else:
        set_dark_theme()

def set_dark_theme():
    style.theme_use("clam")
    root.tk_setPalette(background='#2b2b2b', foreground='white', activeBackground='#3c3f41', activeForeground='white')
    for widget in root.winfo_children():
        widget.configure(bg='#2b2b2b', fg='white', highlightbackground='#3c3f41', highlightcolor='white')
    style.configure("TButton", background="#3c3f41", foreground="white")
    style.configure("TLabel", background="#2b2b2b", foreground="white")
    style.configure("TEntry", fieldbackground="#3c3f41", foreground="white")
    style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#3c3f41", bordercolor="white")

def set_light_theme():
    style.theme_use("clam")
    root.tk_setPalette(background='SystemButtonFace', foreground='black', activeBackground='lightgray', activeForeground='black')
    for widget in root.winfo_children():
        widget.configure(bg='SystemButtonFace', fg='black', highlightbackground='lightgray', highlightcolor='black')
    style.configure("TButton", background="#ff4b5c", foreground="black")
    style.configure("TLabel", background="SystemButtonFace", foreground="black")
    style.configure("TEntry", fieldbackground="white", foreground="black")

# Function to generate rules
def generate_rules():
    generate_rules_frame.pack(fill="both", expand=1)
    main_frame.pack_forget()

# Function to go back to the main page
def go_back():
    generate_rules_frame.pack_forget()
    packet_info_frame.pack_forget()
    run_ids_frame.pack_forget()  # Hide RUN IDS page #questionsandanswers
    user_guide_frame.pack_forget()  # Hide User Guide page
    support_frame.pack_forget()
    questionsandanswers_frame.pack_forget()
    home_frame.pack(fill="both", expand=1)
    if 'ids_window' in globals():
        ids_window.destroy()
    main_frame.pack(fill="both", expand=1)

# Function to add IP to the database
def add_ip_to_database():
    ip_address = ip_entry.get().strip()
    if ip_address:
        db.collection('malicious_ips').add({'ip': ip_address})
        messagebox.showinfo("Info", f"IP {ip_address} added to malicious_ips collection")
        ip_entry.delete(0, tk.END)
    else:
        messagebox.showwarning("Warning", "IP address cannot be empty")

# Function to fetch rules from database
def fetch_rules():
    rules = db.collection('snort_rules').stream()
    rule_display.config(state=tk.NORMAL)
    rule_display.delete('1.0', tk.END)
    for rule in rules:
        rule_display.insert(tk.END, f"{rule.to_dict()}\n")
    rule_display.config(state=tk.DISABLED)

# Function to open log analyzer
def open_log_analyzer():
    packet_info_frame.pack(fill="both", expand=1)
    main_frame.pack_forget()
    messagebox.showinfo("Open Log Analyzer", "Log Analyzer has been opened!")

# Function to run IDS
def run_ids():
    open_ids_window()

# Function to start capturing packets
def start_capturing():
    global capture_thread, stop_event
    messagebox.showinfo("Info", "Started capturing packets")

    if capture_thread is None or not capture_thread.is_alive():
        stop_event.clear()
        capture_thread = threading.Thread(target=run_ids_capture, args=(packet_queue, stop_event))
        capture_thread.start()
    else:
        print("Capture thread already running")

# Function to stop capturing packets
def stop_capturing():
    global stop_event
    messagebox.showinfo("Info", "Stopped capturing packets")
    stop_event.set()

# Function to save captured data to file
def save_to_file():
    data = []
    for child in tree.get_children():
        data.append(tree.item(child)["values"])
    
    if not data:
        messagebox.showinfo("Info", "No data to save")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    
    if not file_path:
        return
    
    with open(file_path, 'w') as file:
        file.write("Number of Packet\tDst IP\tSrc IP\tPayload\tProtocol\tTimestamp\n")
        for row in data:
            file.write("\t".join(map(str, row)) + "\n")
    
    messagebox.showinfo("Info", f"Data saved to {file_path}")

# Function for IDS mode
def ids_mode():
    run_ids()  # Simulate clicking "RUN IDS" button
    messagebox.showinfo("Info", "IDS mode activated")

# Function to search in treeview
def search_treeview():
    search_term = search_var.get().lower()
    if search_term == "":
        # Restore original data if search is cleared
        tree.delete(*tree.get_children())
        for row in original_data:
            tree.insert("", "end", values=row)
    else:
        # Filter data based on search term
        tree.delete(*tree.get_children())
        for row in original_data:
            if any(search_term in str(value).lower() for value in row):
                tree.insert("", "end", values=row)

# Function to center the window
def center_window(window, width=1200, height=800):  # Increased window size
    window.geometry(f'{width}x{height}')
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    window_width = window.winfo_width()
    window_height = window.winfo_height()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    window.geometry(f'{window_width}x{window_height}+{x}+{y}')

def open_ids_window():
    global tree, alert_tree, ids_window, progress_bar, progress_label, graph_frame, original_data  # Declare both as global variables
    ids_window = tk.Toplevel(root)
    ids_window.title("Run IDS")
    ids_window.configure(bg="#000026")
    
    button_frame = tk.Frame(ids_window, bg="#000026")
    button_frame.grid(row=0, column=0, columnspan=3, pady=10)
    
    start_button = tk.Button(button_frame, text="Start Capturing", command=start_capturing,  bg="green",width=13,height=2 ,font=("Helvetica",14))
    stop_button = tk.Button(button_frame, text="Stop Capturing", command=stop_capturing,  bg="red",width=13,height=2 ,font=("Helvetica",14))
    save_button = tk.Button(button_frame, text="Save to File", command=save_to_file, bg="blue",width=13,height=2 ,font=("Helvetica",14))
    back_button = tk.Button(button_frame, text="Back", command=go_back,  bg="gray",width=13,height=2 ,font=("Helvetica",14))  # Updated back button
    
    start_button.grid(row=0, column=0, padx=5)
    stop_button.grid(row=0, column=1, padx=5)
    save_button.grid(row=0, column=2, padx=5)
    back_button.grid(row=0, column=3, padx=5)
    
    search_frame = tk.Frame(button_frame,bg="#000026" )
    search_frame.grid(row=0, column=4, columnspan=3, padx=5)

    search_var = tk.StringVar()
    search_entry = ttk.Entry(search_frame, textvariable=search_var, width=50, style="Light.TEntry")
    search_entry.grid(row=0, column=0, padx=5)
    search_button = ttk.Button(search_frame, text="Search", command=search_treeview, style="Light.TButton")  # Added search button
    search_button.grid(row=0, column=1, padx=5)

    progress_bar = ttk.Progressbar(button_frame, orient='horizontal', mode='indeterminate', length=200)
    progress_bar.grid(row=1, column=0, columnspan=6, pady=10)
    
    progress_label = tk.Label(button_frame, text="")
    progress_label.grid(row=2, column=0, columnspan=6, pady=10)

    capture_frame = ttk.LabelFrame(ids_window, text="Capturing Information", width=300, height=300)
    capture_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew", columnspan=2)

    alert_frame = ttk.LabelFrame(ids_window, text="Alerts Summary", width=300, height=300)
    alert_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew", columnspan=2)
    
    graph_frame = ttk.LabelFrame(ids_window, text="Graphical Display", width=300, height=600)
    graph_frame.grid(row=1, column=2, rowspan=2, padx=10, pady=10, sticky="nsew")
    
    ids_window.columnconfigure(0, weight=1)
    ids_window.columnconfigure(1, weight=1)
    ids_window.columnconfigure(2, weight=1)
    ids_window.rowconfigure(1, weight=1)
    ids_window.rowconfigure(2, weight=1)

    labels = ["Number of Packet", "Dst IP", "Src IP", "Payload", "Protocol", "Timestamp", "TTL", "Dst Port", "Src Port", "Service", "State"]
    tree = ttk.Treeview(capture_frame, columns=labels, show="headings")
    for label in labels:
        tree.heading(label, text=label)
        tree.column(label, width=100)  # Adjust the width of each column

    tree.grid(row=0, column=0, sticky="nsew")
    capture_frame.grid_rowconfigure(0, weight=1)
    capture_frame.grid_columnconfigure(0, weight=1)

    alert_labels = ["Severity", "Description"]
    alert_tree = ttk.Treeview(alert_frame, columns=alert_labels, show="headings")
    for label in alert_labels:
        alert_tree.heading(label, text=label)
        alert_tree.column(label, width=100)

    alert_tree.grid(row=0, column=0, sticky="nsew")
    alert_frame.grid_rowconfigure(0, weight=1)
    alert_frame.grid_columnconfigure(0, weight=1)

    def update_treeview():
        global tree, alert_tree, protocol_counter, progress_bar, progress_label, original_data  # Ensure global variables are referenced
        while not packet_queue.empty():
            packet_info = packet_queue.get()
            progress_bar.start(10)  # Start the progress bar
            progress_label.config(text="Checking Malicious IPs...")
            # Simulate checking against malicious IPs
            if packet_info['type'] == 'log':
                packet = packet_info['data']
                protocol_counter[packet.get('protocol')] += 1
                print(f"Updating TreeView with packet: {packet}")
                values = (
                    packet.get('Number of Packet'),
                    packet.get('dst_ip'),
                    packet.get('src_ip'),
                    packet.get('payload'),
                    packet.get('protocol'),
                    packet.get('timestamp'),
                    packet.get('ttl'),
                    packet.get('dst_port'),
                    packet.get('src_port'),
                    packet.get('service'),
                    packet.get('state')
                )
                tree.insert("", "end", values=values)
                original_data.append(values)
                update_pie_chart()  # Update pie chart whenever a new packet is added
            elif packet_info['type'] == 'alert':
                threat_info = packet_info['data']
                print(f"Updating Alert TreeView with threat: {threat_info}")
                alert_tree.insert("", "end", values=(
                    threat_info['threat'].get('severity', 'Unknown'),
                    f"Threat detected from {threat_info.get('src_ip')} to {threat_info.get('dst_ip')}"
                ), tags=('threat',))
            progress_label.config(text="Checking Snort Rules...")
            # Simulate checking against Snort rules
            
        
        alert_tree.tag_configure('threat', background='red', foreground='white')
        

        root.after(1000, update_treeview)

    def update_pie_chart():
        global protocol_counter
        protocols = list(protocol_counter.keys())
        counts = list(protocol_counter.values())
        fig, ax = plt.subplots()
        ax.pie(counts, labels=protocols, autopct='%1.1f%%')
        ax.set_title("Protocol Distribution")
        for widget in graph_frame.winfo_children():
            widget.destroy()
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=1)

    update_treeview()

root = tk.Tk()
style = ttk.Style()
style.configure("Light.TButton", font=("Helvetica", 12), padding=10, background="#ff4b5c", foreground="black")
style.map("Light.TButton", background=[('active', '#ff0000')])
style.configure("Light.TEntry", padding=5, background="#ffffff", foreground="black")
style.configure("Custom.TFrame", background="white")

root.title("spidaz")
center_window(root, 1200, 800)  # Call the function here to set the size and center the window

main_frame = tk.Frame(root, bg="#000026")  # Set the main frame background to #000026
main_frame.pack(fill="both", expand=1)

menubar = tk.Menu(root)
filemenu = tk.Menu(menubar, tearoff=0)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="Files", menu=filemenu)

editmenu = tk.Menu(menubar, tearoff=0)
editmenu.add_command(label="Toggle Theme", command=change_theme)
menubar.add_cascade(label="Edit", menu=editmenu)


# Adding Help menu
helpmenu = tk.Menu(menubar, tearoff=0)
helpmenu.add_command(label="User Guide", command=lambda: open_user_guide())
helpmenu.add_command(label="Support", command=lambda: open_support())
helpmenu.add_command(label="Questions and Answers", command=lambda: open_questionsandanswers())


menubar.add_cascade(label="Help", menu=helpmenu)

root.config(menu=menubar)





# Create sidebar for buttons
sidebar_frame = tk.Frame(main_frame, bg="#000026", width=200, relief="ridge")
sidebar_frame.pack(fill="y", side="left")

profile_frame = tk.Frame(sidebar_frame, bg="#000026")
profile_frame.pack(pady=10)
profile_label = tk.Label(profile_frame, text="SPIDAZ", bg="#000026", fg="white", font=("Helvetica", 16))
profile_label.pack()

home_button = tk.Button(sidebar_frame, text="Home", command=go_back, width=15, height=2, bg="red", fg="white", font=("Helvetica", 16))
home_button.pack(pady=10)

generate_button = tk.Button(sidebar_frame, text="Rules", command=generate_rules, width=15, height=2, bg="red", fg="white", font=("Helvetica", 16))
generate_button.pack(pady=10)

log_analyzer_button = tk.Button(sidebar_frame, text="Open Log Analyzer", command=open_log_analyzer, width=15, height=2, bg="red", fg="white", font=("Helvetica", 16))
log_analyzer_button.pack(pady=10)

run_ids_button = tk.Button(sidebar_frame, text="Run IDS", command=run_ids, width=15, height=2, bg="red", fg="white", font=("Helvetica", 16))
run_ids_button.pack(pady=10)

# Main content frame
content_frame = tk.Frame(main_frame, bg="#000026", relief="sunken")  # Set the content frame background to #000026
content_frame.pack(fill="both", expand=1, padx=10, pady=10)

home_frame = tk.Frame(content_frame, bg="#000026")  # Set the home frame background to #000026
home_frame.pack(fill="both", expand=1)


generate_rules_frame = tk.Frame(root, bg="#000026")

# Function to play video
def play_video():
    video_path = "D:/My downloads/spidaz.mp4"  # Path to the video
    videoplayer = TkinterVideo(master=home_frame, scaled=True)
    videoplayer.load(video_path)
    videoplayer.pack(expand=True, fill="both")
    videoplayer.play()

play_video()  # Call the function to play the video

back_button = tk.Button(generate_rules_frame, text="Back", command=go_back, bg="gray", width=13,height=2 ,font=("Helvetica",14))
back_button.pack(pady=10)

input_frame = tk.Frame(generate_rules_frame, bg="#000026")
input_frame.pack(pady=20)

ip_label = tk.Label(input_frame, text="Enter the malicious IP Address:",bg="#000026", width=25,height=2 ,font=("Helvetica",8 ), foreground="white")
ip_label.grid(row=0, column=0, padx=5)
ip_entry = ttk.Entry(input_frame, width=30, style="Light.TEntry")
ip_entry.grid(row=0, column=1, padx=5)
add_ip_button = tk.Button(input_frame, text="Add IP", command=add_ip_to_database,bg="red", width=13,height=2 ,font=("Helvetica",14) )
add_ip_button.grid(row=0, column=2, padx=5)

rule_display = tk.Text(generate_rules_frame, state=tk.DISABLED, width=80, height=10, bg="light gray")
rule_display.pack(pady=20)

packet_info_frame = tk.Frame(root, bg="#000026")

packet_button_frame = tk.Frame(packet_info_frame, bg="#000026")
packet_button_frame.pack(pady=10)

start_button = tk.Button(packet_button_frame, text="Start Capturing", command=start_capturing,bg="green", width=13,height=2 ,font=("Helvetica",14))
start_button.grid(row=0, column=0, padx=5, pady=5)

stop_button = tk.Button(packet_button_frame, text="Stop Capturing", command=stop_capturing, bg="red",width=13,height=2 ,font=("Helvetica",14))
stop_button.grid(row=0, column=1, padx=5, pady=5)

save_button = tk.Button(packet_button_frame, text="Save to File", command=save_to_file, bg="blue",width=13,height=2 ,font=("Helvetica",14))
save_button.grid(row=0, column=2, padx=5, pady=5)

back_button = tk.Button(packet_button_frame, text="Back", command=go_back, bg="gray",width=13,height=2 ,font=("Helvetica",14))
back_button.grid(row=0, column=3, padx=5, pady=5)

ids_mode_button = tk.Button(packet_button_frame, text="IDS Mode", command=ids_mode, bg="white",width=13,height=2 ,font=("Helvetica",14))
ids_mode_button.grid(row=0, column=4, padx=5, pady=5)

search_frame = tk.Frame(packet_info_frame, bg="#000026")
search_frame.pack(pady=10)

search_var = tk.StringVar()
search_entry = ttk.Entry(search_frame, textvariable=search_var, width=50, style="Light.TEntry")
search_entry.grid(row=0, column=0, padx=5, pady=5)
search_button = ttk.Button(search_frame, text="Search", command=search_treeview, style="Light.TButton")
search_button.grid(row=0, column=1, padx=5, pady=5)

dashboard_frame = tk.Frame(packet_info_frame, padx="10", bg="white")
dashboard_frame.pack(fill="both", expand=1)

columns = ("#1", "#2", "#3", "#4", "#5", "#6",  "#7", "#8", "#9", "#10", "#11")
tree = ttk.Treeview(dashboard_frame, columns=columns, show="headings")
tree.heading("#1", text="Number of Packet")
tree.heading("#2", text="Dst IP")
tree.heading("#3", text="Src IP")
tree.heading("#4", text="Payload")
tree.heading("#5", text="Protocol")
tree.heading("#6", text="Timestamp")
tree.heading("#7", text="ttl")
tree.heading("#8", text="dst_port")
tree.heading("#9", text="src_port")
tree.heading("#10", text="service")
tree.heading("#11", text="State")
tree.column("#1", width=100)
tree.column("#2", width=100)
tree.column("#3", width=100)
tree.column("#4", width=100)
tree.column("#5", width=100)
tree.column("#6", width=100)
tree.column("#7", width=100)
tree.column("#8", width=100)
tree.column("#9", width=100)
tree.column("#10", width=100)
tree.column("#11", width=100)

tree.pack(fill="both", expand=1)

# Create RUN IDS frame
run_ids_frame = tk.Frame(root, bg="white")

# Add content to RUN IDS frame similar to IDS window
run_ids_button_frame = tk.Frame(run_ids_frame, bg="#000026")
run_ids_button_frame.pack(pady=10)

run_start_button = tk.Button(run_ids_button_frame, text="Start Capturing", command=start_capturing,  bg="white",width=13,height=2 ,font=("Helvetica",14))
run_start_button.grid(row=0, column=0, padx=5, pady=5)

run_stop_button = tk.Button(run_ids_button_frame, text="Stop Capturing", command=stop_capturing,  bg="white",width=13,height=2 ,font=("Helvetica",14))
run_stop_button.grid(row=0, column=1, padx=5, pady=5)

run_save_button = tk.Button(run_ids_button_frame, text="Save to File", command=save_to_file,  bg="white",width=13,height=2 ,font=("Helvetica",14))
run_save_button.grid(row=0, column=2, padx=5, pady=5)

run_back_button = tk.Button(run_ids_button_frame, text="Back", command=go_back, bg="white",width=13,height=2 ,font=("Helvetica",14))
run_back_button.grid(row=0, column=3, padx=5, pady=5)

run_search_frame = tk.Frame(run_ids_button_frame, bg="white")
run_search_frame.grid(row=0, column=4, columnspan=3, padx=5)

run_search_var = tk.StringVar()
run_search_entry = ttk.Entry(run_search_frame, textvariable=run_search_var, width=50, style="Light.TEntry")
run_search_entry.grid(row=0, column=0, padx=5)
run_search_button = ttk.Button(run_search_frame, text="Search", command=search_treeview, style="Light.TButton")  # Added search button
run_search_button.grid(row=0, column=1, padx=5)

run_progress_bar = ttk.Progressbar(run_ids_button_frame, orient='horizontal', mode='indeterminate', length=200)
run_progress_bar.grid(row=1, column=0, columnspan=6, pady=10)

run_progress_label = tk.Label(run_ids_button_frame, text="", bg="white")
run_progress_label.grid(row=2, column=0, columnspan=6, pady=10)

run_labels = ["Number of Packet", "Dst IP", "Src IP", "Payload", "Protocol", "Timestamp", "TTL", "Dst Port", "Src Port", "Service", "State"]
run_tree = ttk.Treeview(run_ids_frame, columns=run_labels, show="headings")
for label in run_labels:
    run_tree.heading(label, text=label)
    run_tree.column(label, width=100)  # Adjust the width of each column

run_tree.pack(fill="both", expand=1)

main_frame.pack(fill="both", expand=1)


def update_treeview():
    global tree, alert_tree, protocol_counter, progress_bar, progress_label, original_data  # Ensure global variables are referenced
    while not packet_queue.empty():
        packet_info = packet_queue.get()
        progress_bar.start(10)  # Start the progress bar
        progress_label.config(text="Checking Malicious IPs...")
        # Simulate checking against malicious IPs
        if packet_info['type'] == 'log':
            packet = packet_info['data']
            protocol_counter[packet.get('protocol')] += 1
            print(f"Updating TreeView with packet: {packet}")
            values = (
                packet.get('Number of Packet'),
                packet.get('dst_ip'),
                packet.get('src_ip'),
                packet.get('payload'),
                packet.get('protocol'),
                packet.get('timestamp'), 
                packet.get('ttl'),
                packet.get('dst_port'),
                packet.get('src_port'),
                packet.get('service'),
                packet.get('state')
            )
            tree.insert("", "end", values=values)
            original_data.append(values)
            update_pie_chart()  # Update pie chart whenever a new packet is added
        elif packet_info['type'] == 'alert':
            threat_info = packet_info['data']
            print(f"Updating Alert TreeView with threat: {threat_info}")
            alert_tree.insert("", "end", values=(
                threat_info['threat'].get('severity', 'Unknown'),
                f"Threat detected from {threat_info.get('src_ip')} to {threat_info.get('dst_ip')}"
            ), tags=('threat',))
        progress_label.config(text="Checking Rules...")
        # Simulate checking against Snort rules
        alert_tree.tag_configure('high', background='red', foreground='white')
        alert_tree.tag_configure('Moderate', background='blue', foreground='white')        
        progress_bar.stop()  # Stop the progress bar when done
        progress_label.config(text="")  # Clear the progress label
        root.after(1000, update_treeview)

def update_pie_chart():
    global protocol_counter
    protocols = list(protocol_counter.keys())
    counts = list(protocol_counter.values())
    fig, ax = plt.subplots()
    ax.pie(counts, labels=protocols, autopct='%1.1f%%')
    ax.set_title("Protocol Distribution")
    for widget in graph_frame.winfo_children():
        widget.destroy()
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=1)

update_treeview()

# Function to open User Guide page
def open_user_guide():
    main_frame.pack_forget()
    user_guide_frame.pack(fill="both", expand=1)

# User Guide frame
user_guide_frame = tk.Frame(root, bg="#000026")

user_guide_text = tk.Text(user_guide_frame, wrap="word", font=("Helvetica", 12), state=tk.DISABLED, bg="white")
user_guide_text.pack(expand=1, fill="both", padx=10, pady=10)

back_button = tk.Button(user_guide_frame, text="Back", command=go_back, bg="gray", width=13,height=2 ,font=("Helvetica",14))
back_button.pack(pady=10)

# Add your user guide content here as a comment
user_guide_content = """
                                                                                                    User Manual for SPIDAZ IDS
Overview
SPIDAZ IDS (Intrusion Detection System) is a network security application designed to capture and analyze network traffic, detect threats, and provide detailed logs and alerts. This guide will help you understand the basic functionalities and how to operate the application.

Main Interface
Home Button: Returns you to the main dashboard of the application.
Rules Button: Allows you to manage the rules used by the IDS for threat detection.
Open Log Analyzer Button: Opens the log analyzer interface for reviewing captured data and alerts.
Run IDS Button: Opens the IDS operational interface where you can start and stop capturing packets and analyze the data.
Running the IDS
Start Capturing: Click this button to begin capturing network packets. The captured data will be displayed in the 'Capturing Information' section.
Stop Capturing: Click this button to stop capturing network packets.
Save to File: Saves the captured data to a file for future reference.
Back: Returns you to the previous screen.
Search: Allows you to search through captured data for specific information.
Capturing Information Section
This section displays the following details for each captured packet:

Number of Packets
Destination IP (Dst IP)
Source IP (Src IP)
Payload
Protocol
Timestamp
Time to Live (TTL)
Destination Port (Dst Port)
Source Port (Src Port)
Service
Alerts Summary Section
Displays any alerts generated based on the analysis of the captured packets. Each alert includes:

Severity: Indicates the seriousness of the threat.
Description: Details about the detected threat.
Graphical Display Section
Displays a graphical representation of the protocol distribution of the captured packets. This helps in understanding the types of traffic on your network.

Managing Rules
Enter the malicious IP Address: Input field where you can enter an IP address to be added to the rules database.
Add IP: Click this button to add the entered IP address to the rules.
Back: Returns you to the previous screen.
Example Usage
Starting the IDS:

Open the application and click on "Run IDS".
Click on "Start Capturing" to begin monitoring the network.
The captured packets will appear in the Capturing Information section.
Stopping and Saving Data:

Click on "Stop Capturing" to halt the monitoring process.
Click on "Save to File" to store the captured data for later analysis.
Analyzing Logs:

Click on "Open Log Analyzer" to view the logs.
Use the search functionality to filter specific data.
Review alerts in the Alerts Summary section.
Managing Threats:

Go to the "Rules" section.
Enter a malicious IP address and click "Add IP" to update the IDS rules.
Tips
Regularly update the rules to ensure the IDS can detect the latest threats.
Use the graphical display to quickly assess the types of traffic and identify any anomalies.
Review the alerts summary frequently to stay informed about potential security issues.
This guide should help you get started with using SPIDAZ IDS effectively. If you encounter any issues or have further questions, refer to the help section within the application or seek support from the development team.
"""

# Insert user guide content into the Text widget
user_guide_text.config(state=tk.NORMAL)
user_guide_text.insert(tk.END, user_guide_content)
user_guide_text.config(state=tk.DISABLED)


# Function to open Support page
def open_support():
    main_frame.pack_forget()
    support_frame.pack(fill="both", expand=1)

#support frame
support_frame = tk.Frame(root, bg="#000026")

support_text = tk.Text(support_frame, wrap="word", font=("Helvetica", 12), state=tk.DISABLED, bg="white")
support_text.pack(expand=1, fill="both", padx=10, pady=10)

back_button = tk.Button(support_frame, text="Back", command=go_back, bg="gray", width=13,height=2 ,font=("Helvetica",14))
back_button.pack(pady=10)

# Add your user guide content here as a comment
support_content = """
                                                                                  Support.
If you have any further question or inquiries please contact us at support@spidaz.com
You can join our discord via this link https://discord.com/channels/SPIDAZ/1108711052843155511                                                                                 


"""

# Insert support content into the Text widget
support_text.config(state=tk.NORMAL)
support_text.insert(tk.END, user_guide_content)
support_text.config(state=tk.DISABLED)


# Function to open questionsandanswers page
def open_questionsandanswers():
    main_frame.pack_forget()
    questionsandanswers_frame.pack(fill="both", expand=1)

#questionsandanswers frame
questionsandanswers_frame = tk.Frame(root, bg="#000026")

questionsandanswers_text = tk.Text(questionsandanswers_frame, wrap="word", font=("Helvetica", 12), state=tk.DISABLED, bg="white")
questionsandanswers_text.pack(expand=1, fill="both", padx=10, pady=10)

back_button = tk.Button(questionsandanswers_frame, text="Back", command=go_back, bg="gray", width=13,height=2 ,font=("Helvetica",14))
back_button.pack(pady=10)

# Add your questionsandanswers content here as a comment
questionsandanswers_content = """
                                                                                  Questions and Answers.


Questions and Answers
Q: What is SPIDAZ IDS?
A: SPIDAZ IDS is a network security application designed to capture and analyze network traffic, detect threats, and provide detailed logs and alerts.

Q: How do I start capturing network packets?
A: Click the "Run IDS" button, then click "Start Capturing" on the IDS interface.

Q: How can I stop capturing network packets?
A: Click the "Stop Capturing" button on the IDS interface.

Q: How do I save captured data to a file?
A: Click the "Save to File" button on the IDS interface after stopping the capture.

Q: What information is displayed in the Capturing Information section?
A: It displays the number of packets, destination IP (Dst IP), source IP (Src IP), payload, protocol, timestamp, time to live (TTL), destination port (Dst Port), source port (Src Port), and service.

Q: How can I view and analyze the logs?
A: Click the "Open Log Analyzer" button to view and analyze the captured data and alerts.

Q: How do I add a malicious IP address to the rules?
A: Go to the "Rules" section, enter the IP address in the input field, and click the "Add IP" button.

Q: What does the Alerts Summary section show?
A: It displays alerts generated based on the analysis of captured packets, including the severity and description of the detected threats.

Q: What is displayed in the Graphical Display section?
A: It shows a graphical representation of the protocol distribution of the captured packets.

Q: How can I search through the captured data?
A: Use the search bar on the IDS interface to filter specific information within the captured data.

Q: What does the "Back" button do in various sections?
A: It returns you to the previous screen or the main dashboard, depending on your current location in the application.

Q: How can I regularly update the IDS rules?
A: You can manually add new IP addresses in the "Rules" section or integrate the IDS with an external rules database for automatic updates.

Q: Can I view the type of traffic on my network?
A: Yes, the protocol distribution graph in the Graphical Display section provides a quick overview of the types of traffic on your network.

Q: What should I do if I encounter a detected threat?
A: Review the alert details in the Alerts Summary section and take appropriate action to mitigate the threat, such as blocking the malicious IP or investigating the source of the threat.

Q: How do I return to the main dashboard from any screen?
A: Click the "Home" button to return to the main dashboard of the application.

This Q&A section covers common questions and should help you navigate and use SPIDAZ IDS effectively. If you have further questions or issues, consult the help section within the application or contact support.
"""

# Insert questionsandanswerscontent into the Text widget
questionsandanswers_text.config(state=tk.NORMAL)
questionsandanswers_text.insert(tk.END, user_guide_content)
questionsandanswers_text.config(state=tk.DISABLED)


root.mainloop()
