import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import time

class FileExtensionChanger:
    def __init__(self, root):
        self.root = root
        self.folder_path = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Ready")
        
        # Extension mappings
        self.forward_mapping = {
            ".jpg": ".txt",
            ".jpeg": ".docx", 
            ".png": ".xlsx",
            ".heic": ".pdf",
            ".mp3": ".ppt",
            ".mkv": ".css",
            ".mov": ".html",
            ".mp4": ".js",
            ".raw": ".php"
        }
        
        self.reverse_mapping = {v: k for k, v in self.forward_mapping.items()}
        
        self.setup_gui()
    
    def setup_gui(self):
        self.root.title("🔄 Advanced File Extension Changer")
        self.root.geometry("600x500")
        self.root.configure(bg="#2c3e50")
        self.root.resizable(True, False)
        
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom colors
        style.configure("Title.TLabel", 
                       background="#2c3e50", 
                       foreground="#ecf0f1", 
                       font=("Arial", 16, "bold"))
        
        style.configure("Subtitle.TLabel",
                       background="#2c3e50",
                       foreground="#bdc3c7",
                       font=("Arial", 10))
        
        style.configure("Custom.TButton",
                       padding=(20, 10),
                       font=("Arial", 10, "bold"))
        
        style.configure("Warning.TButton",
                       padding=(20, 10),
                       font=("Arial", 10, "bold"))
        
        style.map("Custom.TButton",
                 background=[("active", "#3498db"), ("!active", "#2980b9")],
                 foreground=[("active", "white"), ("!active", "white")])
        
        style.map("Warning.TButton",
                 background=[("active", "#e67e22"), ("!active", "#f39c12")],
                 foreground=[("active", "white"), ("!active", "white")])
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#2c3e50", padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="File Extension Changer", style="Title.TLabel")
        title_label.pack(pady=(0, 5))
        
        subtitle_label = ttk.Label(main_frame, 
                                  text="Convert media files to document extensions and vice versa", 
                                  style="Subtitle.TLabel")
        subtitle_label.pack(pady=(0, 20))
        
        # Folder selection frame
        folder_frame = tk.LabelFrame(main_frame, text="📁 Folder Selection", 
                                   bg="#34495e", fg="#ecf0f1", 
                                   font=("Arial", 12, "bold"), padx=10, pady=10)
        folder_frame.pack(fill="x", pady=(0, 20))
        
        # Folder path display
        path_frame = tk.Frame(folder_frame, bg="#34495e")
        path_frame.pack(fill="x", pady=5)
        
        self.path_entry = tk.Entry(path_frame, textvariable=self.folder_path, 
                                  font=("Arial", 10), state="readonly",
                                  bg="#ecf0f1", fg="#2c3e50")
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        browse_btn = tk.Button(path_frame, text="📂 Browse", 
                              command=self.select_folder,
                              bg="#3498db", fg="white", font=("Arial", 10, "bold"),
                              relief="flat", padx=20, pady=5,
                              cursor="hand2")
        browse_btn.pack(side="right")
        
        # Extension mapping info
        info_frame = tk.LabelFrame(main_frame, text="📋 Extension Mappings", 
                                 bg="#34495e", fg="#ecf0f1",
                                 font=("Arial", 12, "bold"), padx=10, pady=10)
        info_frame.pack(fill="x", pady=(0, 20))
        
        # Create two columns for mappings
        mapping_frame = tk.Frame(info_frame, bg="#34495e")
        mapping_frame.pack(fill="x")
        
        left_col = tk.Frame(mapping_frame, bg="#34495e")
        left_col.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        right_col = tk.Frame(mapping_frame, bg="#34495e")
        right_col.pack(side="right", fill="x", expand=True)
        
        # Left column mappings
        for i, (old, new) in enumerate(list(self.forward_mapping.items())[:5]):
            mapping_text = f"{old} → {new}"
            tk.Label(left_col, text=mapping_text, bg="#34495e", fg="#bdc3c7",
                    font=("Courier", 9)).pack(anchor="w", pady=1)
        
        # Right column mappings
        for old, new in list(self.forward_mapping.items())[5:]:
            mapping_text = f"{old} → {new}"
            tk.Label(right_col, text=mapping_text, bg="#34495e", fg="#bdc3c7",
                    font=("Courier", 9)).pack(anchor="w", pady=1)
        
        # Action buttons frame
        action_frame = tk.LabelFrame(main_frame, text="🔧 Actions", 
                                   bg="#34495e", fg="#ecf0f1",
                                   font=("Arial", 12, "bold"), padx=10, pady=10)
        action_frame.pack(fill="x", pady=(0, 20))
        
        button_frame = tk.Frame(action_frame, bg="#34495e")
        button_frame.pack(pady=10)
        
        # Convert button
        self.convert_btn = tk.Button(button_frame, text="🔄 Convert Extensions",
                                   command=self.perform_conversion,
                                   bg="#27ae60", fg="white", font=("Arial", 11, "bold"),
                                   relief="flat", padx=25, pady=10,
                                   cursor="hand2")
        self.convert_btn.pack(side="left", padx=10)
        
        # Reverse button  
        self.reverse_btn = tk.Button(button_frame, text="⏪ Reverse Extensions",
                                   command=self.perform_reverse,
                                   bg="#e74c3c", fg="white", font=("Arial", 11, "bold"),
                                   relief="flat", padx=25, pady=10,
                                   cursor="hand2")
        self.reverse_btn.pack(side="right", padx=10)
        
        # Progress frame
        progress_frame = tk.LabelFrame(main_frame, text="📊 Progress", 
                                     bg="#34495e", fg="#ecf0f1",
                                     font=("Arial", 12, "bold"), padx=10, pady=10)
        progress_frame.pack(fill="x", pady=(0, 10))
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                          maximum=100, style="TProgressbar")
        self.progress_bar.pack(fill="x", pady=(5, 10))
        
        # Status label
        self.status_label = tk.Label(progress_frame, textvariable=self.status_var,
                                   bg="#34495e", fg="#bdc3c7", font=("Arial", 10))
        self.status_label.pack()
        
        # Warning label
        warning_frame = tk.Frame(main_frame, bg="#2c3e50")
        warning_frame.pack(fill="x", pady=10)
        
        warning_text = ("⚠️  WARNING: This tool changes file extensions only. "
                       "It does NOT convert file formats. Use at your own risk!")
        self.warning_label = tk.Label(warning_frame, text=warning_text,
                                    bg="#e74c3c", fg="white", font=("Arial", 9, "bold"),
                                    wraplength=550, justify="center", padx=10, pady=8)
        self.warning_label.pack(fill="x")
    
    def select_folder(self):
        """Open folder selection dialog"""
        folder_selected = filedialog.askdirectory(title="Select folder containing files")
        if folder_selected:
            self.folder_path.set(folder_selected)
            self.status_var.set(f"Selected: {os.path.basename(folder_selected)}")
    
    def check_files_exist(self, folder_path, extensions):
        """Check if any files with specified extensions exist"""
        try:
            files = os.listdir(folder_path)
            return any(filename.lower().endswith(ext) for filename in files for ext in extensions)
        except PermissionError:
            messagebox.showerror("Permission Error", 
                               "Cannot access the selected folder. Check permissions.")
            return False
        except Exception as e:
            messagebox.showerror("Error", f"Error checking files: {str(e)}")
            return False
    
    def show_confirmation_dialog(self, action_type, file_count):
        """Show confirmation dialog before performing actions"""
        action_word = "convert" if action_type == "convert" else "reverse"
        message = (f"This will {action_word} {file_count} file extensions.\n\n"
                  f"⚠️  WARNING: This only changes extensions, not file formats!\n"
                  f"Files may become unreadable by some applications.\n\n"
                  f"Do you want to continue?")
        
        return messagebox.askyesno("Confirm Action", message, icon="warning")
    
    def process_files(self, folder_path, mapping, action_type):
        """Process files with progress updates"""
        try:
            files = [f for f in os.listdir(folder_path) 
                    if os.path.splitext(f)[1].lower() in mapping]
            
            if not files:
                self.status_var.set("No matching files found")
                return False
            
            # Show confirmation dialog
            if not self.show_confirmation_dialog(action_type, len(files)):
                self.status_var.set("Operation cancelled by user")
                return False
            
            total_files = len(files)
            processed = 0
            errors = []
            
            for filename in files:
                try:
                    file_path = os.path.join(folder_path, filename)
                    base, ext = os.path.splitext(file_path)
                    new_extension = mapping[ext.lower()]
                    new_file_path = base + new_extension
                    
                    # Check if target file already exists
                    if os.path.exists(new_file_path):
                        errors.append(f"Target exists: {os.path.basename(new_file_path)}")
                        continue
                    
                    os.rename(file_path, new_file_path)
                    processed += 1
                    
                    # Update progress
                    progress = (processed / total_files) * 100
                    self.progress_var.set(progress)
                    self.status_var.set(f"Processing... ({processed}/{total_files})")
                    self.root.update_idletasks()
                    
                    time.sleep(0.1)  # Small delay for visual feedback
                    
                except Exception as e:
                    errors.append(f"Error with {filename}: {str(e)}")
            
            # Show results
            if errors:
                error_message = "Some files could not be processed:\n\n" + "\n".join(errors[:10])
                if len(errors) > 10:
                    error_message += f"\n... and {len(errors) - 10} more errors"
                messagebox.showwarning("Partial Success", 
                                     f"Processed {processed} files successfully.\n\n{error_message}")
            else:
                messagebox.showinfo("Success", f"Successfully processed {processed} files!")
            
            self.status_var.set(f"Completed: {processed} files processed")
            return True
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error occurred")
            return False
        finally:
            # Reset progress bar
            self.progress_var.set(0)
            # Re-enable buttons
            self.convert_btn.config(state="normal")
            self.reverse_btn.config(state="normal")
    
    def perform_conversion(self):
        """Convert extensions in a separate thread"""
        folder = self.folder_path.get()
        if not folder:
            messagebox.showwarning("No Folder", "Please select a folder first.")
            return
        
        if not os.path.exists(folder):
            messagebox.showerror("Invalid Path", "The selected folder no longer exists.")
            return
        
        # Disable buttons during processing
        self.convert_btn.config(state="disabled")
        self.reverse_btn.config(state="disabled")
        
        # Run in separate thread to prevent GUI freezing
        thread = threading.Thread(target=self.process_files, 
                                args=(folder, self.forward_mapping, "convert"))
        thread.daemon = True
        thread.start()
    
    def perform_reverse(self):
        """Reverse extensions in a separate thread"""
        folder = self.folder_path.get()
        if not folder:
            messagebox.showwarning("No Folder", "Please select a folder first.")
            return
        
        if not os.path.exists(folder):
            messagebox.showerror("Invalid Path", "The selected folder no longer exists.")
            return
        
        # Disable buttons during processing
        self.convert_btn.config(state="disabled") 
        self.reverse_btn.config(state="disabled")
        
        # Run in separate thread to prevent GUI freezing
        thread = threading.Thread(target=self.process_files,
                                args=(folder, self.reverse_mapping, "reverse"))
        thread.daemon = True
        thread.start()

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = FileExtensionChanger(root)
    
    # Center the window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Add icon handling (optional)
    try:
        # If you have an icon file, uncomment the next line
        # root.iconbitmap('icon.ico')
        pass
    except:
        pass
    
    root.mainloop()

if __name__ == "__main__":
    main()