import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class PhotoEncryptor:
    def __init__(self, root):
        self.root = root
        self.folder_path = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Ready")
        
        # Supported image/media extensions for encryption
        self.supported_extensions = {
    # Image formats
    ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".tif", ".webp", ".svg", ".ico", ".heic", ".heif",
    ".raw", ".cr2", ".nef", ".arw", ".dng", ".orf", ".rw2", ".pef", ".srw", ".x3f", ".raf", ".3fr",
    ".dcr", ".k25", ".kdc", ".erf", ".mef", ".mos", ".mrw", ".nrw", ".ptx", ".r3d", ".rwl", ".rwz",
    ".avif", ".jxl", ".jp2", ".jpx", ".j2k", ".pcx", ".tga", ".xbm", ".xpm", ".pbm", ".pgm", ".ppm",
    ".pnm", ".hdr", ".exr", ".dpx", ".cin", ".sgi", ".pic", ".psd", ".ai", ".eps", ".wmf", ".emf",
    
    # Video formats
    ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm", ".m4v", ".3gp", ".3g2", ".asf", ".rm",
    ".rmvb", ".vob", ".ogv", ".dv", ".ts", ".mts", ".m2ts", ".f4v", ".divx", ".xvid", ".mpg", ".mpeg",
    ".m1v", ".m2v", ".mpe", ".mp2", ".mpv", ".m4p", ".m4b", ".f4a", ".f4b", ".f4p", ".qt", ".movie",
    ".mjpeg", ".mjpg", ".yuv", ".y4m", ".rec", ".tod", ".mod", ".dat", ".vcd", ".svcd", ".dvr-ms",
    
    # Audio formats
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a", ".opus", ".aiff", ".au", ".ra", ".mid",
    ".midi", ".kar", ".rmi", ".ac3", ".dts", ".ape", ".mpc", ".tta", ".wv", ".spx", ".gsm", ".dss",
    ".msv", ".dvf", ".vox", ".aa", ".aax", ".act", ".aiff", ".alac", ".amr", ".awb", ".cda", ".dct",
    ".dss", ".flp", ".m4p", ".mmf", ".mp2", ".mpa", ".mpc", ".msv", ".oga", ".mogg", ".raw", ".sln",
    ".tak", ".tta", ".voc", ".vqf", ".w64", ".wma", ".wv", ".webm", ".3gp", ".aa3", ".at3", ".at9",
    
    # Document formats
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".txt",
    ".md", ".tex", ".latex", ".bib", ".wps", ".wpd", ".pages", ".numbers", ".key", ".pub", ".xps",
    ".oxps", ".djvu", ".djv", ".epub", ".mobi", ".azw", ".azw3", ".fb2", ".lit", ".pdb", ".tcr", ".tr2",
    ".tr3", ".opf", ".prc", ".lrf", ".lrx", ".cbr", ".cbz", ".cb7", ".cbt", ".cba", ".chm", ".hlp",
    
    # Spreadsheet specific
    ".csv", ".tsv", ".ods", ".xlsm", ".xlsb", ".xlt", ".xltx", ".xltm", ".xlam", ".xla", ".xlw",
    ".slk", ".dif", ".prn", ".dbf", ".wk1", ".wk3", ".wk4", ".wks", ".123", ".wq1", ".wb1", ".wb2",
    
    # Presentation specific
    ".odp", ".pps", ".ppsx", ".ppsm", ".potx", ".potm", ".pot", ".sxi", ".sti", ".dps", ".dp", ".sdd",
    
    # Web and markup
    ".html", ".htm", ".xhtml", ".xml", ".xsl", ".xslt", ".dtd", ".rss", ".atom", ".opml", ".rdf",
    ".owl", ".daisy", ".svg", ".mathml", ".mml", ".xaml", ".xul", ".mhtml", ".maff", ".webarchive",
    
    # Programming languages
    ".js", ".jsx", ".ts", ".tsx", ".json", ".json5", ".jsonl", ".css", ".scss", ".sass", ".less",
    ".php", ".py", ".rb", ".go", ".rs", ".java", ".c", ".cpp", ".cxx", ".cc", ".h", ".hpp", ".hxx",
    ".swift", ".kt", ".kts", ".m", ".mm", ".vb", ".vbs", ".pl", ".pm", ".sh", ".bash", ".zsh", ".fish",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".scala", ".clj", ".cljs", ".cljc", ".edn", ".hs",
    ".lhs", ".elm", ".purs", ".ml", ".mli", ".fs", ".fsi", ".fsx", ".fsscript", ".ex", ".exs", ".erl",
    ".hrl", ".lua", ".r", ".rmd", ".rnw", ".jl", ".nim", ".nims", ".d", ".dart", ".coffee", ".vue",
    ".svelte", ".astro", ".marko", ".riot", ".tag", ".mjs", ".cjs", ".esm", ".asm", ".s", ".nasm",
    ".gas", ".inc", ".def", ".rc", ".idl", ".proto", ".thrift", ".avro", ".capnp", ".fbs", ".pyi",
    
    # Configuration and data
    ".ini", ".cfg", ".conf", ".config", ".properties", ".yaml", ".yml", ".toml", ".ron", ".hjson",
    ".xml", ".plist", ".reg", ".inf", ".desktop", ".service", ".timer", ".socket", ".mount", ".automount",
    ".swap", ".target", ".path", ".slice", ".scope", ".env", ".dotenv", ".editorconfig", ".gitignore",
    ".gitattributes", ".gitmodules", ".dockerignore", ".eslintrc", ".prettierrc", ".babelrc", ".jshintrc",
    
    # Database
    ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dbf", ".gdb", ".fdb", ".odb", ".frm", ".myd",
    ".myi", ".ibd", ".pid", ".err", ".log", ".bin", ".idx", ".dat", ".bak", ".tmp", ".lock",
    
    # Archives and compression
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".lz", ".lzma", ".z", ".arj", ".ace", ".cab",
    ".lzh", ".lha", ".sit", ".sitx", ".sea", ".hqx", ".bin", ".uue", ".xxe", ".mime", ".b64", ".uu",
    ".jar", ".war", ".ear", ".sar", ".par", ".deb", ".rpm", ".pkg", ".dmg", ".iso", ".img", ".toast",
    ".vcd", ".cue", ".nrg", ".mdf", ".mds", ".cdi", ".b5t", ".b6t", ".bwt", ".ccd", ".clone", ".dao",
    ".tao", ".xcdx", ".gcd", ".gi", ".pdi", ".cdr", ".vhd", ".vhdx", ".vmdk", ".ova", ".ovf", ".qcow2",
    
    # Font files
    ".ttf", ".otf", ".woff", ".woff2", ".eot", ".pfb", ".pfm", ".afm", ".bdf", ".pcf", ".snf", ".ttc",
    ".dfont", ".suit", ".fon", ".fnt", ".abf", ".bmap", ".fea", ".fgd", ".fond", ".lwfn", ".odttf",
    ".pfa", ".pfb", ".pt3", ".sfd", ".t11", ".t42", ".ttx", ".ufo", ".vfb", ".woff", ".gsf",
    
    # CAD and 3D
    ".dwg", ".dxf", ".dwf", ".dgn", ".3ds", ".max", ".blend", ".obj", ".fbx", ".dae", ".x3d", ".wrl",
    ".ply", ".stl", ".off", ".3mf", ".amf", ".step", ".stp", ".iges", ".igs", ".sat", ".brep", ".prt",
    ".par", ".asm", ".catpart", ".catproduct", ".cgr", ".3dxml", ".model", ".session", ".dlv3", ".exp",
    ".jt", ".pv", ".xv3", ".xv0", ".neu", ".unv", ".bdf", ".dat", ".nas", ".fem", ".inp", ".cdb",
    
    # Game files
    ".unity", ".unitypackage", ".prefab", ".mat", ".asset", ".meta", ".scene", ".anim", ".controller",
    ".overrideController", ".mask", ".fbx", ".mb", ".ma", ".mel", ".pyc", ".pyo", ".pk3", ".pak",
    ".wad", ".bsp", ".mdl", ".smd", ".qc", ".vtf", ".vmt", ".mdx", ".mdl", ".ani", ".seq", ".act",
    ".d2v", ".dem", ".hdr", ".lmp", ".sav", ".sg0", ".sg1", ".sg2", ".sg3", ".sg4", ".sg5", ".sg6",
    
    # Scientific and specialized
    ".mat", ".fits", ".fts", ".fit", ".hdf", ".h5", ".hdf5", ".nc", ".cdf", ".nii", ".dcm", ".dicom",
    ".analyze", ".hdr", ".img", ".nrrd", ".nhdr", ".mgh", ".mgz", ".mnc", ".xnat", ".par", ".rec",
    ".edf", ".mrc", ".dm3", ".dm4", ".ser", ".emi", ".tvips", ".msa", ".msi", ".bcf", ".ctf",
    
    # Backup and temporary
    ".bak", ".backup", ".old", ".orig", ".save", ".tmp", ".temp", ".cache", ".swap", ".~", ".autosave",
    ".recover", ".wbk", ".xlk", ".ppt_", ".doc_", ".xls_", ".mdb_", ".ldb", ".mdw", ".mda", ".mde",
    
    # System and executable
    ".exe", ".msi", ".app", ".deb", ".rpm", ".pkg", ".dmg", ".run", ".bin", ".com", ".scr", ".pif",
    ".cmd", ".bat", ".sh", ".bash", ".zsh", ".fish", ".csh", ".ksh", ".tcsh", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc", ".cpl", ".scf", ".lnk", ".url", ".webloc",
    
    # Email and communication
    ".eml", ".msg", ".pst", ".ost", ".olm", ".mbox", ".mbx", ".dbx", ".emlx", ".rge", ".pab", ".wab",
    ".vcf", ".vcard", ".ics", ".ical", ".ifb", ".vcs", ".htt", ".contact", ".group", ".p7s", ".p7m",
    
    # Certificate and security
    ".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".p12", ".pfx", ".jks", ".keystore", ".truststore",
    ".key", ".pub", ".gpg", ".asc", ".sig", ".p7s", ".p7m", ".tsk", ".csr", ".req", ".spc", ".pvk",
    
    # Misc specialized
    ".torrent", ".metalink", ".magnet", ".nzb", ".srt", ".vtt", ".ass", ".ssa", ".sub", ".idx", ".sup",
    ".usf", ".ssf", ".psb", ".stl", ".3mf", ".amf", ".gcode", ".nc", ".tap", ".mpf", ".cnc", ".eia",
    ".mime", ".uuencoded", ".b64", ".uu", ".xxe", ".hqx", ".binhex"
}
        
        # Encrypted file extension
        self.encrypted_extension = ".encrypted"
        
        self.setup_gui()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def get_all_files(self, folder_path, action_type):
        """Get all files recursively from folder and subfolders"""
        all_files = []
        
        try:
            for root_dir, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root_dir, file)
                    
                    if action_type == "encrypt":
                        # Check if file has supported extension
                        _, ext = os.path.splitext(file)
                        if ext.lower() in self.supported_extensions:
                            all_files.append(file_path)
                    else:  # decrypt
                        # Check if file has encrypted extension
                        if file.endswith(self.encrypted_extension):
                            all_files.append(file_path)
            
        except Exception as e:
            print(f"Error scanning directory: {str(e)}")
        
        return all_files
    
    def encrypt_file(self, file_path: str, password: str) -> bool:
        """Encrypt a single file"""
        try:
            # Generate a random salt
            salt = os.urandom(16)
            
            # Derive key from password
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            
            # Read original file
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            # Store original extension for later decryption
            original_ext = os.path.splitext(file_path)[1]
            
            # Create metadata (original extension + encrypted data)
            metadata = {
                'original_ext': original_ext,
                'data': file_data
            }
            
            # Convert metadata to bytes (simple format: ext_length + ext + data)
            ext_bytes = original_ext.encode('utf-8')
            ext_length = len(ext_bytes).to_bytes(4, byteorder='big')
            combined_data = ext_length + ext_bytes + file_data
            
            # Encrypt the combined data
            encrypted_data = fernet.encrypt(combined_data)
            
            # Create new file path with .encrypted extension
            base_path = os.path.splitext(file_path)[0]
            encrypted_path = base_path + self.encrypted_extension
            
            # Write salt + encrypted data to new file
            with open(encrypted_path, 'wb') as encrypted_file:
                encrypted_file.write(salt + encrypted_data)
            
            # Remove original file
            os.remove(file_path)
            
            return True
            
        except Exception as e:
            print(f"Error encrypting {file_path}: {str(e)}")
            return False
    
    def decrypt_file(self, encrypted_path: str, password: str) -> bool:
        """Decrypt a single file"""
        try:
            # Read encrypted file
            with open(encrypted_path, 'rb') as encrypted_file:
                file_content = encrypted_file.read()
            
            # Extract salt (first 16 bytes)
            salt = file_content[:16]
            encrypted_data = file_content[16:]
            
            # Derive key from password
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            
            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Extract original extension and file data
            ext_length = int.from_bytes(decrypted_data[:4], byteorder='big')
            original_ext = decrypted_data[4:4+ext_length].decode('utf-8')
            original_data = decrypted_data[4+ext_length:]
            
            # Create original file path
            base_path = os.path.splitext(encrypted_path)[0]
            original_path = base_path + original_ext
            
            # Write decrypted data to original file
            with open(original_path, 'wb') as original_file:
                original_file.write(original_data)
            
            # Remove encrypted file
            os.remove(encrypted_path)
            
            return True
            
        except Exception as e:
            print(f"Error decrypting {encrypted_path}: {str(e)}")
            return False
    
    def setup_gui(self):
        self.root.title("🔐 Files Encryption Tool")
        self.root.geometry("600x600")
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
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#2c3e50", padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Files Encryption Tool", style="Title.TLabel")
        title_label.pack(pady=(0, 5))
        
        subtitle_label = ttk.Label(main_frame, 
                                  text="Encrypt and decrypt your photos with password protection\n✨ Now includes subfolders!", 
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
        
        # File count display
        self.file_count_label = tk.Label(folder_frame, text="No folder selected",
                                        bg="#34495e", fg="#95a5a6", font=("Arial", 9))
        self.file_count_label.pack(pady=(5, 0))
        
        # Action buttons frame
        action_frame = tk.LabelFrame(main_frame, text="🔧 Actions", 
                                bg="#34495e", fg="#ecf0f1",
                                font=("Arial", 12, "bold"), padx=10, pady=10)
        action_frame.pack(fill="x", pady=(0, 20))

        button_frame = tk.Frame(action_frame, bg="#34495e")
        button_frame.pack(fill="x", pady=10)

        # Encrypt button
        self.encrypt_btn = tk.Button(button_frame, text="🔒 ENCRYPT FILES",
                                command=self.perform_encryption,
                                bg="#27ae60", fg="white", font=("Arial", 12, "bold"),
                                relief="flat", padx=30, pady=15,
                                cursor="hand2")
        self.encrypt_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))

        # Decrypt button  
        self.decrypt_btn = tk.Button(button_frame, text="🔓 DECRYPT FILES",
                                command=self.perform_decryption,
                                bg="#e74c3c", fg="white", font=("Arial", 12, "bold"),
                                relief="flat", padx=30, pady=15,
                                cursor="hand2")
        self.decrypt_btn.pack(side="right", fill="x", expand=True, padx=(5, 0))
                
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
        
        # Security info
        security_frame = tk.Frame(main_frame, bg="#2c3e50")
        security_frame.pack(fill="x", pady=10)
        
        security_text = ("🔐 Uses AES-256 encryption with PBKDF2 key derivation (100,000 iterations)\n"
                        "🔄 Processes all files in selected folder AND subfolders\n"
                        "Strong passwords recommended for maximum security!")
        self.security_label = tk.Label(security_frame, text=security_text,
                                     bg="#27ae60", fg="white", font=("Arial", 9, "bold"),
                                     wraplength=550, justify="center", padx=10, pady=8)
        self.security_label.pack(fill="x")
    
    def update_status(self, message):
        """Thread-safe status update"""
        self.status_var.set(message)
    
    def update_progress(self, value):
        """Thread-safe progress update"""
        self.progress_var.set(value)
    
    def reset_progress(self):
        """Thread-safe progress reset"""
        self.progress_var.set(0)
    
    def enable_buttons(self):
        """Thread-safe button enable"""
        self.encrypt_btn.config(state="normal")
        self.decrypt_btn.config(state="normal")
    
    def show_info(self, title, message):
        """Thread-safe info dialog"""
        messagebox.showinfo(title, message)
    
    def show_warning(self, title, message):
        """Thread-safe warning dialog"""
        messagebox.showwarning(title, message)
    
    def show_error(self, title, message):
        """Thread-safe error dialog"""
        messagebox.showerror(title, message)
    
    def update_file_count(self, folder_path):
        """Update file count display"""
        try:
            encrypt_files = self.get_all_files(folder_path, "encrypt")
            decrypt_files = self.get_all_files(folder_path, "decrypt")
            
            count_text = f"📁 Found: {len(encrypt_files)} files to encrypt, {len(decrypt_files)} encrypted files"
            if len(encrypt_files) > 0 or len(decrypt_files) > 0:
                count_text += " (including subfolders)"
            
            self.file_count_label.config(text=count_text, fg="#3498db")
        except Exception as e:
            self.file_count_label.config(text="Error scanning folder", fg="#e74c3c")
    
    def select_folder(self):
        """Open folder selection dialog"""
        try:
            folder_selected = filedialog.askdirectory(title="Select folder containing files")
            if folder_selected:
                self.folder_path.set(folder_selected)
                self.status_var.set(f"Selected: {os.path.basename(folder_selected)}")
                self.update_file_count(folder_selected)
        except Exception as e:
            messagebox.showerror("Error", f"Error selecting folder: {str(e)}")
    
    def get_password(self, action_type):
        """Get password from user"""
        try:
            title = f"Password for {action_type.title()}"
            prompt = f"Enter password to {action_type} files:"
            
            password = simpledialog.askstring(title, prompt, show='*')
            
            if not password:
                return None
            
            if len(password) < 6:
                messagebox.showwarning("Weak Password", 
                                     "Password should be at least 6 characters long for better security.")
            
            # Confirm password for encryption
            if action_type == "encrypt":
                confirm = simpledialog.askstring(title, "Confirm password:", show='*')
                if password != confirm:
                    messagebox.showerror("Password Mismatch", "Passwords do not match!")
                    return None
            
            return password
        except Exception as e:
            messagebox.showerror("Error", f"Error getting password: {str(e)}")
            return None
    
    def show_confirmation_dialog(self, action_type, files):
        """Show confirmation dialog before performing actions"""
        # Count files by directory for better overview
        dir_count = {}
        for file_path in files:
            dir_name = os.path.dirname(file_path)
            if dir_name not in dir_count:
                dir_count[dir_name] = 0
            dir_count[dir_name] += 1
        
        file_count = len(files)
        folder_count = len(dir_count)
        
        message = (f"This will {action_type} {file_count} files across {folder_count} folder(s).\n\n"
                  f"{'⚠️  Original files will be deleted after encryption!' if action_type == 'encrypt' else '🔓 Encrypted files will be deleted after decryption!'}\n\n"
                  f"Folders affected:\n")
        
        # Show first few directories
        for i, (dir_path, count) in enumerate(list(dir_count.items())[:5]):
            rel_path = os.path.relpath(dir_path, self.folder_path.get())
            if rel_path == ".":
                rel_path = "(root folder)"
            message += f"• {rel_path}: {count} file(s)\n"
        
        if len(dir_count) > 5:
            message += f"• ... and {len(dir_count) - 5} more folders\n"
        
        message += f"\nMake sure you remember your password!\n\nDo you want to continue?"
        
        return messagebox.askyesno("Confirm Action", message, icon="warning")
    
    def process_files(self, folder_path, action_type, password):
        """Process files with progress updates"""
        try:
            # Get all files recursively
            all_files = self.get_all_files(folder_path, action_type)
            
            if not all_files:
                self.root.after(0, self.update_status, f"No files found for {action_type}ion")
                return False
            
            # Show confirmation dialog
            if not self.show_confirmation_dialog(action_type, all_files):
                self.root.after(0, self.update_status, "Operation cancelled by user")
                return False
            
            total_files = len(all_files)
            processed = 0
            errors = []
            
            # Process function based on action type
            process_func = self.encrypt_file if action_type == "encrypt" else self.decrypt_file
            
            for file_path in all_files:
                try:
                    # Update status with current file being processed
                    rel_path = os.path.relpath(file_path, folder_path)
                    self.root.after(0, self.update_status, f"Processing: {rel_path}")
                    
                    success = process_func(file_path, password)
                    
                    if success:
                        processed += 1
                    else:
                        errors.append(f"Failed to process: {rel_path}")
                    
                    # Update progress
                    progress = ((processed + len(errors)) / total_files) * 100
                    self.root.after(0, self.update_progress, progress)
                    
                    time.sleep(0.05)  # Small delay for visual feedback
                    
                except Exception as e:
                    rel_path = os.path.relpath(file_path, folder_path)
                    errors.append(f"Error with {rel_path}: {str(e)}")
            
            # Show results
            if errors:
                error_message = f"Some files could not be processed:\n\n" + "\n".join(errors[:10])
                if len(errors) > 10:
                    error_message += f"\n... and {len(errors) - 10} more errors"
                self.root.after(0, self.show_warning, "Partial Success", 
                              f"Processed {processed} files successfully.\n\n{error_message}")
            else:
                self.root.after(0, self.show_info, "Success", 
                              f"Successfully {action_type}ed {processed} files from {len(set(os.path.dirname(f) for f in all_files))} folder(s)!")
            
            self.root.after(0, self.update_status, f"Completed: {processed} files {action_type}ed")
            
            # Update file count after processing
            self.root.after(100, lambda: self.update_file_count(folder_path))
            
            return True
            
        except Exception as e:
            error_msg = f"An error occurred: {str(e)}"
            self.root.after(0, self.show_error, "Error", error_msg)
            self.root.after(0, self.update_status, "Error occurred")
            return False
        finally:
            # Reset progress bar and re-enable buttons (thread-safe)
            self.root.after(0, self.reset_progress)
            self.root.after(0, self.enable_buttons)
    
    def perform_encryption(self):
        """Encrypt files in a separate thread"""
        folder = self.folder_path.get()
        if not folder:
            messagebox.showwarning("No Folder", "Please select a folder first.")
            return
        
        if not os.path.exists(folder):
            messagebox.showerror("Invalid Path", "The selected folder no longer exists.")
            return
        
        password = self.get_password("encrypt")
        if not password:
            return
        
        # Disable buttons during processing
        self.encrypt_btn.config(state="disabled")
        self.decrypt_btn.config(state="disabled")
        
        # Run in separate thread to prevent GUI freezing
        thread = threading.Thread(target=self.process_files, 
                                args=(folder, "encrypt", password))
        thread.daemon = True
        thread.start()
    
    def perform_decryption(self):
        """Decrypt files in a separate thread"""
        folder = self.folder_path.get()
        if not folder:
            messagebox.showwarning("No Folder", "Please select a folder first.")
            return
        
        if not os.path.exists(folder):
            messagebox.showerror("Invalid Path", "The selected folder no longer exists.")
            return
        
        password = self.get_password("decrypt")
        if not password:
            return
        
        # Disable buttons during processing
        self.encrypt_btn.config(state="disabled") 
        self.decrypt_btn.config(state="disabled")
        
        # Run in separate thread to prevent GUI freezing
        thread = threading.Thread(target=self.process_files,
                                args=(folder, "decrypt", password))
        thread.daemon = True
        thread.start()

def main():
    """Main function to run the application"""
    try:
        # Check if cryptography module is installed
        import cryptography
    except ImportError:
        import subprocess
        import sys
        
        print("Installing required cryptography module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
        print("Installation complete! Please restart the application.")
        return
    
    root = tk.Tk()
    app = PhotoEncryptor(root)
    
    # Center the window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()