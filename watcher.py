import os
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class DLPFileHandler(FileSystemEventHandler):
    """
    Listens for filesystem modifications and creations.
    Triggers the scan callback for new/changed files, skipping 
    directories, quarantine folders, and audit logs.
    """
    def __init__(self, callback, quarantine_dir_name="quarantine", audit_filename="datashield_audit.log"):
        super().__init__()
        self.callback = callback
        self.quarantine_dir_name = quarantine_dir_name
        self.audit_filename = audit_filename

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_event(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._handle_event(event.src_path)

    def _handle_event(self, filepath: str):
        path_obj = Path(filepath).resolve()
        
        # Guard: Ignore quarantine folders, sidecar files, and audit logs to avoid feedback loops
        parts = path_obj.parts
        if self.quarantine_dir_name in parts:
            return
        if path_obj.name.endswith(".quarantine_info"):
            return
        if path_obj.name == self.audit_filename:
            return
            
        # Trigger scanner callback
        self.callback(str(path_obj))


class DLPWatcher:
    """
    Orchestrates the watchdog observer thread to monitor a target directory.
    """
    def __init__(self, target_dir: str, callback, quarantine_name="quarantine", audit_name="datashield_audit.log"):
        self.target_dir = os.path.abspath(target_dir)
        self.callback = callback
        self.handler = DLPFileHandler(callback, quarantine_name, audit_name)
        self.observer = Observer()

    def start(self):
        """Starts background file monitoring."""
        self.observer.schedule(self.handler, self.target_dir, recursive=True)
        self.observer.start()

    def stop(self):
        """Terminates file monitoring observer."""
        self.observer.stop()
        self.observer.join()
