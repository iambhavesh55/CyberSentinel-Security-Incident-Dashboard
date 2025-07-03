"""
File monitoring for real-time log collection
"""
import time
from pathlib import Path
from typing import Callable, Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.core.logger import logger

class LogFileHandler(FileSystemEventHandler):
    """Handle file system events for log files"""
    
    def __init__(self, callback: Callable[[str], None]):
        self.callback = callback
        self.processed_files = set()
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(('.log', '.txt')):
            if event.src_path not in self.processed_files:
                logger.info(f"New log file detected: {event.src_path}")
                self.callback(event.src_path)
                self.processed_files.add(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(('.log', '.txt')):
            logger.info(f"Log file created: {event.src_path}")
            self.callback(event.src_path)

class LogFileMonitor:
    """Monitor directories for new log files"""
    
    def __init__(self, directories: list, callback: Callable[[str], None]):
        self.directories = directories
        self.callback = callback
        self.observer = Observer()
        self.is_running = False
    
    def start_monitoring(self):
        """Start monitoring directories"""
        logger.info("Starting log file monitoring...")
        
        handler = LogFileHandler(self.callback)
        
        for directory in self.directories:
            if Path(directory).exists():
                self.observer.schedule(handler, directory, recursive=True)
                logger.info(f"Monitoring directory: {directory}")
            else:
                logger.warning(f"Directory not found: {directory}")
        
        self.observer.start()
        self.is_running = True
        
        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop monitoring directories"""
        logger.info("Stopping log file monitoring...")
        self.observer.stop()
        self.observer.join()
        self.is_running = False