"""
CyberSentinel: Security Incident Dashboard
Main entry point for the application
"""
import argparse
import sys
from pathlib import Path
from src.core.logger import logger
from src.core.config import config
from src.data_collection.sample_generator import SecurityLogGenerator
from src.data_collection.log_parser import LogParser
from src.data_collection.file_monitor import LogFileMonitor

def setup_directories():
    """Create necessary directories"""
    directories = [
        "data/raw_logs",
        "data/processed_logs", 
        "data/sample_data",
        "logs",
        "config"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    logger.info("Directory structure created successfully")

def generate_sample_data():
    """Generate sample security data"""
    logger.info("Starting sample data generation...")
    generator = SecurityLogGenerator()
    stats = generator.save_sample_data()
    
    logger.info("Sample data generation completed:")
    for data_type, count in stats.items():
        logger.info(f"  {data_type}: {count} entries")

def parse_logs(log_directory: str):
    """Parse logs from directory"""
    logger.info(f"Parsing logs from directory: {log_directory}")
    parser = LogParser()
    
    log_dir = Path(log_directory)
    if not log_dir.exists():
        logger.error(f"Log directory not found: {log_directory}")
        return
    
    log_files = list(log_dir.glob("*.log")) + list(log_dir.glob("*.txt"))
    
    for log_file in log_files:
        logger.info(f"Processing file: {log_file}")
        parsed_data = parser.parse_log_file(str(log_file))
        
        if parsed_data:
            # Save parsed data
            output_file = Path("data/processed_logs") / f"{log_file.stem}_parsed.json"
            import json
            with open(output_file, 'w') as f:
                json.dump(parsed_data, f, indent=2)
            
            logger.info(f"Parsed data saved to: {output_file}")

def monitor_logs(directories: list):
    """Monitor directories for new log files"""
    def process_new_file(file_path: str):
        logger.info(f"Processing new file: {file_path}")
        parser = LogParser()
        parsed_data = parser.parse_log_file(file_path)
        
        if parsed_data:
            logger.info(f"Successfully processed {len(parsed_data)} log entries")
    
    monitor = LogFileMonitor(directories, process_new_file)
    monitor.start_monitoring()

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description="CyberSentinel: Security Incident Dashboard")
    parser.add_argument("--setup", action="store_true", help="Setup directory structure")
    parser.add_argument("--generate-data", action="store_true", help="Generate sample data")
    parser.add_argument("--parse-logs", type=str, help="Parse logs from directory")
    parser.add_argument("--monitor", nargs="+", help="Monitor directories for new logs")
    parser.add_argument("--version", action="version", version="CyberSentinel 1.0.0")
    
    args = parser.parse_args()
    
    try:
        logger.info("Starting CyberSentinel...")
        
        if args.setup:
            setup_directories()
        
        if args.generate_data:
            generate_sample_data()
        
        if args.parse_logs:
            parse_logs(args.parse_logs)
        
        if args.monitor:
            monitor_logs(args.monitor)
        
        if not any(vars(args).values()):
            # Default behavior - setup and generate sample data
            logger.info("No specific command provided. Running setup and sample data generation...")
            setup_directories()
            generate_sample_data()
            
            # Parse the generated sample data
            parse_logs("data/sample_data")
            
            logger.info("CyberSentinel Stage 1 setup completed successfully!")
            logger.info("Next steps:")
            logger.info("1. Review generated sample data in data/sample_data/")
            logger.info("2. Check parsed data in data/processed_logs/")
            logger.info("3. Proceed to Stage 2 for Elasticsearch integration")
    
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()