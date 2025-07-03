# CyberSentinel: Security Incident Dashboard

A comprehensive Security Operations Center (SOC) dashboard for threat detection, log analysis, and security incident management.

## Project Overview

CyberSentinel is a professional-level cybersecurity project that simulates a SOC dashboard using Python, Elasticsearch, and Kibana. The project focuses on:

- **Log Data Collection & Parsing**: Multi-format log parsing with real-time monitoring
- **Threat Detection**: Advanced pattern recognition and anomaly detection
- **Data Visualization**: Interactive dashboards and security metrics
- **Incident Management**: Automated alerting and response workflows

## Project Structure

```
CyberSentinel/
├── config/
│   └── config.yaml              # Configuration settings
├── data/
│   ├── raw_logs/               # Raw log files
│   ├── processed_logs/         # Parsed and processed logs
│   └── sample_data/            # Generated sample data
├── logs/                       # Application logs
├── src/
│   ├── core/
│   │   ├── config.py           # Configuration management
│   │   └── logger.py           # Logging setup
│   ├── data_collection/
│   │   ├── log_parser.py       # Multi-format log parser
│   │   ├── sample_generator.py # Sample data generator
│   │   └── file_monitor.py     # Real-time file monitoring
│   └── utils/
│       └── data_validator.py   # Data validation utilities
├── main.py                     # Main application entry point
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```

## Stage 1: Log Data Collection & Project Setup ✅

### Features Implemented

1. **Multi-Format Log Parser**
   - Apache/Nginx access logs
   - Syslog format
   - Windows Event logs
   - Firewall logs
   - JSON and CSV formats
   - Auto-detection of log types

2. **Sample Data Generation**
   - Realistic security event simulation
   - Apache access logs with suspicious activity
   - Firewall logs with blocked/allowed traffic
   - Authentication logs with brute force attempts
   - Security events with various threat types

3. **Real-Time File Monitoring**
   - Watchdog-based file system monitoring
   - Automatic processing of new log files
   - Configurable monitoring directories

4. **Data Validation & Enrichment**
   - IP address validation
   - Timestamp normalization
   - Risk score calculation
   - Data sanitization
   - Schema validation

5. **Configuration Management**
   - YAML-based configuration
   - Environment-specific settings
   - Elasticsearch connection parameters
   - Security threat indicators

## Installation & Setup

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Setup Directory Structure**
   ```bash
   python main.py --setup
   ```

3. **Generate Sample Data**
   ```bash
   python main.py --generate-data
   ```

4. **Parse Existing Logs**
   ```bash
   python main.py --parse-logs data/sample_data
   ```

5. **Monitor Directories for New Logs**
   ```bash
   python main.py --monitor data/raw_logs /var/log
   ```

## Usage Examples

### Basic Setup (Recommended for first run)
```bash
python main.py
```
This will:
- Create directory structure
- Generate sample security data
- Parse the generated data
- Prepare for Stage 2

### Parse Custom Log Files
```bash
python main.py --parse-logs /path/to/your/logs
```

### Real-Time Monitoring
```bash
python main.py --monitor /var/log/apache2 /var/log/auth.log
```

## Configuration

Edit `config/config.yaml` to customize:

- **Elasticsearch Settings**: Host, port, index configuration
- **Data Sources**: Log directories and file patterns
- **Security Parameters**: Threat indicators, suspicious ports
- **Monitoring**: Collection intervals and batch sizes

## Sample Data Generated

The system generates realistic sample data including:

- **1000 Apache Access Logs**: Normal and suspicious web traffic
- **500 Firewall Logs**: Network traffic with allow/deny decisions
- **200 Security Events**: Various attack types and severities
- **300 Authentication Logs**: Login attempts with failures

## Log Types Supported

| Log Type | Format | Auto-Detection | Sample Fields |
|----------|--------|----------------|---------------|
| Apache | Common Log Format | ✅ | IP, timestamp, method, URL, status |
| Nginx | Similar to Apache | ✅ | IP, timestamp, request, response |
| Syslog | RFC3164 | ✅ | Timestamp, hostname, process, message |
| Firewall | Custom format | ✅ | Source/dest IP, ports, action |
| JSON | Structured JSON | ✅ | All fields preserved |
| Windows Event | Event log format | ✅ | Event ID, level, message |

## Security Features

- **Threat Detection**: Pattern matching for common attacks
- **Risk Scoring**: Automated risk assessment for log entries
- **Data Sanitization**: Input validation and cleaning
- **IP Validation**: Proper IP address format checking
- **Timestamp Normalization**: Consistent time format handling

## Next Steps (Stage 2)

1. **Elasticsearch Integration**: Index parsed data
2. **Kibana Dashboards**: Create visualization dashboards
3. **Real-time Analytics**: Stream processing setup
4. **Alert Configuration**: Automated threat notifications

## Development Notes

- **Modular Architecture**: Clean separation of concerns
- **Extensible Parsers**: Easy to add new log formats
- **Configuration-Driven**: Minimal code changes for customization
- **Comprehensive Logging**: Full audit trail of operations
- **Error Handling**: Robust error recovery and reporting

## Contributing

This is a professional cybersecurity project. Follow these guidelines:

1. Maintain security best practices
2. Add comprehensive logging
3. Include data validation
4. Write clear documentation
5. Test with various log formats

## License

MIT License - See LICENSE file for details.

---

**CyberSentinel v1.0.0** - Professional SOC Dashboard Solution