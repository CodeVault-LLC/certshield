# CertShield

CertShield is a real-time phishing domain detection system that monitors and analyzes newly created SSL/TLS certificates using the CaliDog certstream-go library. By identifying suspicious domain names and certificate attributes, CertShield helps identify potential phishing attacks and malicious websites.

## Features

- Real-Time Monitoring: Continuously tracks the stream of newly issued SSL/TLS certificates.
- Suspicious Domain Detection: Identifies domain names that exhibit patterns commonly associated with phishing sites.
- Certificate Analysis: Evaluates various certificate attributes to detect anomalies and potential security threats.
- Alert System: Generates alerts for identified suspicious certificates and domains.
- Logging: Supports both stdout logging and integration with Elastic for centralized logging and analysis.
- HTTP Filtering: Filter out non working domains and only analyze working domains.

## Integrations

- Elastic: Integration with Elastic allows for advanced logging, search, and analysis capabilities.
- Stdout Logging: Basic logging to standard output for simplicity and ease of use.

## Getting Started

### Prerequisites

- Golang 1.22 or later
- Elastic Stack (optional)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/codevault-llc/certshield.git
    cd certshield
   ```
2. Install dependencies:
   ```bash
   go mod download
   ```
3. Build the project:
   ```bash
    go build
   ```
4. Run the program:
   ```bash
   ./certshield
   ```

### Configuration

We use dotenv to manage environment variables. Create a `.env` file in the project root directory and add the following variables (see `.env.example` for an example):

```bash
# ElasticSearch URL (optional)
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_APIKEY=yourapikey
```

We do also allow for certain arguments when running the program:

```bash
Usage of ./certshield:
  -ping (default false)
         Ping the websites to see if they are working
```

## Disclaimer

This project is intended for educational purposes only. The author is not responsible for any misuse or damage caused by this program. Use at your own risk.

This project is in the early stages of development and has not been thoroughly tested. If you encounter any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request. Your feedback is greatly appreciated!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [CaliDog](https://certstream.calidog.io/) for the certstream-go library.
- [Elastic](https://www.elastic.co/) for the Elastic Stack.
