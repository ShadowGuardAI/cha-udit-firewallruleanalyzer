#!/usr/bin/env python3

import argparse
import subprocess
import re
import logging
import json
import yaml
from jsonpath_ng import jsonpath, parse
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FirewallRuleAnalyzer:
    """
    Analyzes firewall rules to identify overly permissive or redundant rules.
    Supports iptables, firewalld, and Windows Firewall.  Also supports
    auditing system and application configurations against established
    security baselines (e.g., CIS benchmarks).
    """

    def __init__(self, config_file=None):
        """
        Initializes the FirewallRuleAnalyzer.
        :param config_file: Path to the configuration file (YAML or JSON).  Optional.
        """
        self.config = {}
        if config_file:
            try:
                self.load_config(config_file)
            except Exception as e:
                logging.error(f"Error loading configuration file: {e}")
                raise

    def load_config(self, config_file):
        """
        Loads the configuration from a YAML or JSON file.
        :param config_file: Path to the configuration file.
        """
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    self.config = yaml.safe_load(f)
                elif config_file.endswith('.json'):
                    self.config = json.load(f)
                else:
                    raise ValueError("Unsupported configuration file format.  Use YAML or JSON.")
            logging.info(f"Configuration loaded from {config_file}")
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {config_file}")
            raise
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            logging.error(f"Error parsing configuration file: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error loading configuration file: {e}")
            raise

    def get_firewall_rules(self, firewall_type):
        """
        Retrieves firewall rules based on the specified firewall type.
        :param firewall_type: The type of firewall (iptables, firewalld, windows).
        :return: A list of firewall rules.
        """
        try:
            if firewall_type == "iptables":
                result = subprocess.run(["iptables-save"], capture_output=True, text=True, check=True)
                rules = result.stdout.splitlines()
                logging.debug(f"iptables rules retrieved: {rules}")
                return rules
            elif firewall_type == "firewalld":
                result = subprocess.run(["firewall-cmd", "--list-all"], capture_output=True, text=True, check=True)
                rules = result.stdout.splitlines()
                logging.debug(f"firewalld rules retrieved: {rules}")
                return rules
            elif firewall_type == "windows":
                result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True, check=True)
                rules = result.stdout.splitlines()
                logging.debug(f"Windows Firewall rules retrieved: {rules}")
                return rules
            else:
                raise ValueError(f"Unsupported firewall type: {firewall_type}")
        except FileNotFoundError as e:
            logging.error(f"Firewall command not found: {e}")
            raise
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing firewall command: {e}")
            raise
        except Exception as e:
            logging.error(f"Error retrieving firewall rules: {e}")
            raise

    def analyze_rules(self, firewall_type):
        """
        Analyzes firewall rules for potential issues.
        :param firewall_type: The type of firewall being analyzed.
        :return: A list of findings (e.g., overly permissive rules, redundant rules).
        """
        rules = self.get_firewall_rules(firewall_type)
        findings = []

        if firewall_type == "iptables":
            # Example: Check for overly permissive rules (e.g., allowing all traffic to a specific port)
            for rule in rules:
                if "-A INPUT -p tcp --dport" in rule and "-j ACCEPT" in rule:
                    findings.append(f"Potential overly permissive rule: {rule}")
        elif firewall_type == "firewalld":
            # Example: Check for services that are exposed to all interfaces
            for rule in rules:
                if "services:" in rule and "interfaces:" not in rule:
                    findings.append(f"Potential overly exposed service: {rule}")
        elif firewall_type == "windows":
             # Example: check for allow all inbound rules
            for rule in rules:
                if "Direction: Inbound" in rule and "Action: Allow" in rule:
                   findings.append(f"Potential overly permissive rule: {rule}")

        # Check for redundant rules (example: duplicate rules) - very basic example
        seen_rules = set()
        for rule in rules:
            if rule in seen_rules:
                findings.append(f"Redundant rule found: {rule}")
            else:
                seen_rules.add(rule)

        #Configuration Hardening Audit based on configuration file
        if self.config:
            findings.extend(self.audit_configuration())

        return findings

    def audit_configuration(self):
        """
        Audits the system configuration against a security baseline defined in the configuration file.
        Uses jsonpath-ng to query the loaded configuration data.
        """
        findings = []
        for check in self.config.get("security_checks", []):
            description = check.get("description", "No description provided")
            jsonpath_expr = check.get("jsonpath", None)
            expected_value = check.get("expected_value", None)

            if not jsonpath_expr:
                logging.warning(f"Skipping check due to missing jsonpath: {description}")
                continue

            try:
                jsonpath_obj = parse(jsonpath_expr)
                results = jsonpath_obj.find(self.config) # Assuming you're auditing the configuration itself.  Adapt if auditing a different data source.

                if not results:
                    findings.append(f"Configuration check failed: {description} (No matching nodes)")
                else:
                   for result in results:
                        if result.value != expected_value:
                            findings.append(f"Configuration check failed: {description}.  Expected '{expected_value}', got '{result.value}'")

            except Exception as e:
                logging.error(f"Error evaluating jsonpath '{jsonpath_expr}': {e}")
                findings.append(f"Error evaluating configuration check: {description} ({e})")

        return findings

    def generate_report(self, findings):
        """
        Generates a report of the findings.
        :param findings: A list of findings.
        :return: A formatted report string.
        """
        report = "Firewall Rule Analysis Report:\n"
        if findings:
            for finding in findings:
                report += f"- {finding}\n"
        else:
            report += "No issues found.\n"
        return report

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    :return: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Firewall Rule Analyzer")
    parser.add_argument("-t", "--type", choices=["iptables", "firewalld", "windows"],
                        help="The type of firewall to analyze.", required=True)
    parser.add_argument("-c", "--config", help="Path to the configuration file (YAML or JSON).", required=False)
    parser.add_argument("-o", "--output", help="Path to the output file for the report.", required=False)

    return parser

def main():
    """
    The main function of the Firewall Rule Analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        analyzer = FirewallRuleAnalyzer(config_file=args.config)
        findings = analyzer.analyze_rules(args.type)
        report = analyzer.generate_report(findings)

        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write(report)
                print(f"Report saved to {args.output}")
                logging.info(f"Report saved to {args.output}")
            except Exception as e:
                print(f"Error writing report to file: {e}")
                logging.error(f"Error writing report to file: {e}")
        else:
            print(report)
            logging.info("Report printed to console.")

    except ValueError as e:
        print(f"Error: {e}")
        logging.error(str(e))
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        logging.exception("An unexpected error occurred.")


if __name__ == "__main__":
    main()

#Example usage:
# 1. Analyze iptables and print to console:  python3 main.py -t iptables
# 2. Analyze firewalld and save to report.txt: python3 main.py -t firewalld -o report.txt
# 3. Analyze iptables with config: python3 main.py -t iptables -c config.yaml
#
# Example config.yaml:
# security_checks:
#   - description: "Ensure password complexity is enabled"
#     jsonpath: "$.login.password_complexity"
#     expected_value: true
#
#   - description: "Ensure SSH is not using default port"
#     jsonpath: "$.ssh.port"
#     expected_value: 2222