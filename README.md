<h1 align="center">
  <br>
  <img src="logo/grab.png" alt="Grab Logo" width="100"> 
</h1>

<h4 align="center">Grab: Streamline Your Cybersecurity Workflow with Censys</h4>

Grab is a python tool designed to simplify the process of collecting target IP addresses from Censys, a powerful search engine for discovering internet-connected devices.

## Why Grab?

Collect candidate IPs for your security tests, then feed these hosts to tools like Jaeles, Nuclei, other CVE check tools, or open-source POC scripts.

## Getting Started

1. Installation:
   ```shell
   pip install censys
   ```
2. Censys API Credentials: Obtain your API ID and API Secret from the Censys website: https://censys-python.readthedocs.io/en/stable/quick-start.html and add them to your configuration.

## Crafting Censys Queries

- services.http.response.headers: (key: server and value: e\*mail)

- Target systems located in specific countries: `location.country: {Canada, Chile, Honduras, Mexico, "United States", Uruguay}`

- h.search(
  query=query, fields=["ip", "services.port", "services.service_name"]
  )

- services.service_name: HTTP

- Discover HTTP servers with a specific ETag value: `services.http.response.headers: (key: `Etag`and value.headers:`"6001043d.16d"`)`

- services.http.response.html_title: "your dashboard"

## Generate Queries with Censys GPT Tool

To generate queries, use this GPT tool created by Censys:

https://gpt.censys.io/

## Extend Grab's Functionality

To add features to Grab, consult the Censys documentation:

https://censys-python.readthedocs.io/en/stable/usage-v2.html

## status.py

Use this script to obtain a list of successful responses.
