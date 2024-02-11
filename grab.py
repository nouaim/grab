"""Search hosts data set."""

from censys.search import CensysHosts

h = CensysHosts()

## This query is just an example, you can use the same queries you search on https://search.censys.io/
query = """
services.software.product: "Jenkins"
and location.country: {"Saudi Arabia", France, Italy, Germany, Belgium}
and services.service_name: HTTP
"""

search_results = h.search(query=query)

with open("censys_results.txt", "w") as output_file:
    for page in search_results:
        for host in page:
            ip_address = host["ip"]
            if host["services"]:
                for index, service in enumerate(host["services"]):
                    port = service["port"]
                    url = f"http://{ip_address}:{port}"
                    output_file.write(url + "\n")
