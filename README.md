## Description

This tool helps you collect ips from cencys.

## Benifit 

Collect condidate ips you wanna do your tests on, then you can feed the hosts to tools Jaeles, nuklei, any other cve check tool, or open source POC scripts.


## Queries

```shell
services.http.response.headers: (key: server and value: e*mail)
location.country: {Canada, Chile, Honduras, Mexico, “United States”, Uruguay}
h.search(
    query=query, fields=["ip", "services.port", "services.service_name"]
)
services.service_name: HTTP
services.http.response.headers: (key: `Etag` and value.headers: `"6001043d.16d"`)
services.http.response.html_title: "your dashboard" 
```
 

## if you want to generate queries you can use this gpt tool they've made : 
https://gpt.censys.io/



## Read the docs of censys if you want to add something to the code

https://censys-python.readthedocs.io/en/stable/usage-v2.html
