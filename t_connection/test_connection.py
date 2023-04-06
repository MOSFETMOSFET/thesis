#!/bin/python3

from t_connection.es_util import get_common_parser, get_es_connection

import json

# Cyber Range IP Range:
# 10.0.0.0-10.0.15.254

def test_connection(host: str, api_key: str):
    """Verify that the connection with ES works"""

    es = get_es_connection(host, api_key=api_key)

    print(es.info())
    print(es.cat.allocation())

    # results = es.cluster.health()

    # pprint(es.cluster.allocation_explain())

    # indeces = es.indices.get(index=["packetbeat-*"])

    # print(indeces.keys())

    body = {
        "query": {
            "bool": {
                "must": [
                    #{"match": {"source.process.name": "systemd-resolved"}},
                    #{"match": {"observer.hostname": "ep282u-w2-buckeye"}},
                    #{"match": {"process.executable": "/usr/sbin/apache2"}}, # Apache
                ],
                "must_not": [
                    #{"wildcard": {"source.ip": "192.168.*"}}, # Student IPs
                    {"match": {"user_agent.original": "Mozilla/5.0 (X11; Linux x86_64; rv:26.0) Gecko/20100101 Firefox/26.0"}}, # Automated Firefox
                    {"range": {"destination.ip": {"gte": "192.168.0.0", "lte": "192.168.255.255"}}}, # Student IPs
                    {"range": {"source.ip": {"gte": "192.168.0.0", "lte": "192.168.255.255"}}}, # Student IPs
                    {"match": {"source.ip": "::1"}}, # Localhost
                    {"wildcard": {"observer.hostname": "*buckeye"}}, # Firefox DNS requests
                    {"wildcard": {"source.process.executable": "/tmp/*"}},
                    {"wildcard": {"source.process.name": "*beat*"}}, # Beats
                    {"wildcard": {"source.process.name": "google*"}}, # Google services
                    {"match": {"source.process.name": "snapd"}}, # Snapd
                    {"match": {"observer.geo.name": "blueprint"}},
                    {"match": {"source.process.name": "GCEWindowsAgent.exe"}}, # GCE
                ],
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": "2022-11-28T00:00:00.000Z",
                            "lte": "2022-11-30T00:00:00.000Z",
                        }
                    }
                },
            },
        },
        "aggs": {
            "type_count": {
                "multi_terms": {
                    "terms": [
                        {"field": "source.process.name"},
                        {"field": "source.ip"},
                        {"field": "destination.ip"},
                        {"field": "observer.geo.name"},
                    ],
                    "size": "100",
                }
            },
        },
    }

    results = es.search(index="packetbeat-*", body=body)
    #
    # with open("results.json", "w", encoding="utf8") as f:
    #     json.dump(results.body, f, indent=4)

    response_json = json.dumps(results, indent=4)
    with open('response.json', 'w') as f:
        f.write(response_json)


    #hosts_and_ips = get_ips_and_hostnames(es)

    # with open("iplookup.json", "w") as db:
    #     json.dump(hosts_and_ips, db, indent=4)


if __name__ == "__main__":
    parser = get_common_parser()
    args = parser.parse_args(
        [
            "--host",
            "35.206.158.243",
            "--api-key",
            "VlRsLWZvWUJUNVZuNkdFR0VNX1Y6ZlJVelpGOERSeHkxaW1Da0FxSVplUQ==",
        ]
    )
    test_connection(args.host, args.api_key)