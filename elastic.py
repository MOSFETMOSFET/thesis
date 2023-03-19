import json

from elasticsearch.client import Elasticsearch
from elasticsearch_dsl import Search

# NOTE: Using the API port requires a connection through the KTH VPN
es_connection = {
    "hosts": ["35.206.158.243"],
    "port": 9200,
    "use_ssl": True,
    "verify_certs": False,
    "ssl_show_warn": False,
}


def main():
    with open("api-key.json") as f:
        data = json.load(f)

    es_connection["api_key"] = (data["api_key"])

    es = Elasticsearch(
        **es_connection, timeout=30, max_retries=10, retry_on_timeout=True
    )

    s: Search = Search(using=es)

    agent_type = "packetbeat"

    s = s.query("match", **{"agent.type": agent_type})
    s.extra(track_total_hits=True)
    response = s.execute()

    print(response.success())
    print(response.hits.total)

    for h in response:
        print(h.world)


if __name__ == "__main__":
    main()