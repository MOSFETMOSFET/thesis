from elasticsearch.client import Elasticsearch
from elasticsearch_dsl import A, Q, Search
from neo4j import GraphDatabase
import json
from uuid import uuid4

def convert_ip_to_w1_sx(ip_address: str) -> str:
    if ip_address.startswith("192.168.0."):
        last_octet = int(ip_address.split(".")[-1])
        return f"w1-s{last_octet}"
    return ip_address


def get_hostname_for_ip(ip_address: str, packet_data: dict) -> str:
    if "observer" in packet_data and "ip" in packet_data["observer"] and "hostname" in packet_data["observer"]:
        ip_list = packet_data["observer"]["ip"]
        hostname = packet_data["observer"]["hostname"]

        if ip_address in ip_list:
            return hostname

    return ip_address


def get_packetbeat_filtered_packets() -> None:
    """Retrieves packetbeat packets from the Elasticsearch database and saves
    them to a newly created local database and adds relationships to Neo4j."""

    print('Starting get packetbeat')

    es = {
        "hosts": ["35.206.158.243"],
        "port": 9200,
        "use_ssl": True,
        "verify_certs": False,
        "ssl_show_warn": False,
    }

    with open("api-key.json") as f:
        api_key = json.load(f)

    es["api_key"] = (api_key["api_key"])

    es_connection = Elasticsearch(**es, timeout=200, max_retries=10, retry_on_timeout=True)

    print('Elasticsearch connection established')

    s: Search = Search(using=es_connection)
    s = s.extra(track_total_hits=True)
    s = s.extra(size=1000)

    agent_type = "packetbeat"
    world_name = "en2720-w1"

    filter = Q(
        "range", event__start={"lte": 20221003, "gte": 20221003, "format": "basic_date"}
    )
    filter &= Q(
        "range", event__end={"lte": 20221003, "gte": 20221003, "format": "basic_date"}
    )
    agent = Q("term", agent__type=agent_type)

    host = Q("term", world=world_name)

    ip_src_filter = Q(
        "range", **{"source.ip": {"gte": "10.0.0.0", "lt": "10.0.15.254"}}
    ) | Q("range", **{"source.ip": {"gte": "192.168.0.0", "lt": "192.168.0.254"}})

    ip_dest_filter = Q(
        "range", **{"destination.ip": {"gte": "10.0.0.0", "lt": "10.0.15.254"}}
    ) | Q("range", **{"destination.ip": {"gte": "192.168.0.0", "lt": "192.168.0.254"}})

    filter &= host & ip_src_filter & ip_dest_filter & agent


    # filter &= ~Q("wildcard", **{"source.ip": "192.168.*"})  # Student IPs
    # filter &= ~Q("range", **{"destination.ip": {"gte": "192.168.0.0", "lte": "192.168.255.255"}})  # Student IPs
    # filter &= ~Q("range", **{"source.ip": {"gte": "192.168.0.0", "lte": "192.168.255.255"}})  # Student IPs
    # filter &= ~Q("match", **{"source.ip": "::1"})  # Localhost
    filter &= ~Q("wildcard", **{"observer.hostname": "*buckeye"})  # Firefox DNS requests
    filter &= ~Q("wildcard", **{"source.process.executable": "/tmp/*"})
    filter &= ~Q("wildcard", **{"source.process.name": "*beat*"})  # Beats
    filter &= ~Q("wildcard", **{"source.process.name": "google*"})  # Google services
    filter &= ~Q("match", **{
        "user_agent.original": "Mozilla/5.0 (X11; Linux x86_64; rv:26.0) Gecko/20100101 Firefox/26.0"})  # Automated Firefox
    filter &= ~Q("match", **{"observer.geo.name": "blueprint"})
    filter &= ~Q("match", **{"source.process.name": "GCEWindowsAgent.exe"})  # GCE

    q = Q("bool", filter=filter)

    print(f"Total hits: {s.count()}")

    s = s.query(q)

    # Connect to Neo4j database
    neo4j_url = "bolt://localhost:7687"
    neo4j_username = "neo4j"
    neo4j_password = "password"

    driver = GraphDatabase.driver(neo4j_url, auth=(neo4j_username, neo4j_password))

    print('Neo4j connection established')

    with driver.session() as session:
        previous_packet = None
        for h in s.scan():

            source_ip = convert_ip_to_w1_sx(h.source.ip)
            destination_ip = convert_ip_to_w1_sx(h.destination.ip)
            source_hostname = get_hostname_for_ip(source_ip, h.to_dict())
            destination_hostname = get_hostname_for_ip(destination_ip, h.to_dict())

            params = {
                "event_start": h.event.start,
                "event_end": h.event.end,
                "source_ip": source_ip,
                "source_port": getattr(h.source, "port", None),
                "destination_ip": destination_ip,
                "destination_port": getattr(h.destination, "port", None),
                "transport": getattr(h.network, "transport", None),
                "source_hostname": source_hostname or "unknown",
                "destination_hostname": destination_hostname or "unknown",
                "attribution_label": None,
            }

            if (
                    previous_packet
                    and previous_packet["source_port"] == params["source_port"]
                    and previous_packet["destination_port"] == params["destination_port"]
            ):
                params["attribution_label"] = previous_packet["attribution_label"]
            elif not previous_packet:
                params["attribution_label"] = str(uuid4())

            if params["transport"] is None:
                params["transport"] = "unknown"

            cypher = """
                    MERGE (source:IP {name: $source_ip, hostname: $source_hostname})
                    MERGE (destination:IP {name: $destination_ip, hostname: $destination_hostname})
                    MERGE (source)-[t:TRANSPORT {name: $transport}]->(destination)
                    ON CREATE SET t.count = 1, t.source_port = $source_port, t.destination_port = $destination_port
                    ON MATCH SET t.count = t.count + 1
                """

            if params["attribution_label"]:
                cypher += """
                        SET t.attribution_label = $attribution_label
                    """

            cypher += """
                    RETURN t
                """

            session.run(cypher, params)
            previous_packet = params

    driver.close()
    print('Nodes and relationships created in Neo4j')


get_packetbeat_filtered_packets()