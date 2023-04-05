from elasticsearch.client import Elasticsearch
from elasticsearch_dsl import A, Q, Search
from neo4j import GraphDatabase
import json
import time

def convert_ip_to_w1_sx(ip_address: str) -> str:
    if ip_address.startswith("192.168.0."):
        last_octet = int(ip_address.split(".")[-1])
        return f"w1-s{last_octet}"
    return ip_address

def set_attribution_label_recursive(session, starting_nodes, visited_edges=None, iteration=0):
    if visited_edges is None:
        visited_edges = set()

    print(f"Current iteration: {iteration}")

    for start_node_name in starting_nodes:
        cypher = f"""
            MATCH (start_node:IP {{name: '{start_node_name}'}})
            MATCH (start_node)-[direct_conn:TRANSPORT]->(direct_neighbor:IP)
            WHERE NOT id(direct_conn) IN {list(visited_edges)}
            SET direct_conn.attribution_label = start_node.name
            WITH start_node, direct_neighbor, direct_conn
            MATCH (direct_neighbor)-[outgoing:TRANSPORT]->(other:IP)
            WHERE (direct_neighbor)-[:TRANSPORT {{source_port: outgoing.source_port, destination_port: outgoing.destination_port, name: outgoing.name}}]->(start_node)
                  AND NOT id(outgoing) IN {list(visited_edges)}
            SET outgoing.attribution_label = start_node.name
            RETURN id(direct_conn) as direct_conn_id, id(outgoing) as outgoing_id, other.name as other_name
        """
        records = session.run(cypher)

        next_starting_nodes = []
        for record in records:
            next_starting_nodes.append(record["other_name"])
            visited_edges.add(record["direct_conn_id"])
            visited_edges.add(record["outgoing_id"])

        if next_starting_nodes:
            set_attribution_label_recursive(session, next_starting_nodes, visited_edges, iteration=iteration + 1)


def get_hostname_for_ip(ip_address: str, packet_data: dict) -> str:
    if "observer" in packet_data and "ip" in packet_data["observer"] and "hostname" in packet_data["observer"]:
        ip_list = packet_data["observer"]["ip"]
        hostname = packet_data["observer"]["hostname"]

        if ip_address in ip_list:
            return hostname

    return ip_address

def update_attribution_label(session, source_ip, source_port, destination_port, transport):
    cypher = """
        MATCH (source:IP {name: $source_ip})
        MATCH (destination:IP)-[t:TRANSPORT {name: $transport}]->(source)
        WHERE t.source_port = $source_port AND t.destination_port = $destination_port
        MATCH (destination)-[r:TRANSPORT]->(connected)
        WHERE r.source_port = t.source_port AND r.destination_port = t.destination_port AND r.name = t.name
        SET r.attribution_label = source.name
    """
    params = {
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "transport": transport,
    }
    session.run(cypher, params)


def get_edges_with_non_none_attribution_label(session):
    cypher = """
        MATCH (a:IP)-[r:TRANSPORT]->(b:IP)
        WHERE r.attribution_label <> 'none'
        RETURN a.name AS source_ip, b.name AS destination_ip, r.transport AS transport, r.source_port AS source_port, r.destination_port AS destination_port, r.attribution_label AS attribution_label
    """
    result = session.run(cypher)
    return result.data()


def merge_edges(session):
    cypher = """
        MATCH (a:IP)-[r1:TRANSPORT]->(b:IP)
        MATCH (a)-[r2:TRANSPORT]->(b)
        WHERE r1.attribution_label = 'none' AND r2.attribution_label = 'none' AND r1.transport = r2.transport AND id(r1) <> id(r2)
        WITH a, b, r1, r2
        SET r2.count = coalesce(r2.count, 1) + coalesce(r1.count, 1)
        DELETE r1
    """
    session.run(cypher)

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
                "source_port": getattr(h.source, "port", "unknown" ),
                "destination_ip": destination_ip,
                "destination_port": getattr(h.destination, "port", "unknown"),
                "transport": getattr(h.network, "transport", "unknown"),
                "source_hostname": source_hostname or "unknown",
                "destination_hostname": destination_hostname or "unknown",
                "attribution_label": None,
            }

            if (
                    previous_packet
                    and previous_packet["source_port"] == params["source_port"]
                    and previous_packet["destination_port"] == params["destination_port"]
                    and previous_packet["transport"] == params["transport"]
                    and (
                    previous_packet["attribution_label"] == "none"
                    or source_ip.startswith("w1-s")
                    or previous_packet["source_ip"].startswith("w1-s")
            )
            ):
                params["attribution_label"] = previous_packet["attribution_label"]
            else:
                params["attribution_label"] = "none"


            create_or_update_node_cypher = """
                MERGE (source:IP {name: $source_ip})
                ON CREATE SET source.hostname = $source_hostname
                MERGE (destination:IP {name: $destination_ip})
                ON CREATE SET destination.hostname = $destination_hostname
            """

            session.run(create_or_update_node_cypher, params)


            create_or_update_edge_cypher = """
                MERGE (source:IP {name: $source_ip})
                MERGE (destination:IP {name: $destination_ip})
                CREATE (source)-[r:TRANSPORT {
                    name: $transport,
                    source_port: $source_port,
                    destination_port: $destination_port,
                    attribution_label: $attribution_label
                }]->(destination)
            """
            session.run(create_or_update_edge_cypher, params)

        starting_nodes = [f"w1-s{i}" for i in range(1, 255)]
        set_attribution_label_recursive(session, starting_nodes)

        merge_edges(session)

    driver.close()
    print('Nodes and relationships created in Neo4j')


if __name__ == "__main__":
    start_time = time.time()
    get_packetbeat_filtered_packets()
    end_time = time.time()
    execution_time = end_time - start_time
    print(f'Execution time is: {execution_time} seconds')









