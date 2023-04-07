from elasticsearch.client import Elasticsearch
from elasticsearch_dsl import A, Q, Search
from neo4j import GraphDatabase
import json
import time
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

def delete_irrelevant_nodes(session):
    # Find the largest connected component
    cypher_find_largest_connected_component = '''
    MATCH (n)
    CALL apoc.path.subgraphAll(n, {
      minLevel: 1
    })
    YIELD nodes, relationships
    WITH apoc.coll.toSet(nodes) AS largest_connected_component
    RETURN largest_connected_component
    '''

    largest_connected_component = session.run(cypher_find_largest_connected_component).single()[0]

    # Delete nodes that are not part of the largest connected component
    cypher_delete_nodes_not_in_largest_component = """
    MATCH (n)
    WHERE NOT id(n) IN $largest_connected_component_ids
    DETACH DELETE n
    RETURN count(*) as deleted_nodes_count
    """

    largest_connected_component_ids = [node.id for node in largest_connected_component]
    result = session.run(cypher_delete_nodes_not_in_largest_component,
                         {"largest_connected_component_ids": largest_connected_component_ids})

    total_deleted_nodes = result.single()[0]

    return total_deleted_nodes


def set_initial_attribution_labels(session, source_prefix):
    cypher = f"""
        MATCH (source:Node)-[r:TRANSPORT]->(target:Node)
        WHERE source.name STARTS WITH '{source_prefix}'
        SET r.attribution_label = source.name
    """
    session.run(cypher)


def get_connected_nodes(session, node_name):
    connected_nodes = session.run("""
        MATCH (n {name: $node_name})-[r]->(connected:Node)
        RETURN connected.name AS name
    """, node_name=node_name).data()

    return [connected_node['name'] for connected_node in connected_nodes]


def propagate_labels(session, node_name):

    connected_nodes = get_connected_nodes(session, node_name)

    if not connected_nodes:
        return

    for connected_node in connected_nodes:

        matched = set_attribution_label(session, connected_node)

        if matched:
            propagate_labels(session, connected_node)


def set_attribution_label(session, node_name):

    matched = False

    # incoming edges
    incoming_rels = session.run("""
        MATCH (n {name: $node_name})<-[r]-()
        RETURN r.source_port AS source_port, r.destination_port AS destination_port, r.transport AS transport, r.attribution_label AS attribution_label
    """, node_name=node_name).data()

    # outcoming edges
    outgoing_rels = session.run("""
        MATCH (n {name: $node_name})-[r]->()
        RETURN ID(r) AS id, r.source_port AS source_port, r.destination_port AS destination_port, r.transport AS transport
    """, node_name=node_name).data()

    # compare
    for incoming_rel in incoming_rels:
        for outgoing_rel in outgoing_rels:
            if (
                incoming_rel['source_port'] == outgoing_rel['source_port']
                and incoming_rel['destination_port'] == outgoing_rel['destination_port']
                and incoming_rel['transport'] == outgoing_rel['transport']
            ):

                matched = True
                # update attribution label of outcoming edge
                session.run("""
                    MATCH ()-[r]->() WHERE ID(r) = $id
                    SET r.attribution_label = $attribution_label
                """, id=outgoing_rel['id'], attribution_label=incoming_rel['attribution_label'])


    return matched


def merge_edges(session):

    query = """
    MATCH (a)-[r:TRANSPORT]->(b)
    WHERE r.attribution_label = 'unknown'
    WITH a, b, r.transport as transport, collect(r) as edges
    WHERE size(edges) > 1
    CREATE (a)-[merged:TRANSPORT {
        transport: transport,
        attribution_label: 'unknown',
        source_ports: [x in edges WHERE x.source_port IS NOT NULL | x.source_port],
        destination_ports: [x in edges WHERE x.destination_port IS NOT NULL | x.destination_port]
    }]->(b)
    FOREACH (r IN edges | DELETE r)
    RETURN a, b, transport, size(edges) as merged_count
    """

    result = session.run(query)
    merged_count = 0

    for record in result:
        merged_count += record["merged_count"]

    print(f"Merged {merged_count} edges")



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
        "range", event__start={"lte": 20221001, "gte": 20221001, "format": "basic_date"}
    )
    filter &= Q(
        "range", event__end={"lte": 20221001, "gte": 20221001, "format": "basic_date"}
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
                "transport": getattr(h.network, "transport", "unknown"),
                "source_hostname": source_hostname or source_ip,
                "destination_hostname": destination_hostname or destination_ip,
                "attribution_label": "unknown",
            }

            # create nodes

            create_or_update_node_cypher = """
                MERGE (source:IP {name: $source_ip})
                ON CREATE SET source.hostname = $source_hostname
                MERGE (destination:IP {name: $destination_ip})
                ON CREATE SET destination.hostname = $destination_hostname
            """

            session.run(create_or_update_node_cypher, params)

            # create relationships
            create_or_update_relationship_cypher = """
                MATCH (source:IP {name: $source_ip}), (destination:IP {name: $destination_ip})
                CREATE (source)-[t:TRANSPORT {name: $transport, source_port: $source_port, destination_port: $destination_port, attribution_label: CASE WHEN source.name STARTS WITH 'w1-s' THEN source.name ELSE $attribution_label END, event_start: $event_start, event_end: $event_end, count: 1}]->(destination)
            """

            session.run(create_or_update_relationship_cypher, params)

        #filter out nodes that are not connected to any other nodes
        total_deleted_nodes = delete_irrelevant_nodes(session)

        vpn_instance = '10.0.0.2'

        set_initial_attribution_labels(session, 'w1-s')
        set_attribution_label(session, vpn_instance)
        propagate_labels(session, vpn_instance)
        #merge_edges(session)


    driver.close()
    print(f'Nodes and relationships created in Neo4j, {total_deleted_nodes} irrelevant nodes deleted.')
    print('completed')



if __name__ == "__main__":
    start_time = time.time()
    get_packetbeat_filtered_packets()
    end_time = time.time()
    execution_time = end_time - start_time
    print(f'Execution time is: {execution_time} seconds')

