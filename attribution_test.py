from neo4j import GraphDatabase
import random
from collections import deque


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

    # get incoming edges
    incoming_rels = session.run("""
        MATCH (n {name: $node_name})<-[r]-()
        RETURN r.source_port AS source_port, r.destination_port AS destination_port, r.transport AS transport, r.attribution_label AS attribution_label
    """, node_name=node_name).data()

    # get outcoming edges
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
        source_ports: [x in edges | x.source_port],
        destination_ports: [x in edges | x.destination_port]
    }]->(b)
    FOREACH (r IN edges | DELETE r)
    RETURN a, b, transport, size(edges) as merged_count
    """

    result = session.run(query)
    merged_count = 0

    for record in result:
        merged_count += record["merged_count"]

    print(f"Merged {merged_count} edges")



uri = "bolt://localhost:7687"
user = "neo4j"
password = "password"
driver = GraphDatabase.driver(uri, auth=(user, password))


nodes = [
    {'name': 'w1-s2', 'ip': '192.168.0.1', 'hostname': 'w1-s2'},
    {'name': 'w1-s3', 'ip': '192.168.0.2', 'hostname': 'w1-s3'},
    {'name': '192.168.0.3', 'ip': '192.168.0.3', 'hostname': '192.168.0.3'},
    {'name': '192.168.0.4', 'ip': '192.168.0.4', 'hostname': 'en2720-w1-cloud-hopper'},
    {'name': '192.168.0.5', 'ip': '192.168.0.5', 'hostname': '192.168.0.5'},
    {'name': '192.168.0.6', 'ip': '192.168.0.6', 'hostname': 'en2720-w1-energetic-bear'},
    {'name': '192.168.0.7', 'ip': '192.168.0.7', 'hostname': '192.168.0.7'},
    {'name': '192.168.0.8', 'ip': '192.168.0.8', 'hostname': '192.168.0.8'},
    {'name': '192.168.0.10', 'ip': '192.168.0.10', 'hostname': '192.168.0.10'}
]

rels = [
    {'source': 'w1-s2',       'target': '192.168.0.3', 'source_port': 1234, 'destination_port': 2345, 'transport': 'tcp',  'attribution_label': 'unknown'},
    {'source': '192.168.0.3', 'target': '192.168.0.4', 'source_port': 1234, 'destination_port': 2345, 'transport': 'tcp', 'attribution_label': 'unknown'},
    {'source': '192.168.0.3', 'target': '192.168.0.4', 'source_port': 3242, 'destination_port': 245, 'transport': 'tcp', 'attribution_label': 'unknown'},
    {'source': '192.168.0.3', 'target': '192.168.0.4', 'source_port': 124, 'destination_port': 235, 'transport': 'tcp', 'attribution_label': 'unknown'},
    {'source': '192.168.0.4', 'target': '192.168.0.5', 'source_port': 1234, 'destination_port': 2345, 'transport': 'tcp', 'attribution_label': 'unknown'},
    {'source': '192.168.0.5', 'target': '192.168.0.6', 'source_port': 14, 'destination_port': 34, 'transport': 'tcp', 'attribution_label': 'unknown'},
    {'source': '192.168.0.4', 'target': '192.168.0.6', 'source_port': random.randint(1, 65536), 'destination_port': random.randint(1, 65536), 'transport': random.choice(['tcp', 'udp', 'icmp']), 'attribution_label': 'unknown'},
    {'source': '192.168.0.3', 'target': '192.168.0.7', 'source_port': random.randint(1, 65536), 'destination_port': random.randint(1, 65536), 'transport': random.choice(['tcp', 'udp', 'icmp']), 'attribution_label': 'unknown'},
    {'source': '192.168.0.7', 'target': '192.168.0.8', 'source_port': random.randint(1, 65536), 'destination_port': random.randint(1, 65536), 'transport': random.choice(['tcp', 'udp', 'icmp']), 'attribution_label': 'unknown'},
    {'source': 'w1-s3',       'target': '192.168.0.3', 'source_port': 4567, 'destination_port': 6789, 'transport': 'icmp', 'attribution_label': 'unknown'},
    {'source': '192.168.0.3', 'target': '192.168.0.10', 'source_port': 4567, 'destination_port': 6789, 'transport': 'icmp', 'attribution_label': 'unknown'}
]

with driver.session() as session:
    for node in nodes:
        session.run(
            "CREATE (n:Node {name: $name, ip: $ip, hostname: $hostname})",
            name=node['name'], ip=node['ip'], hostname=node['hostname']
        )

    for rel in rels:
        session.run(
            "MATCH (a {{name: '{source}'}}), (b {{name: '{target}'}}) "
            "CREATE (a)-[r:TRANSPORT {{source_port: {source_port}, destination_port: {destination_port}, name: '{transport}', attribution_label: '{attribution_label}'}}]->(b)".format(
                source=rel['source'], target=rel['target'], source_port=rel['source_port'],
                destination_port=rel['destination_port'], transport=rel['transport'], attribution_label=rel['attribution_label']
            )
        )

    vpn_instance = '192.168.0.3'

    set_initial_attribution_labels(session, 'w1-s')
    set_attribution_label(session, vpn_instance)
    propagate_labels(session, vpn_instance)
    merge_edges(session)



driver.close()

