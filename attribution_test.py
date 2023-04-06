from neo4j import GraphDatabase
import random


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


def set_initial_attribution_labels(session, source_prefix):
    cypher = f"""
        MATCH (source:Node)-[r:TRANSPORT]->(target:Node)
        WHERE source.name STARTS WITH '{source_prefix}'
        SET r.attribution_label = source.name
    """
    session.run(cypher)


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
    {'source': '192.168.0.4', 'target': '192.168.0.5', 'source_port': 1234, 'destination_port': 2345, 'transport': 'tcp', 'attribution_label': 'unknown'},
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

    set_initial_attribution_labels(session, 'w1-s')

driver.close()

