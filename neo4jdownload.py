from neo4j import GraphDatabase, Driver, basic_auth
import json
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
import sqlite3 as sl
import ssl

def get_filebeat_packets() -> None:
    """Retrieves filebeat packets from the Elasticsearch database and saves
    them to a newly created local Neo4j database."""

    print('getting filebeat file')

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

    s: Search = Search(using=es_connection)
    s = s.extra(track_total_hits=True)
    s = s.extra(size=0)

    world_name = "en2720-w1"

    agentf = Q("term", agent__type={"value": "filebeat"})
    world = Q("term", world=world_name)
    time = Q(
        "range",
        **{"@timestamp": {"gte": 20221001, "lte": 20221005, "format": "basic_date"}},
    )
    session_start = Q("term", openvpn__event={"value": "client-connected"})
    session_end = Q("term", openvpn__event={"value": "client-disconnected"})

    filter1 = agentf & world & (session_start | session_end) & time

    filter = filter1
    q = Q("bool", filter=filter)

    s = s.query(q)

    # Connect to the Neo4j database
    neo4j_uri = "bolt://localhost:7687"
    neo4j_user = "neo4j"
    neo4j_password = "filebeat"

    driver: Driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

    # Function to run a Cypher query
    def run_query(tx, query, params=None):
        if params:
            tx.run(query, params)
        else:
            tx.run(query)

    # Clear the existing data and create a constraint on the Filebeat nodes
    with driver.session() as session:
        session.write_transaction(run_query, "MATCH (n:Filebeat) DETACH DELETE n")
        session.write_transaction(run_query, "CREATE CONSTRAINT IF NOT EXISTS FOR (f:Filebeat) REQUIRE f.timestamp IS UNIQUE")

    # Cypher query to insert the data into the Neo4j database
    cypher_query = """
    UNWIND $data AS row
    MERGE (f:Filebeat {timestamp: row.timestamp})
    SET f.world = row.world,
        f.openvpn_event = row.openvpn_event,
        f.openvpn_common_name = row.openvpn_common_name
    """

    # Prepare the data for insertion
    data = [
        {
            "timestamp": h["@timestamp"],
            "world": h.world,
            "openvpn_event": h.openvpn.event,
            "openvpn_common_name": h.openvpn.common_name,
        }
        for h in s.scan()
    ]


    # Insert the data into the Neo4j database
    with driver.session() as session:
        session.write_transaction(run_query, cypher_query, {"data": data})

    print('filebeat data saved to Neo4j database')


def get_journalbeat_packets() -> None:
    """Retrieves journalbeat packets from the Elasticsearch database and saves
    them to a newly created Neo4j database."""

    es = {
        "hosts": ["35.206.158.243"],
        "port": 9200,
        "use_ssl": True,
        "verify_certs": False,
        "ssl_show_warn": False,
    }

    print('getting journalbeat file')

    with open("api-key.json") as f:
        api_key = json.load(f)

    es["api_key"] = (api_key["api_key"])

    es_connection = Elasticsearch(**es, timeout=200, max_retries=10, retry_on_timeout=True)
    s: Search = Search(using=es_connection)
    s = s.extra(track_total_hits=True)
    s = s.extra(size=1000)

    filter = (
        Q("term", agent__type="journalbeat")
        & Q("term", syslog__identifier="conntrack")
        & Q("term", agent__hostname="en2720-w1-vpn")
    )
    destination = Q(
        "term",
        conntrack__dst2="10.0.0.2",
    )
    datetime = Q(
        "range", event__start={"lte": 20221005, "gte": 20221001, "format": "basic_date"}
    )
    exclude_vpn = ~Q("term", conntrack__dst1="10.0.0.2")
    filter &= destination & datetime & exclude_vpn
    q = Q("bool", filter=filter)

    s = s.query(q)

    # Connect to the Neo4j database
    neo4j_uri = "bolt://localhost:7687"
    neo4j_user = "neo4j"
    neo4j_password = "journalbeat"
    driver = GraphDatabase.driver(neo4j_uri, auth=basic_auth(neo4j_user, neo4j_password))

    # Function to add data to Neo4j
    def add_data_batch(data_batch):
        def wrapper(tx):
            query = """
            UNWIND $data as data
            CREATE (j:Journalbeat {
                event_start: data.event_start,
                agent_hostname: data.agent_hostname,
                conntrack_src1: data.conntrack_src1,
                conntrack_sport1: data.conntrack_sport1,
                conntrack_src2: data.conntrack_src2,
                conntrack_sport2: data.conntrack_sport2,
                conntrack_dst1: data.conntrack_dst1,
                conntrack_dport1: data.conntrack_dport1,
                conntrack_dst2: data.conntrack_dst2,
                conntrack_dport2: data.conntrack_dport2,
                conntrack_trans_proto: data.conntrack_trans_proto,
                conntrack_timestamp: data.conntrack_timestamp
            });
            """
            tx.run(query, data=data_batch)

        return wrapper

    data = [
        {
            "event_start": h.event.start,
            "agent_hostname": h.agent.hostname,
            "conntrack_src1": h.conntrack.src1,
            "conntrack_sport1": getattr(h.conntrack, "sport1", "NULL"),
            "conntrack_src2": h.conntrack.src2,
            "conntrack_sport2": getattr(h.conntrack, "sport2", "NULL"),
            "conntrack_dst1": h.conntrack.dst1,
            "conntrack_dport1": getattr(h.conntrack, "dport1", "NULL"),
            "conntrack_dst2": h.conntrack.dst2,
            "conntrack_dport2": getattr(h.conntrack, "dport2", "NULL"),
            "conntrack_trans_proto": h.conntrack.trans_proto,
            "conntrack_timestamp": h.conntrack["timestamp"],
        }
        for h in s.scan()
    ]

    # Insert data into Neo4j database
    batch_size = 100  # Adjust the batch size as needed
    data_batches = [data[i:i + batch_size] for i in range(0, len(data), batch_size)]

    # Insert data into Neo4j database in batches
    with driver.session() as session:
        for batch in data_batches:
            session.write_transaction(add_data_batch(batch))

    print('journalbeat data saved to Neo4j database')




def get_packetbeat_packets() -> None:
    """Retrieves packetbeat packets from the Elasticsearch database and saves
    them to a newly created local Neo4j database."""

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
        "range", event__start={"lte": 20221005, "gte": 20221001, "format": "basic_date"}
    )
    filter &= Q(
        "range", event__end={"lte": 20221005, "gte": 20221001, "format": "basic_date"}
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

    q = Q("bool", filter=filter)

    s = s.query(q)

    # Connect to Neo4j database
    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "packetbeat"
    driver = GraphDatabase.driver(uri, auth=(user, password))

    def add_packetbeat(data_batch):
        def wrapper(tx):
            query = """
            UNWIND $data as data
            CREATE (:Packetbeat {
                event_start: data.event_start,
                event_end: data.event_end,
                source_ip: data.source_ip,
                source_port: data.source_port,
                destination_ip: data.destination_ip,
                destination_port: data.destination_port,
                network_transport: data.network_transport
            });
            """
            tx.run(query, data=data_batch)

        return wrapper


    data = [
        {
            "event_start": h.event.start,
            "event_end": h.event.end,
            "source_ip": h.source.ip,
            "source_port": getattr(h.source, "port", "NULL"),
            "destination_ip": h.destination.ip,
            "destination_port": getattr(h.destination, "port", "NULL"),
            "network_transport": getattr(h.network, "transport", "NULL"),
        }
        for h in s.scan()
    ]

    batch_size = 100  # Adjust the batch size as needed
    data_batches = [data[i:i + batch_size] for i in range(0, len(data), batch_size)]

    # Insert data into Neo4j database in batches
    with driver.session() as session:
        for batch in data_batches:
            session.write_transaction(add_packetbeat(batch))

    print('Packetbeat data saved to Neo4j database')

    driver.close()




if __name__ == "__main__":
    # get_filebeat_packets()
    # get_journalbeat_packets()
    # get_packetbeat_packets()

    print(1)


    def connect_to_database(database_name):
        neo4j_uri = "bolt://localhost:7687"
        neo4j_user = "neo4j"
        neo4j_password = "journalbeat"
        driver = GraphDatabase.driver(neo4j_uri, auth=basic_auth(neo4j_user, neo4j_password), database=database_name)
        return driver