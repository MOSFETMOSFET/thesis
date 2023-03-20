import json
from neo4j import GraphDatabase

import json
from py2neo import Graph, Node, Relationship


def load_json_file(json_file_name):
    with open(json_file_name, 'r') as file:
        data = json.load(file)
    return data


def visualize_json_in_neo4j(file_path, neo4j_uri, user, password):
    graph = Graph(neo4j_uri, auth=(user, password))
    graph.delete_all()

    data = load_json_file(file_path)

    nodes = data["nodes"]
    edges = data["edges"]

    # 创建Node节点
    node_dict = {}
    for n in nodes:
        node = Node("IP", id=n["id"], count=n["count"])
        node_dict[n["id"]] = node
        graph.create(node)

    # 创建边
    for e in edges:
        source = node_dict[e["source"]]
        target = node_dict[e["target"]]
        rel = Relationship(source, "CONNECTS", target, date=e["data"]["date"], attr=e["data"]["attr"],
                           ports=e["data"]["ports"], count=e["data"]["count"])
        graph.create(rel)


# 使用方法
json_file_name = "graph_data.json"
neo4j_uri = "bolt://localhost:7687"
user = "neo4j"
password = "displayer"

visualize_json_in_neo4j(json_file_name, neo4j_uri, user, password)