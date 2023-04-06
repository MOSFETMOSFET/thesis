from elasticsearch import Elasticsearch
from argparse import ArgumentParser


def get_common_parser():
    """
    Get common parser
    """
    parser = ArgumentParser()
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", default=9200, type=int)
    parser.add_argument("--api-key")
    return parser


def get_es_connection(host, port=9200, user=None, password=None, api_key=None):
    """
    Get Elasticsearch connection
    """

    if not (api_key or (user and password)):
        raise Exception("Either an API key or an user/password combo must be provided")

    es_connection = {
        "hosts": [f"https://{host}:{port}"],
        "verify_certs": False,
        "basic_auth": (user, password) if user and password else None,
        "api_key": api_key,
        "ssl_show_warn": False,
    }

    connection = Elasticsearch(
        **es_connection, request_timeout=30, max_retries=10, retry_on_timeout=True
    )
    return connection