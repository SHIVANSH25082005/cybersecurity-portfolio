from fusion_engine import get_neighbors, search_nodes


def graph_seed_for_case(case_id, limit=40):
    return get_neighbors("Case", case_id, limit=limit)
