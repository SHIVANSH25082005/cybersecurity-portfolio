from relationship_discovery import discover_relationships
from network_summary import get_network_summary

records = discover_relationships("9876543210")

summary = get_network_summary(records)

print(summary)