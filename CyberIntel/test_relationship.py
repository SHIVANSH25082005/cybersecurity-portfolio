from relationship_discovery import discover_relationships

results = discover_relationships("9876543210")

for item in results:
    print(item)