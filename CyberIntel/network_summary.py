def get_network_summary(records):

    indicators = set()

    for record in records:

        phone = record[2]
        upi = record[3]
        email = record[4]
        telegram = record[5]
        website = record[6]

        values = [
            phone,
            upi,
            email,
            telegram,
            website
        ]

        for value in values:
            if value:
                indicators.add(value)

    return {
        "complaints": len(records),
        "indicators": len(indicators)
    }