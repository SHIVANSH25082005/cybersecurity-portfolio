import sqlite3


def discover_relationships(search_value):

    connection = sqlite3.connect("database/cyberintel.db")
    cursor = connection.cursor()

    visited = set()
    queue = [(search_value, 0)]

    discovered = []
    added_ids = set()

    while queue:

        current, depth = queue.pop(0)

        if current in visited:
            continue

        visited.add(current)

        if depth > 3:
            continue

        # If current value is an IP address,
        # find all phones that used it

        cursor.execute("""
        SELECT phone_number
        FROM ipdr_records
        WHERE ip_address = ?
        """, (current,))

        linked_phones = cursor.fetchall()

        if len(linked_phones) <= 10:
            for linked_phone in linked_phones:

                phone_number = linked_phone[0]

                if (
                    phone_number
                    and phone_number not in visited
                ):
                    queue.append((phone_number, depth + 1))

        # If current value is a phone number,
        # find all IPs that it used
        cursor.execute("""
        SELECT ip_address
        FROM ipdr_records
        WHERE phone_number = ?
        """, (current,))

        linked_ips = cursor.fetchall()
        for linked_ip in linked_ips:
            ip_address = linked_ip[0]
            if (
                ip_address
                and ip_address not in visited
            ):
                queue.append((ip_address, depth + 1))

        # Find complaints containing current value

        cursor.execute("""
        SELECT *
        FROM complaints
        WHERE phone_number = ?
        OR upi_id = ?
        OR email = ?
        OR telegram = ?
        OR website = ?
        """,
        (
            current,
            current,
            current,
            current,
            current
        ))

        records = cursor.fetchall()

        for record in records:

            complaint_id = record[0]

            phone = record[2]
            upi = record[3]
            email = record[4]
            telegram = record[5]
            website = record[6]

            if complaint_id not in added_ids:

                discovered.append(record)
                added_ids.add(complaint_id)

            indicators = [
                phone,
                upi,
                email,
                telegram,
                website
            ]

            for item in indicators:

                if item and item not in visited:
                    queue.append((item, depth + 1))

            # Find IPs used by phone

            cursor.execute("""
            SELECT ip_address
            FROM ipdr_records
            WHERE phone_number = ?
            """, (phone,))

            ip_results = cursor.fetchall()

            for ip in ip_results:

                ip_address = ip[0]

                if (
                    ip_address
                    and ip_address not in visited
                ):
                    queue.append((ip_address, depth + 1))

                # Find all phones sharing same IP

                cursor.execute("""
                SELECT phone_number
                FROM ipdr_records
                WHERE ip_address = ?
                """, (ip_address,))

                shared_phones = cursor.fetchall()

                if len(shared_phones) <= 10:
                    for shared_phone in shared_phones:

                        shared_number = shared_phone[0]

                        if (
                            shared_number
                            and shared_number not in visited
                        ):
                            queue.append((shared_number, depth + 1))

    connection.close()

    return discovered