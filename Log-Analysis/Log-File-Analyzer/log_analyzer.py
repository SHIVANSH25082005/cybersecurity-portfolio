file = open("auth.log", "r")

failed_count = 0

for line in file:
    line = line.strip()

    if "Failed login" in line:
        failed_count = failed_count + 1

file.close()

print("Total failed login attempts:", failed_count)



file = open("auth.log", "r")

ip_count = {}

for line in file:
    line = line.strip()

    if "Failed login" in line:
        parts = line.split()

        ip = parts[-1]       

        if ip in ip_count:
            ip_count[ip] = ip_count[ip] + 1
        else:
            ip_count[ip] = 1

file.close()

print(ip_count)


for ip in ip_count:
    if ip_count[ip] >= 3:
        print("ALERT:", ip_count[ip], "failed logins from", ip)
        print("[HIGH] Brute-force detected -", ip_count[ip], "attempts from IP", ip)



file = open("auth.log", "r")

user_count = {}

for line in file:
    line = line.strip()

    if "Failed login" in line:
        parts = line.split()
        user = parts[7]

        if user in user_count:
            user_count[user] = user_count[user] + 1
        else:
            user_count[user] = 1

file.close()

print(user_count)

for user in user_count:
    if user_count[user] >= 3:
        print("ALERT:", user, "account targeted", user_count[user], "times")

        alert_file = open("alerts.log", "a")

alert_file = open("alerts.log", "a")

for user in user_count:
    if user_count[user] >= 3:
        alert_file.write(
            "[HIGH] Account brute-force detected - "
            + user
            + " targeted "
            + str(user_count[user])
            + " times\n"
        )

alert_file.close()


from datetime import datetime

file = open("auth.log", "r")

times = []

for line in file:
    line = line.strip()

    if "Failed login" in line:
        parts = line.split()
        timestamp = parts[0] + " " + parts[1]
        t = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        times.append(t)

file.close()

times.sort()

for i in range(len(times) - 2):
    if (times[i + 2] - times[i]).seconds <= 30:
        print("ALERT: 3 failed logins within 30 seconds")
        break


from datetime import datetime

file = open("auth.log", "r")

times = []

for line in file:
    line = line.strip()

    if "Failed login" in line:
        parts = line.split()
        timestamp = parts[0] + " " + parts[1]
        t = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        times.append(t)

file.close()

times.sort()

for i in range(len(times) - 2):
    if (times[i + 2] - times[i]).seconds <= 30:
        print("ALERT: 3 failed logins within 30 seconds")
        break

from datetime import datetime

file = open("auth.log", "r")

events = {}

for line in file:
    line = line.strip()

    if "Failed login" in line:
        parts = line.split()

        timestamp = parts[0] + " " + parts[1]
        ip = parts[-1]
        user = parts[7]

        t = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        key = (ip, user)

        if key not in events:
            events[key] = []

        events[key].append(t)

file.close()

alert_file = open("alerts.log", "a")

for (ip, user) in events:
    times = events[(ip, user)]
    times.sort()

    for i in range(len(times) - 2):
        if (times[i + 2] - times[i]).seconds <= 30:
            message = (
                "[CRITICAL] Coordinated brute-force detected: "
                + "IP "
                + ip
                + " targeting user "
                + user
                + " ("
                + str(len(times))
                + " attempts in 30 seconds)"
            )

            print(message)
            alert_file.write(message + "\n")
            break

alert_file.close()
