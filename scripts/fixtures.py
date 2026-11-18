"""Seed data shared by seed.py and generate_bills.py."""

CUSTOMERS = [
    ("alice.smith@example.com", "alice123", "Alice Smith", "12 Birch St, Springvale", "12 Birch St, Springvale"),
    ("ben.wood@example.com", "ben123", "Ben Wood", "48 Oak Ave, Riverton", "48 Oak Ave, Riverton"),
    ("carla.clark@example.com", "carla123", "Carla Clark", "7 Maple Ct, Riverton", "PO Box 220, Riverton"),
    ("devon.reed@example.com", "devon123", "Devon Reed", "301 Cedar Rd, Springvale", "301 Cedar Rd, Springvale"),
    ("elena.brown@example.com", "elena123", "Elena Brown", "9 Willow Way, Fairfield", "9 Willow Way, Fairfield"),
    ("farid.shaw@example.com", "farid123", "Farid Shaw", "56 Elm St, Fairfield", "56 Elm St, Fairfield"),
    ("grace.green@example.com", "grace123", "Grace Green", "18 Poplar Ln, Riverton", "18 Poplar Ln, Riverton"),
    ("harun.lee@example.com", "harun123", "Harun Lee", "77 Spruce Dr, Springvale", "77 Spruce Dr, Springvale"),
]

ADMINS = [
    ("ops1@example.com", "changeme", "Priya Shah"),
    ("ops2@example.com", "changeme", "Marcus Webb"),
    ("devadmin@example.com", "Dev@2024!", "Dev Admin"),
]

METER_NICKNAMES = [
    "Garage sub-panel", "Main house meter", "Workshop meter", "Guest suite meter",
    "Basement meter", "Rental unit meter", "Pool house meter", "Barn meter",
]

METER_BALANCES = [25.0, 25.0, 3.50, 25.0, -8.20, 25.0, 25.0, 25.0]

METER_CODES = [f"MTR-{1000 + i}" for i in range(1, len(CUSTOMERS) + 1)]

CUSTOMER_CREATED_HOURS_AGO = [4380, 2160, 720, 168, 48, 20, 5, 1]

# A handful of realistic-looking alarm/event rows so /admin/alarms has
# something to search -- (meter offset from the seeded list, type, message).
ALARM_SEEDS = [
    (0, "tamper", "Enclosure tamper switch triggered"),
    (1, "comms_failure", "No check-in for 6 hours"),
    (2, "outage", "Loss of supply detected"),
    (3, "voltage", "Sustained under-voltage on phase A"),
    (4, "tamper", "Magnetic field anomaly detected near meter"),
    (5, "comms_failure", "Firmware heartbeat missed 3 times"),
]

SQLI_FLAG_ACCOUNTS = [
    ("svc-meters@example.com", "Meters Sync Service"),
    ("svc-alarms@example.com", "Alarms Sync Service"),
]

SQLI_TEACH_FLAG_VALUE = "__WG_SENTINEL_SQLI_TEACH__"
SQLI_EXERCISE_FLAG_VALUE = "__WG_SENTINEL_SQLI_EXERCISE__"
SQLI_BONUS_FLAG_VALUE = "__WG_SENTINEL_SQLI_BONUS__"

SESSIONID_ACCOUNT = ("fieldrelay@example.com", "n0t-f0r-hum4n-use-88x2", "Field Relay Unit")
SESSIONID_ACCOUNT_BASELINE_TOKEN = "100000"

BILL_PERIOD = "2026-09"
BILL_AMOUNTS = [42.17, 38.90, 51.05, 29.60, 47.33, 33.10, 55.82, 40.25]
TRAVERSAL_FLAG_METER = "MTR-1002"  # Ben Wood
