"""Fixed lists the platform accepts: the query whitelist and the university's majors."""

QUERY_TYPES = {
    "graduates_count": "Number of graduates",
    "avg_gpa": "Average GPA",
    "coop_rate": "Cooperative-training completion rate",
}

FILTERS = ("major", "grad_year")  # both optional; values must exist in the data

MAJORS = (
    "Computer Science",
    "Cybersecurity",
    "Data Science",
    "Information Systems",
    "Software Engineering",
)

# Accepted graduation years for imported data
MIN_GRAD_YEAR, MAX_GRAD_YEAR = 2000, 2100
