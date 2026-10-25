"""Intentionally incorrect implementation for the Codex repair exercise."""


def calculate_total(items, discount_percent=0):
    subtotal = sum(float(item["price"]) for item in items)
    return f"{subtotal * (1 + discount_percent / 100):.2f}"
