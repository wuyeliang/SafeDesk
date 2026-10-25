"""Acceptance tests. Keep these unchanged while repairing pricing.py."""
import unittest

from pricing import calculate_total


class PricingAcceptanceTest(unittest.TestCase):
    def test_empty_cart(self):
        self.assertEqual(calculate_total([]), "0.00")

    def test_multiple_quantities(self):
        items = [{"price": "19.90", "qty": 3}, {"price": "5.50", "qty": 1}]
        self.assertEqual(calculate_total(items), "65.20")

    def test_discount_reduces_total(self):
        self.assertEqual(calculate_total([{"price": "10.00", "qty": 1}], 10), "9.00")

    def test_half_up_rounding(self):
        self.assertEqual(calculate_total([{"price": "0.05", "qty": 1}], 10), "0.05")

    def test_zero_price(self):
        self.assertEqual(calculate_total([{"price": "0.00", "qty": 2}]), "0.00")

    def test_single_item(self):
        self.assertEqual(calculate_total([{"price": "3.50", "qty": 1}]), "3.50")

    def test_decimal_arithmetic(self):
        self.assertEqual(calculate_total([{"price": "0.10", "qty": 3}]), "0.30")

    def test_full_discount(self):
        self.assertEqual(calculate_total([{"price": "10.00", "qty": 2}], 100), "0.00")

    def test_fractional_discount(self):
        self.assertEqual(calculate_total([{"price": "8.00", "qty": 1}], 12.5), "7.00")

    def test_round_only_final_total(self):
        items = [{"price": "0.05", "qty": 1}, {"price": "0.05", "qty": 1}]
        self.assertEqual(calculate_total(items, 10), "0.09")

    def test_half_up_tie(self):
        self.assertEqual(calculate_total([{"price": "0.05", "qty": 1}], 50), "0.03")

    def test_large_quantity(self):
        self.assertEqual(calculate_total([{"price": "0.01", "qty": 10000}]), "100.00")

    def test_negative_price_rejected(self):
        with self.assertRaises(ValueError):
            calculate_total([{"price": "-1.00", "qty": 1}])

    def test_non_positive_quantity_rejected(self):
        for quantity in [0, -1]:
            with self.subTest(quantity=quantity), self.assertRaises(ValueError):
                calculate_total([{"price": "1.00", "qty": quantity}])

    def test_non_integer_quantity_rejected(self):
        for quantity in [1.5, True, "2"]:
            with self.subTest(quantity=quantity), self.assertRaises(ValueError):
                calculate_total([{"price": "1.00", "qty": quantity}])

    def test_non_finite_price_rejected(self):
        for price in ["NaN", "Infinity", "-Infinity"]:
            with self.subTest(price=price), self.assertRaises(ValueError):
                calculate_total([{"price": price, "qty": 1}])

    def test_non_finite_discount_rejected(self):
        for discount in [float("nan"), float("inf"), float("-inf")]:
            with self.subTest(discount=discount), self.assertRaises(ValueError):
                calculate_total([{"price": "1.00", "qty": 1}], discount)

    def test_invalid_discount_rejected(self):
        for discount in [-1, 101]:
            with self.subTest(discount=discount), self.assertRaises(ValueError):
                calculate_total([{"price": "1.00", "qty": 1}], discount)


if __name__ == "__main__":
    unittest.main()
