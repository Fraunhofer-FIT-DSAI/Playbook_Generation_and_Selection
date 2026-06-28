import unittest
from math import prod

class TestSCADAProbabilityPropagation(unittest.TestCase):
    def setUp(self):
        # Minimal SCADA dependency model mock
        self.temp_model = {
            "A_1": {
                "id": 1,
                "name": "A",
                "dependencies": ["B", "C"],
                "type": "AND",
                "probability": 1.0,
            },
            "B_2": {
                "id": 2,
                "name": "B",
                "dependencies": ["D"],
                "type": "AND",
                "probability": 0.8,
            },
            "C_3": {
                "id": 3,
                "name": "C",
                "dependencies": [],
                "type": "AND",
                "probability": 0.7,
            },
            "D_4": {
                "id": 4,
                "name": "D",
                "dependencies": [],
                "type": "AND",
                "probability": 0.5,
            },
        }

    def update_probability(self, component):
        if component not in self.temp_model:
            return 1.0

        comp = self.temp_model[component]
        dependencies = [d for d in comp["dependencies"] if d]

        dep_probabilities = []
        for dep in dependencies:
            match_key = next((k for k, v in self.temp_model.items() if v["name"] == dep), None)
            if not match_key or match_key == component:
                dep_probabilities.append(1.0)
            else:
                dep_probabilities.append(self.update_probability(match_key))

        base = comp["probability"]
        if comp["type"] == "AND":
            result = base * prod(dep_probabilities)
        elif comp["type"] == "OR":
            result = base * (1 - prod(1 - p for p in dep_probabilities))
        else:
            result = base

        comp["computed_probability"] = result
        return result

    def test_probability_propagation(self):
        final_prob = self.update_probability("A_1")
        expected = 1.0 * (0.8 * 0.5) * 0.7  # = 0.28
        self.assertAlmostEqual(final_prob, expected, places=5)

if __name__ == "__main__":
    unittest.main()
