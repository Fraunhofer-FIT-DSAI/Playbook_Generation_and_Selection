from not_used_longer.cio_calculator import calculate_CiO, find_top_components, is_categorical_grouping
import unittest
from math import isclose
""" Test for the core functionality of the cio_calculator  """


class TestCiOCalculator(unittest.TestCase):
    def setUp(self):
        """Setup a sample dependency model for testing with extra depth on SubA."""
        self.dependency_model = {
            "SystemDescription": {
                'id': '1',
                "name": "System",
                "dependencies": "ComponentA, ComponentB",
                "type": "AND",
                "status": 1
            },
            "Component_A": {
                'id': '2',
                "name": "ComponentA",
                "dependencies": "SubA, SubB",
                "type": "OR",
                "status": 1
            },
            "Component_B": {
                'id': '3',
                "name": "ComponentB",
                "dependencies": "SubC, SubD",
                "type": "AND",
                "status": 1
            },
            "Sub_A": {
                'id': '4',
                "name": "SubA",
                "dependencies": "SubA1, SubA2",
                "type": "AND",
                "status": 1
            },
            "Sub_B": {
                'id': '5',
                "name": "SubB",
                "dependencies": '',
                "type": "AND",
                "status": 1
            },
            "Sub_C": {
                'id': '6',
                "name": "SubC",
                "dependencies": '',
                "type": "AND",
                "status": 1
            },
            "Sub_D": {
                'id': '7',
                "name": "SubD",
                "dependencies": '',
                "type": "AND",
                "status": 1
            },
            "Sub_A1": {
                'id': '8',
                "name": "SubA1",
                "dependencies": '',
                "type": "AND",
                "status": 1
            },
            "Sub_A2": {
                'id': '9',
                "name": "SubA2",
                "dependencies": '',
                "type": "AND",
                "status": 1
            }
        }


    def test_no_affected_components(self):
        """Test when no components are affected, CiO should be 0."""
        affected_components = []
        top = find_top_components(self.dependency_model)
        result = calculate_CiO(affected_components, self.dependency_model, top)
        expected_value = 0.0  # No impact expected
        self.assertTrue(isclose(result, expected_value, rel_tol=1e-3), f"Expected CiO={expected_value}, but got {result}")

    def test_affected_component_with_and_logic(self):
        """Test when a component with AND dependencies is affected."""
        top = find_top_components(self.dependency_model)
        affected_components = ["SubC"]
        expected_value = 0.5  # Expected degradation based on AND logic
        result = calculate_CiO(affected_components, self.dependency_model, top)
        self.assertTrue(isclose(result, expected_value, rel_tol=1e-3), f"Expected CiO={expected_value}, but got {result}")

    def test_affected_component_with_or_logic(self):
        """Test when a component with OR dependencies is affected."""
        top = find_top_components(self.dependency_model)
        affected_components = ["SubA"]
        expected_value = 0  # Expected degradation based on OR logic
        result = calculate_CiO(affected_components, self.dependency_model, top)
        print(f"\nDEBUG: Test OR Logic -> Expected: {expected_value}, Got: {result}")
        self.assertTrue(isclose(result, expected_value, rel_tol=1e-3), f"Expected CiO={expected_value}, but got {result}")

    def test_affected_component_with_both_logics(self):
        """Test when components with both AND and OR dependencies are affected."""
        top = find_top_components(self.dependency_model)
        affected_components = ["SubA", "SubC"]
        expected_value = 0.5  # Expected degradation based on mixed logic
        result = calculate_CiO(affected_components, self.dependency_model, top)
        print(f"\nDEBUG: Test Mixed AND/OR Logic -> Expected: {expected_value}, Got: {result}")
        self.assertTrue(isclose(result, expected_value, rel_tol=1e-3), f"Expected CiO={expected_value}, but got {result}")
        
    def test_multiple_top_components(self):
        """Test CiO calculation when there are multiple top components."""
        top = find_top_components(self.dependency_model)
        affected_components = ["SubA", "SubB","SubC","SubD"]
        expected_value = 0.8125  # 1-CIO
        result = calculate_CiO(affected_components, self.dependency_model, top)
        print(f"\nDEBUG: Test multiple component Logic -> Expected: {expected_value}, Got: {result}")
        self.assertTrue(isclose(result, expected_value, rel_tol=1e-3), f"Expected CiO={expected_value}, but got {result}")
        
    def test_with_nested_dependencies(self):
        """Test when SubA1 and SubB are affected — both children of ComponentA."""
        top = find_top_components(self.dependency_model)
        affected_components = ["SubA1", "SubB"]

        # SubA = 0.5 (SubA1=0.5, SubA2=1.0, AND)
        # SubB = 0.5
        # ComponentA = OR(0.5, 0.5) = 0.75
        # ComponentB = 1.0 (unchanged)
        # System = AND(0.75, 1.0) = 0.75
        # CiO = 1.0 - 0.75 = 0.25

        expected_value = 0.25
        result = calculate_CiO(affected_components, self.dependency_model, top)
        print(f"\nDEBUG: Test SubA1 & SubB Affected -> Expected: {expected_value}, Got: {result}")
        self.assertTrue(isclose(result, expected_value, rel_tol=1e-3))
        

class TestSemanticHeuristics(unittest.TestCase):
    def test_is_categorical_grouping(self):

        test_cases = [
            ("PLCs are Ok", ["Safety PLC is Ok", "Ladder logic is Ok", "Control function is Ok", "Settings are Ok"], True),
            ("Meters are Ok", ["Customer meters are Ok", "Interllegent meters are Ok"], False),
            ("Zones are Ok", [], True),
            ("Power supply is Ok", [], False),
            ("Employees are Ok", ["Training is Ok", "Awareness is Ok"], True),
            ("Field devices are Ok", ["IEDs are Ok", "PLCs are Ok", "Sensors are Ok"], False),
            ("Sensor readings are Ok", ["Primary/raw data is Ok", "Analysed data is Ok", "Backup data is Ok"], True),
            ("Alarms are Ok", ["Control system generated alarms are OK", "Field device generated alarms are Ok"], False),
            ("Alarms issuing and control are Ok", ["Thresholds are Ok", "View of all alarms is Ok", "Alarm activation is Ok"], True),
            ("Software applications in use are Okay", ["GIS system is Ok", "Customer invoicing system is Ok", "Remote maintenance software is Ok"], True),
            ("HMI workstations are Ok", ["Graphic card is Ok", "Ergonomics is Ok", "Client application is Ok"], True)
        ]


        for desc, children, expected in test_cases:
            result = is_categorical_grouping(desc, children)
            self.assertEqual(result, expected, f"Failed on: '{desc}' with children {children}")


if __name__ == "__main__":
    unittest.main()
