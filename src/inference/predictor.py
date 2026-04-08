import pandas as pd

class AttackPredictor:
    def __init__(self, model):
        self.model = model
        self.features = [
            "endpoint_length",
            "has_sql",
            "has_script",
            "has_path_traversal",
            "param_count",
            "has_query"
        ]

    def predict(self, data: dict):
        df = pd.DataFrame([data])
        pred = self.model.predict(df[self.features])
        return int(pred[0])