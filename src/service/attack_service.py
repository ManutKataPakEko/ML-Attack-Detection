from inference.feature_extractor import FeatureExtractor
from proto import attack_pb2
from proto import attack_pb2_grpc
from utils.logger import get_logger
from api.database import insert_prediction

logger = get_logger("AttackService")


class AttackService(attack_pb2_grpc.AttackDetectionServicer):

    def __init__(self, predictor):
        self.predictor = predictor
        self.extractor = FeatureExtractor()

    def Predict(self, request, context):
        raw_data = {
            "timestamp": request.timestamp,
            "ip": request.ip,
            "method": request.method,
            "path": request.path,
            "query": request.query,
            "headers": dict(request.headers),
            "body": request.body,
        }

        logger.info(
            f"Incoming request from {raw_data['ip']} | {raw_data['method']} {raw_data['path']}"
        )

        features = self.extractor.extract_from_raw(raw_data)
        logger.debug(f"Extracted features: {features}")

        result = self.predictor.predict(features)
        label = "Normal" if result == 0 else "Attack"

        logger.info(f"Prediction: {label} | IP: {raw_data['ip']} | Path: {raw_data['path']}")

        insert_prediction({
            "timestamp": raw_data["timestamp"],
            "ip": raw_data["ip"],
            "method": raw_data["method"],
            "path": raw_data["path"],
            "query": raw_data["query"],
            "body": raw_data["body"],
            "headers": raw_data["headers"],
            "prediction": label,
        })

        return attack_pb2.PredictResponse(prediction=label)