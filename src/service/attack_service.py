from inference.feature_extractor import FeatureExtractor
from inference.classifier_loader import load_attack_classifier
from proto import attack_pb2
from proto import attack_pb2_grpc
from utils.logger import get_logger
from api.database import insert_prediction

logger = get_logger("AttackService")


class AttackService(attack_pb2_grpc.AttackDetectionServicer):

    def __init__(self, predictor, classifier=None):
        self.predictor = predictor
        self.classifier = classifier
        self.extractor = FeatureExtractor()
        
        if self.classifier:
            logger.info("Attack classification enabled")
        else:
            logger.warning("Attack classification not available")

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
        
        # Classify attack type jika terdeteksi sebagai attack
        attack_type = None
        attack_confidence = None
        
        if result == 1 and self.classifier:
            try:
                classification_result = self.classifier.classify(features)
                attack_type = classification_result['attack_type']
                attack_confidence = classification_result['confidence']
                logger.info(
                    f"Attack classified as: {attack_type} (confidence: {attack_confidence:.2%})"
                )
            except Exception as e:
                logger.error(f"Error during attack classification: {str(e)}")
                attack_type = "unknown"
                attack_confidence = 0.0

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
            "attack_type": attack_type,
            "attack_confidence": attack_confidence,
        })

        return attack_pb2.PredictResponse(prediction=label)