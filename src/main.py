import grpc
from concurrent import futures

from inference.model_loader import load_model
from inference.predictor import AttackPredictor

from service.attack_service import AttackService
import proto.attack_pb2_grpc as attack_pb2_grpc


def serve():

    # load model sekali saat start
    model = load_model()
    predictor = AttackPredictor(model)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    attack_pb2_grpc.add_AttackDetectionServicer_to_server(
        AttackService(predictor),
        server
    )

    server.add_insecure_port("[::]:50051")

    print("Attack Detection gRPC Server running on port 50051...")

    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()