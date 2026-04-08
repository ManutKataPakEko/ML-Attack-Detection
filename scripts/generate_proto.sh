python -m grpc_tools.protoc \
--proto_path=proto \
--python_out=src/proto \
--grpc_python_out=src/proto \
proto/attack.proto