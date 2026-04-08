import pickle

def load_model():
    with open("models/attack_detection_model.pkl", "rb") as f:
        model = pickle.load(f)
    return model