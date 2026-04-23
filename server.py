from secure_review.env_loader import load_dotenv
from secure_review.app import run


if __name__ == "__main__":
    load_dotenv()
    run()
