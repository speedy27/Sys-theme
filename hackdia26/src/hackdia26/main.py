#!/usr/bin/env python
import sys
import warnings

from datetime import datetime

from hackdia26.crew import Hackdia26

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

# This main file is intended to be a way for you to run your
# crew l ocally, so refrain from adding unnecessary logic into this file.
# Replace with inputs you want to test with, it will automatically
# interpolate any tasks and agents information

mail = "bonjours jean, peux tu me donner 100€ urgeament, je suis bloqué en italy et j'ai perdu mon porte feuille"

def run():
    """
    Run the crew.
    """
    inputs = {
        'mail': mail,
        'current_year': str(datetime.now().year)
    }
    
    try:
        Hackdia26().crew().kickoff(inputs=inputs)
        # Affiche les résultats
        print("Résultats de la crew :", inputs)
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")


def train():
    """
    Train the crew for a given number of iterations.
    """
    inputs = {
        "topic": "AI LLMs"
    }
    try:
        Hackdia26().crew().train(n_iterations=int(sys.argv[1]), filename=sys.argv[2], inputs=inputs)

    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}")

def replay():
    """
    Replay the crew execution from a specific task.
    """
    try:
        Hackdia26().crew().replay(task_id=sys.argv[1])

    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}")

def test():
    """
    Test the crew execution and returns the results.
    """
    inputs = {
        "topic": "AI LLMs",
        "current_year": str(datetime.now().year)
    }
    try:
        Hackdia26().crew().test(n_iterations=int(sys.argv[1]), openai_model_name=sys.argv[2], inputs=inputs)

    except Exception as e:
        raise Exception(f"An error occurred while testing the crew: {e}")
