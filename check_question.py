import os
import django
import sys

# Add the project root to the python path
sys.path.append(os.getcwd())

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "produit_academy_backend.settings")
django.setup()

from api.models import Question

try:
    q = Question.objects.get(id=4)
    print(f"Question 4 exists: {q}")
except Question.DoesNotExist:
    print("Question 4 does NOT exist")
except Exception as e:
    print(f"Error: {e}")

print("All Question IDs:", list(Question.objects.values_list('id', flat=True)))
