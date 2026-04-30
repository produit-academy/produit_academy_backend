from django.urls import path
from .views import JobApplicationCreateView

urlpatterns = [
    path('apply/', JobApplicationCreateView.as_view(), name='career-apply'),
]