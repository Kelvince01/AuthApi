from django.urls import path, include

from .views import RegistrationAPIView, LoginAPIView, UserRetrieveUpdateAPIView


app_name = 'Accounts'
urlpatterns = [
    path('user', UserRetrieveUpdateAPIView.as_view()),
    path('users', RegistrationAPIView.as_view()),
    path('users/login', LoginAPIView.as_view()),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]