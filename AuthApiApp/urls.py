from django.urls import path, include

from .views import *
from rest_framework_simplejwt import views as jwt_views


app_name = 'authapiapp'
urlpatterns = [
    path('update', UserRetrieveUpdateAPIView.as_view(), name='update'),
    path('signup', RegistrationAPIView.as_view(), name='signup'),
    path('login', LoginAPIView.as_view(), name='login'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('signup/verify/', SignupVerify.as_view(),
         name='signup-verify'),
    path('password/reset/', PasswordReset.as_view(),
         name='password-reset'),
    path('password/reset/verify/', PasswordResetVerify.as_view(),
         name='password-reset-verify'),
    path('password/reset/verified/', PasswordResetVerified.as_view(),
         name='password-reset-verified'),
    path('password/change/', PasswordChange.as_view(),
         name='password-change'),
     path('token/', jwt_views.TokenObtainPairView.as_view(), name='token-obtain-pair'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token-refresh'),
]

#curl -X POST -H "Content-Type: application/json" -d '{"email":"kelvince05@gmail.com","password":"k@maa@05"} \http://localhost:8000/api/token/