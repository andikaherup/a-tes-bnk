from django.urls import path
from .views import (
    MyInfoAuthorizeView, 
    MyInfoCallbackView, 
    MyInfoDataView,
    MyInfoProfileView,
    MyInfoStatusView,
    MyInfoLogoutView,
    GenerateCodeChallengeView
)

urlpatterns = [
    path('authorize/', MyInfoAuthorizeView.as_view(), name='myinfo-authorize'),
    path('', MyInfoCallbackView.as_view(), name='myinfo-callback'),
    path('data/', MyInfoDataView.as_view(), name='myinfo-data'),
    path('generate-code-challenge/', GenerateCodeChallengeView.as_view(), name='generate-code-challenge'),
    path('profile/', MyInfoProfileView.as_view(), name='myinfo-profile'),
    path('status/', MyInfoStatusView.as_view(), name='myinfo-status'),
    path('logout/', MyInfoLogoutView.as_view(), name='myinfo-logout'),
]