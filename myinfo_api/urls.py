from django.urls import path
from .views import MyInfoAuthorizeView, MyInfoCallbackView, MyInfoDataView

urlpatterns = [
    path('authorize/', MyInfoAuthorizeView.as_view(), name='myinfo-authorize'),
    path('callback/', MyInfoCallbackView.as_view(), name='myinfo-callback'),
    path('data/', MyInfoDataView.as_view(), name='myinfo-data'),
]