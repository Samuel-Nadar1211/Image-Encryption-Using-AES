from . import views
from django.urls import path

app_name = "cryptobox"
urlpatterns = [
    path("", views.index, name = "home"),
    path('encrypt/', views.encrypt, name='encrypt'),
    path('decrypt/', views.decrypt, name='decrypt'),
]