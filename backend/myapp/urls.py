from django.urls import path
from .views import signup_view, login_view, lookup_phone_number, logout_view, user_detail, auth_status

urlpatterns = [
    path('signup/', signup_view, name='signup'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('user/', user_detail, name='user_detail'),
    path('status/', auth_status, name='auth_status'),
    path('lookup/', lookup_phone_number, name='lookup'),
]
