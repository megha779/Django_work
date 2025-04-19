from django.urls import path
from .views import register_view, login_view, profile_view, user_profile_view,change_password,logout_view,current_user,user_profile,admin_user_list,admin_delete_user,admin_user_detail_update

urlpatterns = [
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('profile/', profile_view, name='profile'),
    path('user/', user_profile, name='user'),
    path('change-password/', change_password, name='change-password'),
    path('logout/', logout_view, name='logout'),
    path('current_user/', current_user, name='current_user'),
    path('user_profile/', user_profile_view, name='user_profile'),
    path('admin/users/list',admin_user_list, name='admin-user-list'),
    path('admin/users/delete/<int:user_id>/',admin_delete_user, name='admin-delete-user'),
    path('admin/users/details', admin_user_detail_update, name='admin-user-list-details'),
]

