from django.urls import path
from .views import delete_rules, get_rules_by_tag, register_user, login_user, get_profile, logout_user
from .views import create_member_by_owner, update_member_by_owner, delete_member_by_owner, list_members_by_owner, get_member_by_id

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('login/', login_user, name='login_user'),
    path('profile/', get_profile, name='get_profile'),
    path('logout/', logout_user, name='logout_user'),
    path('owner/create_member/', create_member_by_owner, name='create_member_by_owner'),
    path('owner/update_member/<int:user_id>/', update_member_by_owner, name='update_member_by_owner'),
    path('owner/delete_member/<int:user_id>/', delete_member_by_owner, name='delete_member_by_owner'),
    path('owner/list_members/', list_members_by_owner, name='list_members_by_owner'),
    path('owner/get_member/<int:member_id>/', get_member_by_id, name='get_member_by_id'),
    path('get_rules_by_tag/', get_rules_by_tag, name='get_rules_by_tag'),
    path('delete_rules/', delete_rules, name='delete_rules'),
]
