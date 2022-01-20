from django.urls import path

from . import views

app_name = 'recon'
urlpatterns = [
    # target urls
    path('', views.recon, name='home'),  # ex: /
    path('bye-data/', views.drop_table, name='clean'),  # ex: /recon/clean

    # Main APP Flow
    path('recon/', views.target, name='target'),  # ex: /recon/
    path('weaponize/', views.weaponize, name='weaponize'),  # ex: /weaponize/
    path('delivery/', views.delivery, name='delivery'),  # ex: /delivery/

    # Main page links
    path('exploits/', views.exploits, name='exploits'),  # ex: /exploits/


    # #path('<int:target_id>/recon/', views.detail, name='detail'),  # ex: /1/
    # path('<int:target_id>/recon/', views.detail, name='detail'),  # ex: /1/
    # path('<int:target_id>/recon/<int:services_id>/', views.weaponize, name='recon'),  # ex: /weaponize
    # #path('<int:target_id>/recon/<int:services_id>/weaponize/', views.weaponize, name='weaponize'),  # ex: /weaponize
    # #path('<int:target_id>/<int:services_id>/weaponize/', views.weaponize, name='weaponize'),  # ex: /weaponize
    #
    # # exploit url paths
    # path('<int:target_id>/recon/<int:services_id>/exploit/', views.pick_exploit, name='pick-exploit'),  # ex: /1/2/exploit/
    # path('<int:target_id>/recon/<int:services_id>/exploit/<int:exploit_id>/', views.run_exploit, name='run-exploit'),  # /1/3/exploit/3/
    # path('<int:target_id>/recon/<int:services_id>/module/', views.run_tool, name='run-tool'),  # /1/3/module/
    #
    # # recon tool/module urls
    # path('add-tool/', views.add_tool, name='add-tool'),  # ex: /add-tool/
    # path('tool/<int:tool_id>/', views.tool_detail, name='tool-detail'),  # ex: /tool/1/
    # path('tool/<int:tool_id>/edit/', views.edit_tool, name='edit-tool'),  # ex: /tool/1/edit
    # path('tool/<int:tool_id>/edit/remove/', views.delete_tool, name='delete-tool'),  # ex: /tool/1/edit/remove
    # # path('tool/<int:tool_id>/run/', views.run_tool, name='run-tool'),  # ex: /tool/1/edit/remove
    #
    # # drop table
    # path('clean/', views.drop_table, name='clean'),  # ex: /pentest/clean
    #
    # path('add-exploit/', views.add_exploit, name='add-exploit'),  # ex: /add-exploit
    # path('view-exploits/', views.view_exploits, name='view-exploits'),  # ex: /view-exploits
    # path('manual-exploit/', views.manual_exploit, name='manual-exploit'),  # ex: /add-exploit
    #
    # path('delivery/', views.view_delivery, name='delivery'),

    #path('<int:target_id>/<int:services_id>/exploit/<int:exploit_id>/', views.run_exploit, name='run-exploit'),  # ex: /1/3/exploit/
    # path('/run-exploit/', views.run_exploit, name='run-exploit'),  # ex: /pentest/add-exploit/
]
