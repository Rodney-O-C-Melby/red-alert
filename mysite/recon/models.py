from django.db import models


# Create your models here.
class Target(models.Model):
    ip = models.CharField(max_length=30)
    hostname = models.CharField(max_length=255, blank=True)
    system = models.TextField(blank=True)
    kernel = models.TextField(blank=True, null=True)
    mac = models.CharField(max_length=17, blank=True)
    vendor = models.CharField(max_length=100, blank=True)
    cpe = models.TextField(blank=True, null=True)
    date = models.DateTimeField(null=True, blank=True)
    mode = models.IntegerField(default=1)


class ReconTool(models.Model):
    name = models.CharField(max_length=30)
    argv1 = models.CharField(max_length=255)
    argv2 = models.CharField(max_length=255, blank=True)
    argv3 = models.CharField(max_length=255, blank=True)
    argv4 = models.CharField(max_length=255, blank=True)
    argv5 = models.CharField(max_length=255, blank=True)
    argv6 = models.CharField(max_length=255, blank=True)
    argv7 = models.CharField(max_length=255, blank=True)
    argv8 = models.CharField(max_length=255, blank=True)
    argv9 = models.CharField(max_length=255, blank=True)


class ReconToolData(models.Model):
    tool_id = models.IntegerField(default=1)
    target_id = models.IntegerField(default=1)
    command = models.CharField(max_length=200)
    output = models.TextField(max_length=4096, blank=True)


class Services(models.Model):
    target_id = models.IntegerField(default=1)
    port_number = models.IntegerField(default=1)
    service = models.TextField(max_length=30)
    port_state = models.TextField(max_length=30)
    port_protocol = models.TextField(max_length=30)
    port_program = models.TextField(max_length=30, blank=True)
    port_version = models.CharField(max_length=30, blank=True)
    port_extra_info = models.TextField(blank=True)
    port_script = models.TextField(blank=True)

    def get_clean_service(self):  # removes dashes from services for matching exploits - clean name
        return self.service.replace('-', ' ')


class Exploit(models.Model):
    name = models.CharField(max_length=200)  # name of the exploit (your own ref)
    system = models.TextField(max_length=30, blank=True)  # exploit target os
    protocol = models.CharField(max_length=30, blank=True)  # exploit protocol
    program = models.CharField(max_length=50, blank=True)  # exploit program name
    versions = models.CharField(max_length=80, blank=True)  # vulnerable versions
    cve = models.CharField(max_length=12, blank=True)  # CVE
    cvs = models.FloatField(blank=True)  # CVSS Score
    args = models.CharField(max_length=255, blank=True)  # exploit arguments
    language = models.CharField(max_length=30)  # exploit language
    url = models.CharField(max_length=255, blank=True)  # exploit url
    location = models.CharField(max_length=255, blank=True)  # exploit path


# class Scan(models.Model):
#     target_id = models.IntegerField(default=1)
#     vuln_title =
#
# class Attack(models.Model):
#     target_id = models.IntegerField(default=1)
#     target_id = models.IntegerField(default=1)
# class Delivery(models.Model):
#     #tid = models.IntegerField(default=1)
#     name = models.CharField(max_length=200)  # name of the exploit (your own ref)
