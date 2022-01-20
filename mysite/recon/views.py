from django.contrib import messages
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponseRedirect
from django.utils import timezone
from django.utils.datastructures import MultiValueDictKeyError

from .redalert import valid_ip, valid_host, set_nmap_args, valid_net, nmap_scan, parse_nmap_scan
from .redalert import parse_searchsploit_json, os_execute, execute, cve_search # run_vulners_cpe, run_vulners_software, run_vulners_query, print_dict
from .models import Target, Services, ReconTool, Exploit
from .forms import ScanForm, AddToolForm, AddExploitForm, AddExploitFormManual

import json
import datetime


# Create your views here.
def recon(request):
    """ Recon page. Home scanning page. GET and POST. """
    if request.method == 'GET':  # GET request
        form = ScanForm()
        targets = Target.objects.order_by('-date')  # get targets
        modules = ReconTool.objects.order_by('id')  # get recon tools
        context = {'targets': targets, 'modules': modules, 'form': form}  # data for view
        return render(request, 'recon/recon.html', context)  # render template
    if request.method == 'POST':  # POST form data
        form = ScanForm(request.POST)  # create a form with data from the request
        if form.is_valid():  # check form validity
            scan_ip = form.cleaned_data['ip_or_host']  # get ip or hostname
            mode = form.cleaned_data['ip_protocol']  # get user choice of scan
            date = datetime.datetime.now(tz=timezone.utc)  # create scan date
            is_ip = valid_ip(scan_ip)  # true if valid possible ip
            is_host = valid_host(scan_ip)  # true if valid possible hostname
            scan = set_nmap_args(mode, scan_ip)  # get nmap args
            # nmap -sV -oX file.xml 192.168.1.254

            # error checking
            if not is_ip and not is_host:  # not ip or hostname
                if not valid_net(scan_ip):  # not network, so error
                    messages.error(request, 'Invalid IP, hostname, or network.')  # error message
                    return HttpResponseRedirect("/")  # redirect

            # run nmap scan
            host_list, data = nmap_scan(scan_ip, scan, date.strftime("%m-%d-%Y-%H:%M:%S"))

            # error if no hosts found
            if len(host_list) == 0:
                messages.error(request, 'No route to ' + scan_ip + ', please check host or IP exists, and is pingable.')
                return HttpResponseRedirect("/")  # redirect

            num = 0
            ip, system, kernel, hostname, product, version, extra, script, cpe = "", "", "", "", "", "", "", "", ""
            # for each ip found
            for ip, status in host_list:
                if status == "up":
                    # TODO: load scan data from file ? quicker?
                    hostname, system, kernel, protocol, vendor, mac, cpe, ports = parse_nmap_scan(data[ip])  # get data
                    targets = Target(ip=ip, hostname=hostname, system=system, kernel=kernel, date=date, mode=int(mode),
                                     mac=mac, vendor=vendor, cpe=cpe)
                    targets.save()  # save basic scan data to database

                    # run vulners cpe scan
                    #if product != "" and version != "":
                    # svl = run_vulners_cpe(cpe)
                    # print("CPE VULN LIST\n")
                    # print(svl)

                    # # run vulners query of os and kernel
                    # res = run_vulners_query(
                    #     "affectedSoftware.name:Linux AND affectedSoftware.version:'3.4.11' AND cvss.score:[7 TO 10]")
                    # size = len(res)
                    # print(size)
                    #

                    # parse port info and save each port to database
                    for port in ports:
                        state = ports[port]["state"]
                        name = ports[port]["name"]
                        if "product" in ports[port]:
                            product = ports[port]["product"]
                        if "version" in ports[port]:
                            version = ports[port]["version"]
                        if "extrainfo" in ports[port]:
                            extra = ports[port]["extrainfo"]
                        if "script" in ports[port]:
                            script = ports[port]["script"]

                        # # run vulners scan for software vulns
                        #run_vulners_software(name, version)
                        # cve = cve_search(product)
                        # if product != "" and version != "":
                        #     svl = run_vulners_software(name, version)
                        #     print("SOFTWARE VULN LIST\n\n")
                        #     print(svl)

                        # save ports
                        services = Services(target_id=targets.pk, port_number=int(port), service=name, port_state=state,
                                            port_protocol=protocol, port_program=product, port_version=version,
                                            port_extra_info=extra, port_script=script)
                        services.save()  # save port info to database
                        num = targets.pk

            # run searchsploit to create json
            command = "searchsploit --nmap mysite/recon/output/scans/" + date.strftime("%m-%d-%Y-%H:%M:%S") \
                      + ".xml -j > mysite/recon/output/exploits/" + date.strftime("%m-%d-%Y-%H:%M:%S") + ".json"
            status = os_execute(command)
            if status != 0:
                print("ERROR Searchsploit no good")

            # Redirect for one scan
            if len(host_list) == 1:  # only one ip scanned
                messages.success(request, 'Scan of ' + str(scan_ip) + ' successfully completed.')  # add message
                return HttpResponseRedirect("/recon?tid=" + str(num))  # redirect

            # Redirect for multiple scans
            if len(host_list) > 1:  # more than one ip scanned
                messages.success(request, 'Scan of ' + str(scan_ip) + ' successfully completed.')  # add message
                return HttpResponseRedirect("/")  # redirect
        else:  # form not valid
            messages.error(request, 'No IP or Hostname.')  # error message
            return HttpResponseRedirect("/")  # redirect


def drop_table(request):
    """ Deletes all database tables. """
    Target.objects.all().delete()
    ReconTool.objects.all().delete()
    Services.objects.all().delete()
    Exploit.objects.all().delete()
    messages.success(request, 'Successfully deleted data.')
    return HttpResponseRedirect("/")  # redirect


def target(request):
    """ Target page. Shows targets services. GET and POST. """
    if request.method == 'GET':
        tid = request.GET['tid']
        targeted = get_object_or_404(Target, pk=tid)  # get selected target
        services = Services.objects.filter(target_id=tid).order_by('id')  # get ports
        filename = targeted.date.strftime("%m-%d-%Y-%H:%M:%S")  # get date as string from db target table
        exploit_db = parse_searchsploit_json('mysite/recon/output/exploits/' + filename + '.json')  # parse json file into obj

        #run_vulners_cpe(cpe_list)
        #print("CPE: " + targeted.cpe)

        #exploit_v, vulnerabilities_v = run_vulners_software(targeted.system, targeted.kernel)

        for x in range(0, len(services)):
            product = services[x].port_program
            service = services[x].service
            #print(service)
            #print(product)

            cve = cve_search(product)
            print(cve)
        #print(targeted.kernel)

        # run vulners query of os and kernel

        #k_info = run_vulners_query("type: " + targeted.system + " cvss.score:[8 TO 10] order:published")

        #k_info = run_vulners_query("affectedSoftware.name:Linux AND affectedSoftware.version:'3.4.11' AND cvss.score:[7 TO 10]")
        #k_info = run_vulners_query("affectedSoftware.name:" + targeted.system + " AND affectedSoftware.version:'" + targeted.kernel + "'")
        #print(k_info)
        #request.session['res'] = res  # add session data of vulners query, for use in view

        context = {'target': targeted, 'services': services, 'exploit_db': exploit_db}
        return render(request, 'recon/target.html', context)
    if request.method == 'POST':
        tid = request.POST["tid"]
        try:  # catch no service selected error
            service_id = request.POST["checkbox"]
            return HttpResponseRedirect("/weaponize/?tid=" + str(tid) + "&sid=" + str(service_id))  # redirect
        except MultiValueDictKeyError:
            messages.error(request, 'Please select a port to test for vulnerabilities.')  # add message
            return HttpResponseRedirect("/recon/" + str(tid) + "/")  # redirect


def weaponize(request):
    """ Weaponize page. Shows target, service, and exploits. GET and POST. """
    if request.method == 'GET':
        tid = request.GET['tid']
        sid = request.GET['sid']
        targeted = get_object_or_404(Target, pk=tid)  # get selected target
        service = get_object_or_404(Services, pk=sid)  # get selected port
        exploits = Exploit.objects.all().order_by('id')  # get exploits
        modules = ReconTool.objects.all().order_by('id')  # get recon module tools
        filename = targeted.date.strftime("%m-%d-%Y-%H:%M:%S")  # get date as string from db target table
        edb = parse_searchsploit_json('mysite/recon/output/exploits/' + filename + '.json')  # parse json file into obj
        #print(edb)
        context = {'target': targeted, 'service': service, 'exploit_db': edb, 'modules': modules, 'exploits': exploits}
        return render(request, 'recon/weaponize.html', context)
    if request.method == 'POST':
        tid = request.POST["tid"]
        sid = request.POST["sid"]
        try:  # catch no service selected error
            exploit_title = request.POST["eid"]
            targeted = get_object_or_404(Target, pk=tid)  # get selected target
            filename = targeted.date.strftime("%m-%d-%Y-%H:%M:%S")  # get date as string from db target table
            edb = parse_searchsploit_json('mysite/recon/output/exploits/' + filename + '.json')  # parse json file into obj

            # set edb id as EDB-ID not parsable by django
            edb_id = 0
            for result_set in edb:
                for exploit in result_set["RESULTS_EXPLOIT"]:
                    if exploit["Title"] == exploit_title:
                        edb_id = exploit["EDB-ID"]

            return HttpResponseRedirect("/delivery/?tid=" + str(tid) + "&sid=" + str(sid) + "&eid=" + str(edb_id))
        except MultiValueDictKeyError:
            messages.error(request, 'Please select an exploit to deliver to the target.')  # add message
            return HttpResponseRedirect("/weaponize/?tid=" + str(tid) + "&sid=" + str(sid))  # redirect


def exploits(request):
    if request.method == 'POST':
        search = request.POST['search']
        tid = request.POST["tid"]
        sid = request.POST["sid"]
        print(search)
        command = "searchsploit -j " + search
        command_list = command.split(' ')
        print(command_list)
        p = execute(command_list)
        output = p.stdout
        print(output)

        obj = json.loads(output)

        targeted = get_object_or_404(Target, pk=tid)  # get selected target
        service = get_object_or_404(Services, pk=sid)  # get selected port
        context = {'target': targeted, 'service': service, 'exploit_search': obj}
        return render(request, 'recon/weaponize.html', context)

    if request.method == 'GET':
        tid, sid, eid = 0, 0, 0

        tid = request.GET['tid']
        sid = request.GET['sid']
        try:
            eid = request.GET['eid']
        except MultiValueDictKeyError:  # no eid show all exploits
            test = 1

        targeted = get_object_or_404(Target, pk=tid)  # get selected target
        service = get_object_or_404(Services, pk=sid)  # get selected port
        exploits = Exploit.objects.all().order_by('id')  # get exploits
        modules = ReconTool.objects.all().order_by('id')  # get recon module tools

        # # run searchsploit to create json
        # command = "searchsploit --nmap recon/output/scans/" + date.strftime("%m-%d-%Y-%H:%M:%S") \
        #           + ".xml -j > recon/output/exploits/" + date.strftime("%m-%d-%Y-%H:%M:%S") + ".json"
        #
        # execute(input_list)
        # status = os_execute(command)
        # if status != 0:
        #     print("ERROR Searchsploit no good")

        filename = targeted.date.strftime("%m-%d-%Y-%H:%M:%S")  # get date as string from db target table
        edb = parse_searchsploit_json('mysite/recon/output/exploits/' + filename + '.json')  # parse json file into obj
        edb_row = 0
        for result_set in edb:
            for exploit in result_set["RESULTS_EXPLOIT"]:
                if exploit["EDB-ID"] == eid:
                    edb_row = exploit

        #print(edb)
        context = {'target': targeted, 'service': service, 'edb_row': edb_row, 'eid': eid, 'modules': modules, 'exploits': exploits}
        return render(request, 'recon/weaponize.html', context)


def delivery(request):
    """ Delivery page. Shows target, service, exploit, and delivery choices. GET and POST. """
    if request.method == 'GET':
        tid = request.GET['tid']
        sid = request.GET['sid']
        eid = request.GET['eid']
        targeted = get_object_or_404(Target, pk=tid)  # get selected target
        service = get_object_or_404(Services, pk=sid)  # get selected port
        exploits = Exploit.objects.all().order_by('id')  # get exploits
        modules = ReconTool.objects.all().order_by('id')  # get recon module tools

        filename = targeted.date.strftime("%m-%d-%Y-%H:%M:%S")  # get date as string from db target table
        edb = parse_searchsploit_json('mysite/recon/output/exploits/' + filename + '.json')  # parse json file into obj
        # filter exploit db results
        edb_row = 0
        for result_set in edb:
            for exploit in result_set["RESULTS_EXPLOIT"]:
                if exploit["EDB-ID"] == eid:
                    edb_row = exploit

        # print(edb)
        # print(edb_row)
        filepath = edb_row["Path"]
        with open(filepath) as f:
            lines = f.readlines()
        data = ''.join(lines)

        context = {'target': targeted, 'service': service, 'edb_row': edb_row, 'eid': eid, 'data': data, 'modules': modules, 'exploits': exploits}
        return render(request, 'recon/delivery.html', context)
    #if request.method == 'POST':