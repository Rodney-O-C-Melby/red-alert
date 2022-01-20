from django import forms


class AddToolForm(forms.Form):
    tool_name = forms.CharField(label='Program', max_length=30)
    tool_argv1 = forms.CharField(label='Argv1', max_length=255, required=False)
    tool_argv2 = forms.CharField(label='Argv2', max_length=255, required=False)
    tool_argv3 = forms.CharField(label='Argv3', max_length=255, required=False)
    tool_argv4 = forms.CharField(label='Argv4', max_length=255, required=False)
    tool_argv5 = forms.CharField(label='Argv5', max_length=255, required=False)
    tool_argv6 = forms.CharField(label='Argv6', max_length=255, required=False)
    tool_argv7 = forms.CharField(label='Argv7', max_length=255, required=False)
    tool_argv8 = forms.CharField(label='Argv8', max_length=255, required=False)
    tool_argv9 = forms.CharField(label='Argv9', max_length=255, required=False)

    # initialize placeholders into form
    def __init__(self, *args, **kwargs):
        super(AddToolForm, self).__init__(*args, **kwargs)
        self.fields['tool_name'].widget.attrs['placeholder'] = 'onesixtyone'
        self.fields['tool_argv1'].widget.attrs['placeholder'] = '-c'
        self.fields['tool_argv2'].widget.attrs['placeholder'] = '/usr/share/onesixtyone/dict.txt'


class ScanForm(forms.Form):
    protocols = (("1", "TCP"), ("2", "UDP"), ("3", "Silent"), ("4", "Attack"), ("5", "Nmap"))  # create select values
    ip_protocol = forms.ChoiceField(label='', choices=protocols)  # create select dropdown
    ip_or_host = forms.CharField(label='', max_length=255, required=True)

    # initialize placeholders into form
    def __init__(self, *args, **kwargs):
        super(ScanForm, self).__init__(*args, **kwargs)
        self.fields['ip_or_host'].widget.attrs['placeholder'] = '10.0.0.1, localhost, 10.0.0.1/24, -Pn 10.0.0.1'  # placeholder
        self.fields['ip_or_host'].widget.attrs['class'] = 'form-control'
        self.fields['ip_or_host'].widget.attrs['style'] = 'width:63%;'
        self.fields['ip_protocol'].widget.attrs['class'] = 'form-select'  # set class for select
        self.fields['ip_protocol'].widget.attrs['style'] = 'width:22%;'


class AddExploitForm(forms.Form):
    # input attributes and placeholders
    def __init__(self, *args, **kwargs):
        super(AddExploitForm, self).__init__(*args, **kwargs)
        # initialize placeholders into form
        self.fields['exploit_name'].widget.attrs['placeholder'] = 'Drupalgeddon2'
        self.fields['exploit_program'].widget.attrs['placeholder'] = 'Drupal'
        self.fields['exploit_version'].widget.attrs['placeholder'] = '7.0-7.57'
        self.fields['exploit_cve'].widget.attrs['placeholder'] = '2018-7600'
        self.fields['exploit_cvs'].widget.attrs['placeholder'] = '9.8'
        self.fields['exploit_args'].widget.attrs['placeholder'] = '-c id -h'
        self.fields['exploit_language'].widget.attrs['placeholder'] = 'Python'
        self.fields['exploit_url'].widget.attrs['placeholder'] = 'https://raw.githubusercontent.com/lorddemon/' \
                                                                 'drupalgeddon2/master/drupalgeddon2.py'
        # set form class attribute
        self.fields['exploit_language'].widget.attrs['class'] = 'form-select'  # set clean dropdown
        self.fields['exploit_system'].widget.attrs['class'] = 'form-select'
        self.fields['exploit_protocol'].widget.attrs['class'] = 'form-select'
        self.fields['exploit_name'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_program'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_version'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_cve'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_cvs'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_args'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_url'].widget.attrs['class'] = 'form-control'

    # input selections for dropdowns
    oses = (
        ("Linux", "Linux"),
        ("Windows", "Win"),
        ("Mac", "Mac"),
        ("Android", "Android"),
        ("IOS", "IOS")
    )
    protocols = (("tcp", "TCP"), ("udp", "UDP"))
    languages = (("Python", "Python"), ("Bash", "Bash"), ("Ruby", "Ruby"))

    # form inputs
    exploit_url = forms.CharField(label='URL', max_length=255, required=False)
    exploit_name = forms.CharField(label='Name', max_length=100)
    exploit_program = forms.CharField(label='Program', max_length=100, required=False)
    exploit_version = forms.CharField(label='Versions', max_length=100, required=False)
    exploit_cve = forms.CharField(label='CVE', max_length=100, required=False)
    exploit_cvs = forms.CharField(label='CVSS', max_length=5, required=False)
    exploit_args = forms.CharField(label='Arguments', max_length=100)
    exploit_system = forms.ChoiceField(label='OS', choices=oses)
    exploit_language = forms.ChoiceField(label='Language', choices=languages)
    exploit_protocol = forms.ChoiceField(label='Protocol', choices=protocols)


class AddExploitFormManual(forms.Form):
    # input attributes and placeholders
    def __init__(self, *args, **kwargs):
        super(AddExploitFormManual, self).__init__(*args, **kwargs)
        # initialize placeholders into form
        self.fields['exploit_name'].widget.attrs['placeholder'] = 'Drupalgeddon2'
        self.fields['exploit_program'].widget.attrs['placeholder'] = 'Drupal'
        self.fields['exploit_version'].widget.attrs['placeholder'] = '7.0-7.57'
        self.fields['exploit_cve'].widget.attrs['placeholder'] = '2018-7600'
        self.fields['exploit_cvs'].widget.attrs['placeholder'] = '9.8'
        self.fields['exploit_language'].widget.attrs['placeholder'] = 'Python'
        self.fields['exploit'].widget.attrs['placeholder'] = 'import pty; pty.spawn("/bin/bash")'
        # set form class attribute
        self.fields['exploit_language'].widget.attrs['class'] = 'form-select'  # set clean dropdown
        self.fields['exploit_system'].widget.attrs['class'] = 'form-select'
        self.fields['exploit_protocol'].widget.attrs['class'] = 'form-select'
        self.fields['exploit_name'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_program'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_version'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_cve'].widget.attrs['class'] = 'form-control'
        self.fields['exploit_cvs'].widget.attrs['class'] = 'form-control'
        self.fields['exploit'].widget.attrs['class'] = 'form-control'

    # input selections for dropdowns
    oses = (
        ("Linux", "Linux"),
        ("Windows", "Win"),
        ("Mac", "Mac"),
        ("Android", "Android"),
        ("IOS", "IOS")
    )
    protocols = (("tcp", "TCP"), ("udp", "UDP"))
    languages = (("Python", "Python"), ("Bash", "Bash"), ("Ruby", "Ruby"))

    # form inputs
    exploit = forms.CharField(widget=forms.Textarea(attrs={"rows": 5, "cols": 20}))
    exploit_name = forms.CharField(label='Name', max_length=100)
    exploit_program = forms.CharField(label='Program', max_length=100, required=False)
    exploit_version = forms.CharField(label='Versions', max_length=100, required=False)
    exploit_cve = forms.CharField(label='CVE', max_length=100, required=False)
    exploit_cvs = forms.CharField(label='CVSS', max_length=100, required=False)
    exploit_system = forms.ChoiceField(label='OS', choices=oses)
    exploit_language = forms.ChoiceField(label='Language', choices=languages)
    exploit_protocol = forms.ChoiceField(label='Protocol', choices=protocols)
