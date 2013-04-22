#!/usr/bin/env python

# Written by tganzeboom 20-4-2013
# GPLv2

import getpass, os, platform, re, subprocess, sys, time
from datetime import timedelta

def simple():
    gathersimple = {}

    linux_dist = platform.linux_distribution()

    gathersimple['operatingsystem'] = linux_dist[0]
    gathersimple['operatingsystemrelease'] = linux_dist[1]
    gathersimple['lsbdistcodename'] = linux_dist[2]

    uname = platform.uname()

    gathersimple['kernel'] = uname[0]
    gathersimple['hostname'] = uname[1]
    gathersimple['kernelmajorversion'] = uname[2][:3]
    gathersimple['kernelrelease'] = uname[2]
    kv = re.compile(r'.*?-')
    reskv = kv.findall(uname[2])
    gathersimple['kernelversion'] = reskv[0].rstrip('-').strip()
    gathersimple['model'] = uname[4]
    gathersimple['isa'] = uname[5]

    gathersimple['currentuser'] = getpass.getuser()
    gathersimple['path'] = os.environ['PATH']
    gathersimple['pythonversion'] = platform.python_version()
    gathersimple['timezone'] = time.tzname[1]
    return gathersimple

# If you are the root user, give some more information.
def rootgather():
    gatherroot = {}

    d1 = subprocess.Popen(['dmidecode', '-t', '1'], stdout=subprocess.PIPE)
    d1out, d1err = d1.communicate()
    uuid = re.compile(r'UUID:.*')
    resuuid = uuid.findall(d1out)
    gatherroot['UUID'] = resuuid[0].lstrip('UUID:').strip()#dmidecode -t 2

    d2 = subprocess.Popen(['dmidecode', '-t', '2'], stdout=subprocess.PIPE)
    d2out, d2err = d2.communicate()
    bmanu = re.compile(r'Manufacturer:.*')
    bprod = re.compile(r'Product Name:.*')
    bserial = re.compile(r'Serial Number:.*')
    resbmanu = bmanu.findall(d2out)
    resbprod = bprod.findall(d2out)
    resbserial = bserial.findall(d2out)
#    print resmanu
    gatherroot['boardmanufacturer'] = resbmanu[0].lstrip('Manufacturer:').strip() #dmidecode -t 2
    gatherroot['boardproductname'] = resbprod[0].lstrip('Product Name:').strip()#dmidecode -t 2
    gatherroot['boardserialnumber'] = resbserial[0].lstrip('Serial Number').strip(':').strip()#dmidecode -t 2
    return gatherroot

def notsimple(gathersimple):
    gathernotsimple = {}

    i = subprocess.Popen(['/sbin/ip', 'addr', 'sh'], stdout=subprocess.PIPE)
    out, err = i.communicate()
# Still to do, aliases, bonding
    intfaces = re.compile(r'\d: \w+\d?:')
    resultintfs = intfaces.findall(out)
    interfaces = [x.lstrip('1234567890: ').strip(': ') for x in resultintfs]
    gathernotsimple['iface_number'] = len(interfaces)
    gathernotsimple['ifaces'] = ','.join(''.join(map(str, item)) for item in interfaces)
    for ggint in interfaces:
        ipaddrsh = subprocess.Popen(['/sbin/ip', 'addr', 'sh', ggint], stdout=subprocess.PIPE)
        ipaddrshout, ipaddrsherr = ipaddrsh.communicate()
# Still to do: ipv6
        inet4 = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}')
        resultinet4 = inet4.findall(ipaddrshout)
        inet6 = re.compile(r'\w{1,4}\:\w{1,4}\.\d{1,3}\.\d{1,3}\/\d{1,2}')
        resultinet6 = inet6.findall(ipaddrshout)
        mac = re.compile(r'[a-fA-F0-9]{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}\ brd')
        resultmac = mac.findall(ipaddrshout)

        if resultinet4:
            gathernotsimple['iface_ip_' + ggint] = resultinet4[0].rstrip('1234567890').strip('/').strip()
        else:
            gathernotsimple['iface_ip_' + ggint] = 'None'
        if resultmac:
            gathernotsimple['iface_mac_' + ggint] = resultmac[0].strip('brd').strip()
        else:
            gathernotsimple['iface_mac_' + ggint] = 'None'
        if resultinet4:
            gathernotsimple['iface_netmask_' + ggint] = resultinet4[0].lstrip('1234567890.').strip('/').strip()
        else:
            gathernotsimple['iface_netmask_' + ggint] = 'None'


# Check if lsb_release exists on the system, if not, complain
    if os.path.isfile('/usr/bin/lsb_release'):
# FNULL = Open for handling stderr from lsb_release -a, otherwise you'll get 'No LSB modules are available.' Doesn't look nice in the output.
        FNULL = open(os.devnull, 'w')
        lsb = subprocess.Popen(['/usr/bin/lsb_release', '-a'], stdout=subprocess.PIPE, stderr=FNULL, stdin=None)
        FNULL.close()
        lsbout, lsberr = lsb.communicate()
        lsbdistcode = re.compile(r'Codename:.*')
        lsbdistdesc = re.compile(r'Description:.*')
        lsbdistid = re.compile(r'Distributor ID:.*')
        lsbdistrel = re.compile(r'Release:.*')
        lsbmajdistrel = re.compile(r'Release:.*')
        reslsbdistcode = lsbdistcode.findall(lsbout)
        reslsbdistdesc = lsbdistdesc.findall(lsbout)
        reslsbdistid = lsbdistid.findall(lsbout)
        reslsbdistrel = lsbdistrel.findall(lsbout)
        reslsbmajdistrel = lsbmajdistrel.findall(lsbout)

        gathernotsimple['lsbdistcodename'] =  reslsbdistcode[0].strip('Codename:').strip()
        gathernotsimple['lsbdistdescription'] = reslsbdistdesc[0].strip('Description:').strip()
        gathernotsimple['lsbdistid'] = reslsbdistid[0].lstrip('Distributor ID:').strip()
        gathernotsimple['lsbdistrelease'] = reslsbdistrel[0].strip('Release:').strip()
        gathernotsimple['lsbmajdistrelease'] = reslsbmajdistrel[0].strip('Release:').rstrip('1234567890').strip('.').strip()
    else:
        gathernotsimple['lsbdistcodename'] =  'lsb_release not installed' #quantal
        gathernotsimple['lsbdistdescription'] = 'lsb_release not installed' #Ubuntu 12.10
        gathernotsimple['lsbdistid'] = 'lsb_release not installed' #Ubuntu
        gathernotsimple['lsbdistrelease'] = 'lsb_release not installed' #12.10
        gathernotsimple['lsbmajdistrelease'] = 'lsb_release not installed'

    iproute = subprocess.Popen(['/sbin/ip', 'route'], stdout=subprocess.PIPE)
    iprouteout, iprouteerr = iproute.communicate()
    r = 1
    for line in iprouteout.splitlines():
        gathernotsimple['route_' + str(r)] = line
        r = r + 1

    m = subprocess.Popen(['cat', '/proc/meminfo'], stdout=subprocess.PIPE)
    memout, memerr = m.communicate()
    memtotal = re.compile(r'MemTotal:.*')
    memfree = re.compile(r'MemFree:.*')
    swaptotal = re.compile(r'SwapTotal:.*')
    swapfree = re.compile(r'SwapFree:.*')
    resmemtotal = memtotal.findall(memout)
    resmemfree = memfree.findall(memout)
    resswaptotal = swaptotal.findall(memout)
    resswapfree = swapfree.findall(memout)
    gathernotsimple['memorytotal'] = resmemtotal[0].lstrip('MemTotal:').strip()
    gathernotsimple['memoryfree'] = resmemfree[0].lstrip('MemFree:').strip()
    gathernotsimple['swaptotal'] = resswaptotal[0].lstrip('SwapTotal:').strip()
    gathernotsimple['swapfree'] = resswapfree[0].lstrip('SwapFree:').strip()

## if statements for debian / redhat / suse / Ubuntu / Centos
    if gathersimple['operatingsystem'] == 'Ubuntu':
        gathernotsimple['osfamily'] = 'Debian'
    if gathersimple['operatingsystem'] == 'Debian':
        gathernotsimple['osfamily'] = 'Debian'
    elif gathersimple['operatingsystem'] == 'Red Hat Enterprise Linux Server':
        gathernotsimple['osfamily'] = 'RedHat'
    elif gathersimple['operatingsystem'] == 'CentOS':
        gathernotsimple['osfamily'] = 'RedHat'

    if gathernotsimple['osfamily'] == 'Debian':
        gathernotsimple['architecture'] = 'amd64'
    elif gathernotsimple['osfamily'] == 'RedHat':
        gathernotsimple['architecture'] = 'x86_64'

# Check if I am a virtual or something else.
# lspci is not in the /sbin directory on RedHat, but in /usr/bin/. This needs to be handled.
    if gathernotsimple['osfamily'] == 'Debian':
        lspci = '/usr/bin/lspci'
    elif gathernotsimple['osfamily'] == 'RedHat':
        lspci = '/sbin/lspci'
    v = subprocess.Popen(lspci, stdout=subprocess.PIPE)
    vout, verr = v.communicate()
# Needs some more TLC.
    if 'System peripheral:' in vout:
        gathernotsimple['iamavirtual'] = 'VMware'
    else:
        gathernotsimple['iamavirtual'] = 'Physical'

    cpuinfo = subprocess.Popen(['cat', '/proc/cpuinfo'], stdout=subprocess.PIPE)
    cpuinfoout, cpuinfoerr = cpuinfo.communicate()
    processor = re.compile(r'processor.*')
    modelname = re.compile(r'model name.*')
    resprocessor = processor.findall(cpuinfoout)
    resmodelname = modelname.findall(cpuinfoout)
#    numbproc = resprocessor[0].lstrip('processor\t:')
    numbproc = [x.lstrip('processor\t:').strip() for x in resprocessor]
    for ggproc in numbproc:
        gathernotsimple['processor' + ggproc] = ' '.join(''.join(map(str, item))for item in resmodelname[0].lstrip('model name').strip().lstrip(':').split())
# Loop through /sys/devices/system/cpu/cpu*
#    gathernotsimple['processorcount'] = #number of cores
# Check /proc/self/mountinfo
    selinuxmount = subprocess.Popen(['cat', '/proc/self/mountinfo'], stdout=subprocess.PIPE)
    selinuxmountout, selinuxmounterr = selinuxmount.communicate()
    selinuxfs = re.compile(r'selinuxfs')
    resselinux = selinuxfs.findall(selinuxmountout)
    if resselinux:
        sestatus = subprocess.Popen(['/usr/sbin/sestatus'], stdout=subprocess.PIPE)
        sestatusout, sestatuserr = sestatus.communicate()
        selinuxst = re.compile(r'SELinux status:.*')
        selinuxcm = re.compile(r'Current mode:.*')
        selinuxfm = re.compile(r'Mode from config file:.*')
        selinuxpv = re.compile(r'Policy version:.*')
        selinuxpf = re.compile(r'Policy from config file:.*')
        resselinuxst = selinuxst.findall(sestatusout)
        resselinuxcm = selinuxcm.findall(sestatusout)
        resselinuxfm = selinuxfm.findall(sestatusout)
        resselinuxpv = selinuxpv.findall(sestatusout)
        resselinuxpf = selinuxpf.findall(sestatusout)
        gathernotsimple['selinux_status'] = resselinuxst[0].lstrip('SELinux status:').strip()
        gathernotsimple['selinux_currentmode'] = resselinuxcm[0].lstrip('Current mode').strip(':').strip()
        gathernotsimple['selinux_filemode'] = resselinuxfm[0].lstrip('Mode from config file').strip(':').strip()
        gathernotsimple['selinux_policyversion'] = resselinuxpv[0].lstrip('Policy version:').strip()
        gathernotsimple['selinux_filepolicy'] = resselinuxpf[0].lstrip('Policy from config file:').strip()
    else:
        gathernotsimple['selinux'] = 'Disabled'
# Check /etc/ssh /usr/local/etc/ssh /etc/ /usr/local/etc *dsa*.pub and warn about dsa
#    gathernotsimple['sshdsakey'] =
# Check /etc/ssh /usr/local/etc/ssh /etc/ /usr/local/etc *rsa*.pub
#    gathernotsimple['sshrsakey'] =
# Check de time module
    checkuptime = subprocess.Popen(['cat', '/proc/uptime'], stdout=subprocess.PIPE)
    checkuptimeout, checkuptimeerr = checkuptime.communicate()
    uptime = str(timedelta(seconds = float(checkuptimeout.strip().split()[0])))
    gathernotsimple['uptime_seconds'] = checkuptimeout.split()[0].strip().rstrip('1234567890').strip('.')
    gathernotsimple['uptime'] = uptime.strip().rstrip('1234567890').strip('.')
    gathernotsimple['uptime_days'] = uptime.split()[0]
    gathernotsimple['uptime_hours'] = int(checkuptimeout.split()[0].strip().rstrip('1234567890').strip('.')) / 3600

    hi = subprocess.Popen(['hostid'], stdout=subprocess.PIPE)
    hiout, hierr = hi.communicate()
    gathernotsimple['hostid'] = hiout.split()[0]
    return gathernotsimple

if __name__ == "__main__":

    seperator = '=>'
    simpleinfo = simple()
    notsimpleinfo = notsimple(simpleinfo)
    simpleinfo.update(notsimpleinfo)
    if getpass.getuser() == 'root':
        rootgather()
        simpleinfo.update(rootgather())
    for key in sorted(simpleinfo.iterkeys()):
        print '%s %s %s' % (key, seperator, simpleinfo[key])
