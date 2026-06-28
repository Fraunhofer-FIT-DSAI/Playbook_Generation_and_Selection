#### helper functions for converting python code to Datalog




### Primitives

def inCompetent(principal):
    return "inCompetent(" + principal + ").\n"


def competent(principal):
    return "competent(" + principal + ").\n"


def clientProgram(host, program_name):
    return "clientProgram(" + host + ", " + program_name + ").\n"


def vulExists(host, vul_ID, mitre_id):
    return "vulExists(" + host + ", " + "'" + vul_ID + "'" + "," + '\'' + mitre_id + '\'' + ").\n"


def vulProperty(vul_ID, range, cons):
    return "vulProperty(" + "'" + vul_ID + "'" + ", " + range + "," + cons + ").\n"


def hacl(src, dst, protocol, port):
    return "hacl(" + src + ", " + dst + "," + protocol + "," + port + ").\n"
    
def progRunning(prog, host):
    return 'progRunning(' + "'" + prog + "'" + ', ' + host + ').\n'


def attackerLocated(host):
    return "attackerLocated(" + host + ").\n"


def hasAccount(principal, host, account):
    return 'hasAccount(' + principal + ', ' + host + ', ' + account + ').\n'


def networkServiceInfo(host, program, protocol, port, user):
    return 'networkServiceInfo(' + host + ', ' + '\'' + program + '\'' + ', ' + protocol + ', ' + port + ', ' + user + ').\n'


def setuidProgramInfo(host, program, owner):
    return 'setuidProgramInfo(' + host + ', ' + program + ', ' + owner + ').\n'


def localFileProtection(host, user, access, path):
    return 'localFileProtection(' + host + ', ' + user + ', ' + access + ',' + path + ').\n'

def dependsOn(host, program, library):
    return 'dependsOn(' + host + ', ' + program + ', ' + library + ').\n'


def installed(host, program):
    return 'installed(' + host + ', ' + program + ').\n'


def bugHyp(arg1, arg2, arg3):
    return 'bugHyp(' + arg1 + ', ' + arg2 + ', ', arg3 + ').\n'


def canAccessFile(host, user, access, path):
    return 'canAccessFile(' + host + ', ' + user + ', ', access + ', ' + path + ').\n'

def isWebServer(host):
    return 'isWebServer(' + host + ').\n'


def cvss(vul_ID, ac):
    return 'cvss(' + vul_ID + ', ' + ac + ').\n'





#### Derived

def execCode(host, user):
    return 'execCode(' + host + ', ' + user + ').\n'


def netAccess(machine, protocol, port):
    return 'netAccess(' + machine + ', ' + protocol + ', ' + port + ').\n'


def networkScan(host, user):
    return 'networkScan(' + host + ', ' + user + ').\n'


def gainVisibilityOfExistingAccessPoints(machine, protocol, port):
    return 'gainVisibilityOfExistingAccessPoints(' + machine + ', ' + protocol + ', ' + port + ').\n'


def canAccessHost(host):
    return 'canAccessHost(' + host + ').\n'


def accessFile(machine, access, path):
    return 'accessFile(' + machine + ', ' + access + ', ' + path + ').\n'


def accessMaliciousInput(host, principal, program):
    return 'accessMaliciousInput(' + host + ', ' + principal + ', ' + program + ').\n'



def principalCompromised(victim):
    return 'principalCompromised(' + victim + ').\n'



def dos(host):
    return 'dos(' + host + ').\n'


def logInService(host, protocol, port):
    return 'logInService(' + host + ', ' + protocol + ', ' + port + ').\n'


def manInTheMiddle(host1, host2, protocol, port):
    return 'manInTheMiddle(' + host1 + ', ' + host2 + ', ' + protocol + ', ' + port + ').\n'
    


def attackGoal(goal):
    return 'attackGoal(' + 'execCode(' + goal + ' ,_,_)).\n'


def advances(host1, host2):
    return 'advances(' + host1 + ', ' + host2 + ').\n'


def execGoalRule():
    return """
execCode(Attacker, Host, User) :-
    networkService(Host, Program, Protocol, Port, User),
    vulExists(Host, VulID, Program),
    netAccess(Attacker, Host, Protocol, Port).
"""


def get_target(facts):
    primtive = fact.split('(')[0]
    rest = fact.split('(')[1]
    rest = rest.split(')')[0]
    rest = rest.split(',')

    host = ''
    adjHost = ''
    program = ''
    vulID = ''
    protocol = ''
    port = ''
    for fact in facts:
        if primtive == 'netAccess':
            if rest[0] != '_':
                host = rest[0]
            if rest[1] != '_':
                protocol = rest[1]
            if rest[2] != '_':
                port = rest[2]
        elif primtive == 'progRunning':
            if rest[0] != '_':
                host = rest[0]
            if rest[1] != '_':
                program = rest[1]
        elif primtive == 'hacl':
            if rest[0] != '_':
                adjHost = rest[0]
            if rest[1] != '_':
                host = rest[1]
            if rest[2] != '_':
                protocol = rest[0]
            if rest[3] != '_':
                port = rest[1]
        elif primtive == 'vulExists':
            if rest[0] != '_':
                host = rest[0]
            if rest[1] != '_':
                vulID = rest[1]
            if rest[2] != '_':
                program = rest[0]
    
    return host, adjHost, protocol, program, port, vulID
    
