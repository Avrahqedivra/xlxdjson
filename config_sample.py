REPORT_NAME     = "XLXJSON Monitor for D-STAR"  # Name of the monitored WiresX system
#
CONFIG_INC      = True                          # Include HBlink stats
HOMEBREW_INC    = True                          # Display Homebrew Peers status
LASTHEARD_INC   = True                          # Display lastheard table on main page
BRIDGES_INC     = True                          # Display Bridge status and button
EMPTY_MASTERS   = False                         # Display (True) or not (False) empty master in status

FREQUENCY       = 5                             # Frequency to push updates to web clients
SOCKET_SERVER_PORT = 9004                       # Websocket server for realtime monitoring
JSON_SERVER_PORT = 7770                         # Has to be above 1024 if you're not running as root
DISPLAY_LINES =  15                             # number of lines displayed in index_template
CLIENT_TIMEOUT  = 0                             # Clients are timed out after this many seconds, 0 to disable

XLXD_IP         = 'xxx.xxx.xxx.xxx'             # your XLXD server IP address 
XLXD_PORTJSON   = 10001                         # XLXD JSON reporting socket (standard port, check if opened in firewall)

# ids of module to be excluded, for example "A,B,T"
MOD_FILTER = ""
# number of modules (A -> Z)
MOD_NUMBER = 26
# module names, from A to Z, missing will default to "Reserved"
MOD_NAMES = '{ "A":"YSF-France", "B": "YSF-Nantes", "C":"YSF-Idf", "D":"M17-FRA-D (Stop)", "Z":"Interco IMRS" }'
# ids of module order on html monitor page, for example "B,T,A,C"
MOD_ORDER = "A,B,T"
# all module not in this list will be excluded. if empty all will be allowed
MOD_ALLOWED = ""
# modules to hilite (will be displayed in another color)
MOD_HILITE = "T"
# modules colors is a json array string of tgid and hex rgb
MOD_COLORS = '{ "tx":"#fbd379", "ind":"#fefefe", "A":"#569cd6", "C":"#fca33c", "T":"#a3e978", "B":"#bc7ebb" }'
# dynamic modules, if not filtred by MOD_FILTER, module will be added dynamicaly to dashboard beside those in MOD_ORDER
DYNAMIC_MOD = True

# Authorization of access to dashboard as admin
ADMIN_USER = 'admin'
ADMIN_PASS = 'admin'

# Authorization of access to dashboard# as user
WEB_AUTH =  False
WEB_USER =  'admin'
WEB_PASS =  'admin'

# Files and stuff for loading alias files for mapping numbers to names
PATH            = './'                           # MUST END WITH '/'
FILE_RELOAD     = 1                              # Number of days before we reload DMR-MARC database files

# Settings for log files
LOG_PATH        = './log/'                       # MUST END WITH '/'
LOG_NAME        = 'xlxmon.log'

# Settings for xlxd log files
XLXDLOG_FILE      = '/var/log/xlxd.xml'

