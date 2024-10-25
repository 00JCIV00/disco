//! Basic Netlink 802.11 (nl80211) Functions

const std = @import("std");
const ascii = std.ascii;
const enums = std.enums;
const heap = std.heap;
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const os = std.os;
const posix = std.posix;
const time = std.time;

const nl = @import("../nl.zig");
const utils = @import("../utils.zig");
const c = utils.toStruct;

/// Control Info Map
var ctrl_info: ?nl.generic.CtrlInfo = null;


// Constants
/// Command
pub const CMD = enum(u8) {
    UNSPEC = 0,
    GET_WIPHY = 1,
    SET_WIPHY = 2,
    NEW_WIPHY = 3,
    DEL_WIPHY = 4,
    GET_INTERFACE = 5,
    SET_INTERFACE = 6,
    NEW_INTERFACE = 7,
    DEL_INTERFACE = 8,
    GET_KEY = 9,
    SET_KEY = 10,
    NEW_KEY = 11,
    DEL_KEY = 12,
    GET_BEACON = 13,
    SET_BEACON = 14,
    START_AP = 15,
    //NEW_BEACON = START_AP,
    STOP_AP = 16,
    //DEL_BEACON = STOP_AP,
    GET_STATION = 17,
    SET_STATION = 18,
    NEW_STATION = 19,
    DEL_STATION = 20,
    GET_MPATH = 21,
    SET_MPATH = 22,
    NEW_MPATH = 23,
    DEL_MPATH = 24,
    SET_BSS = 25,
    SET_REG = 26,
    REQ_SET_REG = 27,
    GET_MESH_CONFIG = 28,
    SET_MESH_CONFIG = 29,
    SET_MGMT_EXTRA_IE = 30,
    GET_REG = 31,
    GET_SCAN = 32,
    TRIGGER_SCAN = 33,
    NEW_SCAN_RESULTS = 34,
    SCAN_ABORTED = 35,
    REG_CHANGE = 36,
    AUTHENTICATE = 37,
    ASSOCIATE = 38,
    DEAUTHENTICATE = 39,
    DISASSOCIATE = 40,
    MICHAEL_MIC_FAILURE = 41,
    REG_BEACON_HINT = 42,
    JOIN_IBSS = 43,
    LEAVE_IBSS = 44,
    TESTMODE = 45,
    CONNECT = 46,
    ROAM = 47,
    DISCONNECT = 48,
    SET_WIPHY_NETNS = 49,
    GET_SURVEY = 50,
    NEW_SURVEY_RESULTS = 51,
    SET_PMKSA = 52,
    DEL_PMKSA = 53,
    FLUSH_PMKSA = 54,
    REMAIN_ON_CHANNEL = 55,
    CANCEL_REMAIN_ON_CHANNEL = 56,
    SET_TX_BITRATE_MASK = 57,
    REGISTER_FRAME = 58,
    //REGISTER_ACTION = REGISTER_FRAME,
    FRAME = 59,
    //ACTION = FRAME,
    FRAME_TX_STATUS = 60,
    //ACTION_TX_STATUS = FRAME_TX_STATUS,
    SET_POWER_SAVE = 61,
    GET_POWER_SAVE = 62,
    SET_CQM = 63,
    NOTIFY_CQM = 64,
    SET_CHANNEL = 65,
    SET_WDS_PEER = 66,
    FRAME_WAIT_CANCEL = 67,
    JOIN_MESH = 68,
    LEAVE_MESH = 69,
    UNPROT_DEAUTHENTICATE = 70,
    UNPROT_DISASSOCIATE = 71,
    NEW_PEER_CANDIDATE = 72,
    GET_WOWLAN = 73,
    SET_WOWLAN = 74,
    START_SCHED_SCAN = 75,
    STOP_SCHED_SCAN = 76,
    SCHED_SCAN_RESULTS = 77,
    SCHED_SCAN_STOPPED = 78,
    SET_REKEY_OFFLOAD = 79,
    PMKSA_CANDIDATE = 80,
    TDLS_OPER = 81,
    TDLS_MGMT = 82,
    UNEXPECTED_FRAME = 83,
    PROBE_CLIENT = 84,
    REGISTER_BEACONS = 85,
    UNEXPECTED_4ADDR_FRAME = 86,
    SET_NOACK_MAP = 87,
    CH_SWITCH_NOTIFY = 88,
    START_P2P_DEVICE = 89,
    STOP_P2P_DEVICE = 90,
    CONN_FAILED = 91,
    SET_MCAST_RATE = 92,
    SET_MAC_ACL = 93,
    RADAR_DETECT = 94,
    GET_PROTOCOL_FEATURES = 95,
    UPDATE_FT_IES = 96,
    FT_EVENT = 97,
    CRIT_PROTOCOL_START = 98,
    CRIT_PROTOCOL_STOP = 99,
    GET_COALESCE = 100,
    SET_COALESCE = 101,
    CHANNEL_SWITCH = 102,
    VENDOR = 103,
    SET_QOS_MAP = 104,
    ADD_TX_TS = 105,
    DEL_TX_TS = 106,
    GET_MPP = 107,
    JOIN_OCB = 108,
    LEAVE_OCB = 109,
    CH_SWITCH_STARTED_NOTIFY = 110,
    TDLS_CHANNEL_SWITCH = 111,
    TDLS_CANCEL_CHANNEL_SWITCH = 112,
    WIPHY_REG_CHANGE = 113,
    ABORT_SCAN = 114,
    START_NAN = 115,
    STOP_NAN = 116,
    ADD_NAN_FUNCTION = 117,
    DEL_NAN_FUNCTION = 118,
    CHANGE_NAN_CONFIG = 119,
    NAN_MATCH = 120,
    SET_MULTICAST_TO_UNICAST = 121,
    UPDATE_CONNECT_PARAMS = 122,
    SET_PMK = 123,
    DEL_PMK = 124,
    PORT_AUTHORIZED = 125,
    RELOAD_REGDB = 126,
    EXTERNAL_AUTH = 127,
    STA_OPMODE_CHANGED = 128,
    CONTROL_PORT_FRAME = 129,
    GET_FTM_RESPONDER_STATS = 130,
    PEER_MEASUREMENT_START = 131,
    PEER_MEASUREMENT_RESULT = 132,
    PEER_MEASUREMENT_COMPLETE = 133,
    NOTIFY_RADAR = 134,
    UPDATE_OWE_INFO = 135,
    PROBE_MESH_LINK = 136,
    SET_TID_CONFIG = 137,
    UNPROT_BEACON = 138,
    CONTROL_PORT_FRAME_TX_STATUS = 139,
    SET_SAR_SPECS = 140,
    OBSS_COLOR_COLLISION = 141,
    COLOR_CHANGE_REQUEST = 142,
    COLOR_CHANGE_STARTED = 143,
    COLOR_CHANGE_ABORTED = 144,
    COLOR_CHANGE_COMPLETED = 145,
    SET_FILS_AAD = 146,
    ASSOC_COMEBACK = 147,
    ADD_LINK = 148,
    REMOVE_LINK = 149,
    ADD_LINK_STA = 150,
    MODIFY_LINK_STA = 151,
    REMOVE_LINK_STA = 152,
    SET_HW_TIMESTAMP = 153,
    LINKS_REMOVED = 154,
    SET_TID_TO_LINK_MAPPING = 155,
};

/// Attributes
pub const ATTR = enum(u16) {
    UNSPEC = 0,
    WIPHY = 1,
    WIPHY_NAME = 2,
    IFINDEX = 3,
    IFNAME = 4,
    IFTYPE = 5,
    MAC = 6,
    KEY_DATA = 7,
    KEY_IDX = 8,
    KEY_CIPHER = 9,
    KEY_SEQ = 10,
    KEY_DEFAULT = 11,
    BEACON_INTERVAL = 12,
    DTIM_PERIOD = 13,
    BEACON_HEAD = 14,
    BEACON_TAIL = 15,
    STA_AID = 16,
    STA_FLAGS = 17,
    STA_LISTEN_INTERVAL = 18,
    STA_SUPPORTED_RATES = 19,
    STA_VLAN = 20,
    STA_INFO = 21,
    WIPHY_BANDS = 22,
    MNTR_FLAGS = 23,
    MESH_ID = 24,
    STA_PLINK_ACTION = 25,
    MPATH_NEXT_HOP = 26,
    MPATH_INFO = 27,
    BSS_CTS_PROT = 28,
    BSS_SHORT_PREAMBLE = 29,
    BSS_SHORT_SLOT_TIME = 30,
    HT_CAPABILITY = 31,
    SUPPORTED_IFTYPES = 32,
    REG_ALPHA2 = 33,
    REG_RULES = 34,
    MESH_CONFIG = 35,
    BSS_BASIC_RATES = 36,
    WIPHY_TXQ_PARAMS = 37,
    WIPHY_FREQ = 38,
    WIPHY_CHANNEL_TYPE = 39,
    KEY_DEFAULT_MGMT = 40,
    MGMT_SUBTYPE = 41,
    IE = 42,
    MAX_NUM_SCAN_SSIDS = 43,
    SCAN_FREQUENCIES = 44,
    SCAN_SSIDS = 45,
    GENERATION = 46,
    BSS = 47,
    REG_INITIATOR = 48,
    REG_TYPE = 49,
    SUPPORTED_COMMANDS = 50,
    FRAME = 51,
    SSID = 52,
    AUTH_TYPE = 53,
    REASON_CODE = 54,
    KEY_TYPE = 55,
    MAX_SCAN_IE_LEN = 56,
    CIPHER_SUITES = 57,
    FREQ_BEFORE = 58,
    FREQ_AFTER = 59,
    FREQ_FIXED = 60,
    WIPHY_RETRY_SHORT = 61,
    WIPHY_RETRY_LONG = 62,
    WIPHY_FRAG_THRESHOLD = 63,
    WIPHY_RTS_THRESHOLD = 64,
    TIMED_OUT = 65,
    USE_MFP = 66,
    STA_FLAGS2 = 67,
    CONTROL_PORT = 68,
    TESTDATA = 69,
    PRIVACY = 70,
    DISCONNECTED_BY_AP = 71,
    STATUS_CODE = 72,
    CIPHER_SUITES_PAIRWISE = 73,
    CIPHER_SUITE_GROUP = 74,
    WPA_VERSIONS = 75,
    AKM_SUITES = 76,
    REQ_IE = 77,
    RESP_IE = 78,
    PREV_BSSID = 79,
    KEY = 80,
    KEYS = 81,
    PID = 82,
    FOUR_ADDR = 83,
    SURVEY_INFO = 84,
    PMKID = 85,
    MAX_NUM_PMKIDS = 86,
    DURATION = 87,
    COOKIE = 88,
    WIPHY_COVERAGE_CLASS = 89,
    TX_RATES = 90,
    FRAME_MATCH = 91,
    ACK = 92,
    PS_STATE = 93,
    CQM = 94,
    LOCAL_STATE_CHANGE = 95,
    AP_ISOLATE = 96,
    WIPHY_TX_POWER_SETTING = 97,
    WIPHY_TX_POWER_LEVEL = 98,
    TX_FRAME_TYPES = 99,
    RX_FRAME_TYPES = 100,
    FRAME_TYPE = 101,
    CONTROL_PORT_ETHERTYPE = 102,
    CONTROL_PORT_NO_ENCRYPT = 103,
    SUPPORT_IBSS_RSN = 104,
    WIPHY_ANTENNA_TX = 105,
    WIPHY_ANTENNA_RX = 106,
    MCAST_RATE = 107,
    OFFCHANNEL_TX_OK = 108,
    BSS_HT_OPMODE = 109,
    KEY_DEFAULT_TYPES = 110,
    MAX_REMAIN_ON_CHANNEL_DURATION = 111,
    MESH_SETUP = 112,
    WIPHY_ANTENNA_AVAIL_TX = 113,
    WIPHY_ANTENNA_AVAIL_RX = 114,
    SUPPORT_MESH_AUTH = 115,
    STA_PLINK_STATE = 116,
    WOWLAN_TRIGGERS = 117,
    WOWLAN_TRIGGERS_SUPPORTED = 118,
    SCHED_SCAN_INTERVAL = 119,
    INTERFACE_COMBINATIONS = 120,
    SOFTWARE_IFTYPES = 121,
    REKEY_DATA = 122,
    MAX_NUM_SCHED_SCAN_SSIDS = 123,
    MAX_SCHED_SCAN_IE_LEN = 124,
    SCAN_SUPP_RATES = 125,
    HIDDEN_SSID = 126,
    IE_PROBE_RESP = 127,
    IE_ASSOC_RESP = 128,
    STA_WME = 129,
    SUPPORT_AP_UAPSD = 130,
    ROAM_SUPPORT = 131,
    SCHED_SCAN_MATCH = 132,
    MAX_MATCH_SETS = 133,
    PMKSA_CANDIDATE = 134,
    TX_NO_CCK_RATE = 135,
    TDLS_ACTION = 136,
    TDLS_DIALOG_TOKEN = 137,
    TDLS_OPERATION = 138,
    TDLS_SUPPORT = 139,
    TDLS_EXTERNAL_SETUP = 140,
    DEVICE_AP_SME = 141,
    DONT_WAIT_FOR_ACK = 142,
    FEATURE_FLAGS = 143,
    PROBE_RESP_OFFLOAD = 144,
    PROBE_RESP = 145,
    DFS_REGION = 146,
    DISABLE_HT = 147,
    HT_CAPABILITY_MASK = 148,
    NOACK_MAP = 149,
    INACTIVITY_TIMEOUT = 150,
    RX_SIGNAL_DBM = 151,
    BG_SCAN_PERIOD = 152,
    WDEV = 153,
    USER_REG_HINT_TYPE = 154,
    CONN_FAILED_REASON = 155,
    AUTH_DATA = 156,
    VHT_CAPABILITY = 157,
    SCAN_FLAGS = 158,
    CHANNEL_WIDTH = 159,
    CENTER_FREQ1 = 160,
    CENTER_FREQ2 = 161,
    P2P_CTWINDOW = 162,
    P2P_OPPPS = 163,
    LOCAL_MESH_POWER_MODE = 164,
    ACL_POLICY = 165,
    MAC_ADDRS = 166,
    MAC_ACL_MAX = 167,
    RADAR_EVENT = 168,
    EXT_CAPA = 169,
    EXT_CAPA_MASK = 170,
    STA_CAPABILITY = 171,
    STA_EXT_CAPABILITY = 172,
    PROTOCOL_FEATURES = 173,
    SPLIT_WIPHY_DUMP = 174,
    DISABLE_VHT = 175,
    VHT_CAPABILITY_MASK = 176,
    MDID = 177,
    IE_RIC = 178,
    CRIT_PROT_ID = 179,
    MAX_CRIT_PROT_DURATION = 180,
    PEER_AID = 181,
    COALESCE_RULE = 182,
    CH_SWITCH_COUNT = 183,
    CH_SWITCH_BLOCK_TX = 184,
    CSA_IES = 185,
    CNTDWN_OFFS_BEACON = 186,
    CNTDWN_OFFS_PRESP = 187,
    RXMGMT_FLAGS = 188,
    STA_SUPPORTED_CHANNELS = 189,
    STA_SUPPORTED_OPER_CLASSES = 190,
    HANDLE_DFS = 191,
    SUPPORT_5_MHZ = 192,
    SUPPORT_10_MHZ = 193,
    OPMODE_NOTIF = 194,
    VENDOR_ID = 195,
    VENDOR_SUBCMD = 196,
    VENDOR_DATA = 197,
    VENDOR_EVENTS = 198,
    QOS_MAP = 199,
    MAC_HINT = 200,
    WIPHY_FREQ_HINT = 201,
    MAX_AP_ASSOC_STA = 202,
    TDLS_PEER_CAPABILITY = 203,
    SOCKET_OWNER = 204,
    CSA_C_OFFSETS_TX = 205,
    MAX_CSA_COUNTERS = 206,
    TDLS_INITIATOR = 207,
    USE_RRM = 208,
    WIPHY_DYN_ACK = 209,
    TSID = 210,
    USER_PRIO = 211,
    ADMITTED_TIME = 212,
    SMPS_MODE = 213,
    OPER_CLASS = 214,
    MAC_MASK = 215,
    WIPHY_SELF_MANAGED_REG = 216,
    EXT_FEATURES = 217,
    SURVEY_RADIO_STATS = 218,
    NETNS_FD = 219,
    SCHED_SCAN_DELAY = 220,
    REG_INDOOR = 221,
    MAX_NUM_SCHED_SCAN_PLANS = 222,
    MAX_SCAN_PLAN_INTERVAL = 223,
    MAX_SCAN_PLAN_ITERATIONS = 224,
    SCHED_SCAN_PLANS = 225,
    PBSS = 226,
    BSS_SELECT = 227,
    STA_SUPPORT_P2P_PS = 228,
    PAD = 229,
    IFTYPE_EXT_CAPA = 230,
    MU_MIMO_GROUP_DATA = 231,
    MU_MIMO_FOLLOW_MAC_ADDR = 232,
    SCAN_START_TIME_TSF = 233,
    SCAN_START_TIME_TSF_BSSID = 234,
    MEASUREMENT_DURATION = 235,
    MEASUREMENT_DURATION_MANDATORY = 236,
    MESH_PEER_AID = 237,
    NAN_MASTER_PREF = 238,
    BANDS = 239,
    NAN_FUNC = 240,
    NAN_MATCH = 241,
    FILS_KEK = 242,
    FILS_NONCES = 243,
    MULTICAST_TO_UNICAST_ENABLED = 244,
    BSSID = 245,
    SCHED_SCAN_RELATIVE_RSSI = 246,
    SCHED_SCAN_RSSI_ADJUST = 247,
    TIMEOUT_REASON = 248,
    FILS_ERP_USERNAME = 249,
    FILS_ERP_REALM = 250,
    FILS_ERP_NEXT_SEQ_NUM = 251,
    FILS_ERP_RRK = 252,
    FILS_CACHE_ID = 253,
    PMK = 254,
    SCHED_SCAN_MULTI = 255,
    SCHED_SCAN_MAX_REQS = 256,
    WANT_1X_4WAY_HS = 257,
    PMKR0_NAME = 258,
    PORT_AUTHORIZED = 259,
    EXTERNAL_AUTH_ACTION = 260,
    EXTERNAL_AUTH_SUPPORT = 261,
    NSS = 262,
    ACK_SIGNAL = 263,
    CONTROL_PORT_OVER_NL80211 = 264,
    TXQ_STATS = 265,
    TXQ_LIMIT = 266,
    TXQ_MEMORY_LIMIT = 267,
    TXQ_QUANTUM = 268,
    HE_CAPABILITY = 269,
    FTM_RESPONDER = 270,
    FTM_RESPONDER_STATS = 271,
    TIMEOUT = 272,
    PEER_MEASUREMENTS = 273,
    AIRTIME_WEIGHT = 274,
    STA_TX_POWER_SETTING = 275,
    STA_TX_POWER = 276,
    SAE_PASSWORD = 277,
    TWT_RESPONDER = 278,
    HE_OBSS_PD = 279,
    WIPHY_EDMG_CHANNELS = 280,
    WIPHY_EDMG_BW_CONFIG = 281,
    VLAN_ID = 282,
    HE_BSS_COLOR = 283,
    IFTYPE_AKM_SUITES = 284,
    TID_CONFIG = 285,
    CONTROL_PORT_NO_PREAUTH = 286,
    PMK_LIFETIME = 287,
    PMK_REAUTH_THRESHOLD = 288,
    RECEIVE_MULTICAST = 289,
    WIPHY_FREQ_OFFSET = 290,
    CENTER_FREQ1_OFFSET = 291,
    SCAN_FREQ_KHZ = 292,
    HE_6GHZ_CAPABILITY = 293,
    FILS_DISCOVERY = 294,
    UNSOL_BCAST_PROBE_RESP = 295,
    S1G_CAPABILITY = 296,
    S1G_CAPABILITY_MASK = 297,
    SAE_PWE = 298,
    RECONNECT_REQUESTED = 299,
    SAR_SPEC = 300,
    DISABLE_HE = 301,
    OBSS_COLOR_BITMAP = 302,
    COLOR_CHANGE_COUNT = 303,
    COLOR_CHANGE_COLOR = 304,
    COLOR_CHANGE_ELEMS = 305,
    MBSSID_CONFIG = 306,
    MBSSID_ELEMS = 307,
    RADAR_BACKGROUND = 308,
    AP_SETTINGS_FLAGS = 309,
    EHT_CAPABILITY = 310,
    DISABLE_EHT = 311,
    MLO_LINKS = 312,
    MLO_LINK_ID = 313,
    MLD_ADDR = 314,
    MLO_SUPPORT = 315,
    MAX_NUM_AKM_SUITES = 316,
    EML_CAPABILITY = 317,
    MLD_CAPA_AND_OPS = 318,
    TX_HW_TIMESTAMP = 319,
    RX_HW_TIMESTAMP = 320,
    TD_BITMAP = 321,
    PUNCT_BITMAP = 322,
    MAX_HW_TIMESTAMP_PEERS = 323,
    HW_TIMESTAMP_ENABLED = 324,
    EMA_RNR_ELEMS = 325,
    MLO_LINK_DISABLED = 326,
    BSS_DUMP_INCLUDE_USE_DATA = 327,
    MLO_TTLM_DLINK = 328,
    MLO_TTLM_ULINK = 329,
    ASSOC_SPP_AMSDU = 330,
    WIPHY_RADIOS = 331,
    WIPHY_INTERFACE_COMBINATIONS = 332,
};
    
/// Authentication Types
pub const AUTHTYPE = enum(u16) {
    OPEN = 0,
    SHARED_KEY = 1,
    FT = 2,
    NETWORK_EAP = 3,
    SAE = 4,
};
/// WPA
pub const WPA = enum(u16) {
    VERSION_1 = 1,
    VERSION_2 = 2,
};
/// Interface Type
pub const IFTYPE = enum(u32) {
    UNSPECIFIED,
    ADHOC,
    STATION,
    AP,
    AP_VLAN,
    WDS,
    MONITOR,
    MESH_POINT,
    P2P_CLIENT,
    P2P_GO0,
    P2P_DEVICE1,
    OCB2,
    NAN3,
};
/// Scan Flags
pub const SCAN_FLAG = enum(u32) {
    /// Scan with low priority to minimize interference with other traffic
    LOW_PRIORITY = 1 << 0,
    /// Flush cached scan results before starting a new scan
    FLUSH = 1 << 1,
    /// Limit scan to access points only
    AP = 1 << 2,
    /// Use a random MAC address during the scan
    RANDOM_ADDR = 1 << 3,
    /// Use FILS and limit channel time for faster scanning
    FILS_MAX_CHANNEL_TIME = 1 << 4,
    /// Accept broadcast probe responses during the scan
    ACCEPT_BCAST_PROBE_RESP = 1 << 5,
    /// Use high transmission rate for OCE (Opportunistic Channel Encoding) probe requests
    OCE_PROBE_REQ_HIGH_TX_RATE = 1 << 6,
    /// Suppress deferrals of OCE probe requests to reduce scan delay
    OCE_PROBE_REQ_DEFERRAL_SUPPRESSION = 1 << 7,
    /// Low-span scanning to reduce the impact of the scan
    LOW_SPAN = 1 << 8,
    /// Low-power scanning to save energy during the scan
    LOW_POWER = 1 << 9,
    /// High-accuracy scanning, possibly trading off speed or power
    HIGH_ACCURACY = 1 << 10,
    /// Use a random sequence number in probe requests
    RANDOM_SN = 1 << 11,
    /// Send minimal probe request content
    MIN_PREQ_CONTENT = 1 << 12,
    /// Report frequency in kilohertz
    FREQ_KHZ = 1 << 13,
    /// Scan for colocated 6 GHz APs
    COLOCATED_6GHZ = 1 << 14,
};

/// Scan Results
pub const ScanResults = struct {
    pub const AttrE = ATTR;

    GENERATION: ?u32 = null,
    WIPHY: ?u32 = null,
    IFINDEX: u32,
    WDEV: u64,

    BSS: ?BasicServiceSet = null,
    SCAN_SSIDS: ?[]const u8 = null,
    SCAN_FREQUENCIES: ?[]const u8 = null,
    SCAN_FLAGS: ?[]const u8 = null,
};

/// Basic Service Set (BSS)
pub const BSS = enum(u32) {
    /// Invalid value for BSS attributes
    INVALID = 0,
    /// Basic Service Set Identifier (BSSID)
    BSSID = 1,
    /// Frequency (in MHz) on which the BSS is operating
    FREQUENCY = 2,
    /// Timestamp (in microseconds) when the beacon or probe response was received
    TSF = 3,
    /// Beacon interval (in time units)
    BEACON_INTERVAL = 4,
    /// Capabilities of the BSS
    CAPABILITY = 5,
    /// Information elements from the beacon or probe response
    INFORMATION_ELEMENTS = 6,
    /// Signal strength in milliBel milliwatts (mBm)
    SIGNAL_MBM = 7,
    /// Signal strength in unspecified units
    SIGNAL_UNSPEC = 8,
    /// Status of the BSS (associated, authenticated, etc.)
    STATUS = 9,
    /// Time in milliseconds since the BSS was last seen
    SEEN_MS_AGO = 10,
    /// Beacon Information Elements (IEs)
    BEACON_IES = 11,
    /// Channel width of the BSS
    CHAN_WIDTH = 12,
    /// Timestamp of the beacon TSF
    BEACON_TSF = 13,
    /// Probe response data
    PRESP_DATA = 14,
    /// Last seen boot time (in nanoseconds)
    LAST_SEEN_BOOTTIME = 15,
    /// Padding attribute
    PAD = 16,
    /// Parent TSF of the BSS
    PARENT_TSF = 17,
    /// Parent BSSID of the BSS
    PARENT_BSSID = 18,
    /// Signal strength of each chain
    CHAIN_SIGNAL = 19,
    /// Frequency offset of the BSS
    FREQUENCY_OFFSET = 20,
    /// MLO (Multi-Link Operation) Link ID of the BSS
    MLO_LINK_ID = 21,
    /// MLD (Multi-Link Device) address
    MLD_ADDR = 22,
    /// Reason the BSS should be used
    USE_FOR = 23,
    /// Reasons why the BSS cannot be used
    CANNOT_USE_REASONS = 24,
    /// Maximum value of BSS attributes
    MAX = 25,
};

/// Basic Service Set (BSS) Info
pub const BasicServiceSet = struct {
    pub const AttrE = BSS;

    /// Optional BSSID (MAC address)
    BSSID: ?[6]u8 = null,
    /// Optional frequency in MHz
    FREQUENCY: ?u32 = null,
    /// Optional TSF timestamp
    TSF: ?u64 = null,
    /// Optional beacon interval in time units
    BEACON_INTERVAL: ?u16 = null,
    /// Optional capability field from beacon
    CAPABILITY: ?u16 = null,
    /// Optional information elements (raw data)
    INFORMATION_ELEMENTS: ?InformationElements = null,
    /// Optional signal strength in milliBel milliwatts (mBm)
    SIGNAL_MBM: ?u32 = null,
    /// Optional signal strength in unspecified units
    SIGNAL_UNSPEC: ?u32 = null,
    /// Optional BSS status (e.g., associated, authenticated)
    STATUS: ?u32 = null,
    /// Optional time since BSS was last seen (in milliseconds)
    SEEN_MS_AGO: ?u32 = null,
    /// Optional beacon-specific Information Elements
    BEACON_IES: ?InformationElements = null,
    /// Optional channel width
    CHAN_WIDTH: ?u8 = null,
    /// Optional beacon TSF timestamp
    BEACON_TSF: ?u64 = null,
    /// Optional probe response data
    PRESP_DATA: ?[]const u8 = null,
    /// Optional boot time when BSS was last seen
    LAST_SEEN_BOOTTIME: ?u64 = null,
    /// Optional padding
    PAD: ?u8 = null,
    /// Optional parent TSF (for multi-link operations)
    PARENT_TSF: ?u64 = null,
    /// Optional parent BSSID (for multi-link operations)
    PARENT_BSSID: ?[6]u8 = null,
    /// Optional signal strength per chain
    CHAIN_SIGNAL: ?[]const u8 = null,
    /// Optional frequency offset in kHz
    FREQUENCY_OFFSET: ?u32 = null,
    /// Optional Multi-Link Operation (MLO) Link ID
    MLO_LINK_ID: ?u8 = null,
    /// Optional Multi-Link Device (MLD) address
    MLD_ADDR: ?[6]u8 = null,
    /// Optional use case for this BSS
    USE_FOR: ?u32 = null,
    /// Optional reasons this BSS cannot be used
    CANNOT_USE_REASONS: ?u32 = null,
};

/// Information Element Tag Header
pub const InformationElementHeader = extern struct {
    pub const nl_align = false;
    pub const full_len = false;

    type: u8,
    len: u8,
};

/// Information Element Tag
pub const InformationElement = struct {
    hdr: InformationElementHeader,
    data: []const u8,
};

/// Information Element Types
pub const IE = enum(u8) {
    /// Service Set Identifier (SSID)
    SSID = 0,
    /// Supported Rates
    SUPPORTED_RATES = 1,
    /// FH Parameter Set
    FH_PARAMETER_SET = 2,
    /// DS Parameter Set
    DS_PARAMETER_SET = 3,
    /// CF Parameter Set
    CF_PARAMETER_SET = 4,
    /// Traffic Indication Map (TIM)
    TIM = 5,
    /// IBSS Parameter Set
    IBSS_PARAMETER_SET = 6,
    /// Country
    COUNTRY = 7,
    /// Hopping Pattern Parameters
    HOPPING_PATTERN_PARAMS = 8,
    /// Hopping Pattern Table
    HOPPING_PATTERN_TABLE = 9,
    /// Request
    REQUEST = 10,
    /// BSS Load
    BSS_LOAD = 11,
    /// EDCA Parameter Set
    EDCA_PARAMETER_SET = 12,
    /// Traffic Specification (TSPEC)
    TSPEC = 13,
    /// Traffic Classification (TCLAS)
    TCLAS = 14,
    /// Schedule
    SCHEDULE = 15,
    /// Challenge Text (used in Shared Key authentication)
    CHALLENGE_TEXT = 16,
    /// Power Constraint
    POWER_CONSTRAINT = 32,
    /// Power Capability
    POWER_CAPABILITY = 33,
    /// Transmit Power Control (TPC) Request
    TPC_REQUEST = 34,
    /// Transmit Power Control (TPC) Report
    TPC_REPORT = 35,
    /// Supported Channels
    SUPPORTED_CHANNELS = 36,
    /// Channel Switch Announcement
    CHANNEL_SWITCH_ANNOUNCEMENT = 37,
    /// Measurement Request
    MEASUREMENT_REQUEST = 38,
    /// Measurement Report
    MEASUREMENT_REPORT = 39,
    /// Quiet
    QUIET = 40,
    /// IBSS DFS
    IBSS_DFS = 41,
    /// ERP Information
    ERP_INFORMATION = 42,
    /// HT Capabilities
    HT_CAPABILITIES = 44,
    /// HT Operation
    HT_OPERATION = 45,
    /// Secondary Channel Offset
    SECONDARY_CHANNEL_OFFSET = 46,
    /// Robust Security Network (RSN) Information
    RSN = 48,
    /// Extended Supported Rates
    EXTENDED_SUPPORTED_RATES = 50,
    /// Mesh Configuration
    MESH_CONFIGURATION = 60,
    /// Mesh ID
    MESH_ID = 61,
    /// Multi-band
    MULTI_BAND = 70,
    /// Extended Capabilities
    EXTENDED_CAPABILITIES = 127,
    /// VHT Capabilities
    VHT_CAPABILITIES = 191,
    /// VHT Operation
    VHT_OPERATION = 192,
    /// Vendor Specific
    VENDOR_SPECIFIC = 221,

    /// Unknown (Used by this library for unknown tags)
    __UNKNOWN__,
};


/// Information Element 
pub const InformationElements = struct {
    pub const AttrE = IE;
    pub const AttrHdrT = InformationElementHeader;

    /// Robust Security Network (RSN)
    const RobustSecurityNetwork = struct {
        pub fn fromBytes(alloc: mem.Allocator, bytes: []const u8) !@This() {
            var rsn: @This() = undefined;
            if (bytes.len < 8) {
                log.err("Incomplete Type Data for RSN. Only {d}B received.", .{ bytes.len });
                return error.IncompleteTypeData;
            }
            inline for (meta.fields(@This())) |field| {
                const field_info = @typeInfo(field.type);
                if (field_info == .Optional) @field(rsn, field.name) = null;
                if (field_info == .Pointer and field_info.Pointer.size == .Slice)
                    @field(rsn, field.name) = &.{};
            }
            rsn.VERSION = @bitCast(bytes[0..2].*);
            rsn.GROUP_CIPHER_SUITE = @bitCast(bytes[2..6].*);
            var start: usize = 6;
            var end: usize = 8;
            if (end < bytes.len) opts: {
                rsn.PAIRWISE_CIPHER_COUNT = @bitCast(bytes[6..8].*);
                if (rsn.PAIRWISE_CIPHER_COUNT.? > 0) {
                    const slice_end = end + (@sizeOf(Suite) * rsn.PAIRWISE_CIPHER_COUNT.?);
                    while (end < slice_end) {
                        start = end;
                        end += @sizeOf(Suite);
                        try nl.parse.setOptFromBytes(
                            alloc, 
                            ?[]const Suite, 
                            &rsn.PAIRWISE_CIPHER_SUITES, 
                            bytes[start..end],
                        );
                    }
                }
                start = end;
                end += 2;
                if (end > bytes.len) break :opts;

                rsn.AKM_SUITE_COUNT = @bitCast(bytes[start..end][0..2].*);
                if (rsn.AKM_SUITE_COUNT.? > 0) {
                    const slice_end = end + (@sizeOf(Suite) * rsn.AKM_SUITE_COUNT.?);
                    while (end < slice_end) {
                        start = end;
                        end += @sizeOf(Suite);
                        try nl.parse.setOptFromBytes(
                            alloc, 
                            ?[]const Suite, 
                            &rsn.AKM_SUITES, 
                            bytes[start..end],
                        );
                    }
                }
                start = end;
                end += 2;
                if (end > bytes.len) break :opts;

                rsn.CAPABILITIES = @bitCast(bytes[start..end][0..2].*);
                start = end;
                end += 2;
                if (end > bytes.len) break :opts;

                rsn.PMKID_COUNT = @bitCast(bytes[start..end][0..2].*);
                if (rsn.PMKID_COUNT.? > 0) {
                    const slice_end = end + (@sizeOf(Suite) * rsn.PMKID_COUNT.?);
                    while (end < slice_end) {
                        start = end;
                        end += @sizeOf(Suite);
                        try nl.parse.setOptFromBytes(
                            alloc, 
                            ?[]const [16]u8, 
                            &rsn.PMKID_LIST, 
                            bytes[start..end],
                        );
                    }
                }
                if (end > bytes.len) break :opts;

                start = end;
                end += @sizeOf(Suite);
                rsn.GROUP_MANAGEMENT_CIPHER_SUITE = @bitCast(bytes[start..end][0..4].*);
            }
            {
                const rsn_str = try json.stringifyAlloc(alloc, rsn, .{ .whitespace = .indent_4, .emit_null_optional_fields = false });
                defer alloc.free(rsn_str);
                log.debug("RSN:\n{s}", .{ rsn_str });
            }
            return rsn;
        }

        pub fn toBytes(self: @This(), alloc: mem.Allocator) ![]u8 {
            var buf = try std.ArrayListUnmanaged(u8).initCapacity(alloc, 0);
            inline for (meta.fields(@This())) |field| {
                const field_info = @typeInfo(field.type);
                const in_field = @field(self, field.name);
                switch (field_info) {
                    .Optional => |optl| optl: {
                        const _in_field = in_field orelse break :optl;
                        if (optl.child == u16 or optl.child == Suite) {
                            try buf.appendSlice(alloc, mem.toBytes(_in_field)[0..]);
                            break :optl;
                        }
                        for (_in_field[0..]) |item|
                            try buf.appendSlice(alloc, mem.toBytes(item)[0..]);
                    },
                    else => try buf.appendSlice(alloc, mem.toBytes(in_field)[0..]),
                }
            }
            return try buf.toOwnedSlice(alloc);
        }

        pub const Suite = extern struct {
            OUI: [3]u8,
            TYPE: u8,
        };

        /// Robust Security Network Types
        pub const RSN = struct {
            /// Cipher Suite Selectors
            pub const CipherSuiteSelector = enum(u8) {
                /// No encryption (useful for open networks)
                NONE = 0x00,
                /// WEP-40 encryption
                WEP40 = 0x01,
                /// TKIP (Temporal Key Integrity Protocol) encryption (used in WPA)
                TKIP = 0x02,
                /// AES-CCMP (Counter Mode Cipher Block Chaining Message Authentication Code Protocol)
                CCMP = 0x04,
                /// WEP-104 encryption
                WEP104 = 0x05,
                /// AES-GCMP (Galois/Counter Mode Protocol) encryption (used in WPA3)
                GCMP = 0x08,
                /// AES-GCMP-256 encryption (used in WPA3)
                GCMP_256 = 0x09,
            };
            /// Authentication Key Management (AKM) Suite Selectors
            pub const AKM = enum(u8) {
                /// WPA2 PSK (Pre-Shared Key)
                PSK = 0x02,
                /// 802.1X (Enterprise) authentication (used with EAP)
                EAP = 0x01,
                /// Simultaneous Authentication of Equals (SAE), used in WPA3-Personal
                SAE = 0x08,
                /// 802.11r Fast BSS Transition (FT) with PSK
                FT_PSK = 0x04,
                /// 802.11r Fast BSS Transition (FT) with EAP
                FT_EAP = 0x03,
                /// Suite B-192 authentication, used in WPA3-Enterprise
                SUITE_B_192 = 0x0C,
            };
            /// Group Cipher Suites
            pub const GroupCipherSuites = enum(u8) {
                /// Group Cipher Suite for WPA2 (AES-CCMP)
                GROUP_CCMP = 0x04,
                /// Group Cipher Suite for WPA (TKIP)
                GROUP_TKIP = 0x02,
            };
            // WPA3 Key Management
            pub const WPA3 = enum(u8) {
                /// WPA3-Personal using Simultaneous Authentication of Equals (SAE)
                WPA3_SAE = 0x08,
                /// WPA3-Enterprise using 802.1X authentication
                WPA3_EAP = 0x0D,
            };
        };

        /// Version of the RSN (typically 1 for WPA2)
        VERSION: u16,
        /// Group Cipher Suite
        GROUP_CIPHER_SUITE: Suite,
        /// Pairwise Cipher Suite Count
        PAIRWISE_CIPHER_COUNT: ?u16 = null,
        /// Pairwise Cipher Suite(s)
        PAIRWISE_CIPHER_SUITES: ?[]const Suite = null,
        /// AKM Suite Count
        AKM_SUITE_COUNT: ?u16 = null,
        /// AKM Suite(s)
        AKM_SUITES: ?[]const Suite = null,
        /// RSN Capabilities
        CAPABILITIES: ?u16 = null,
        /// Optional fields for WPA3 and beyond
        PMKID_COUNT: ?u16 = null,
        PMKID_LIST: ?[]const [16]u8 = null,
        GROUP_MANAGEMENT_CIPHER_SUITE: ?Suite = null,
    };

    /// SSID
    SSID: ?[]const u8 = null,
    /// Supported Rates
    SUPPORTED_RATES: ?[]const u8 = null,
    /// FH Parameter Set
    FH_PARAMETER_SET: ?[]const u8 = null,
    /// DS Parameter Set
    DS_PARAMETER_SET: ?[]const u8 = null,
    /// CF Parameter Set
    CF_PARAMETER_SET: ?[]const u8 = null,
    /// Traffic Indication Map (TIM)
    TIM: ?[]const u8 = null,
    /// IBSS Parameter Set
    IBSS_PARAMETER_SET: ?[]const u8 = null,
    /// Country
    COUNTRY: ?[]const u8 = null,
    /// Hopping Pattern Parameters
    HOPPING_PATTERN_PARAMS: ?[]const u8 = null,
    /// Hopping Pattern Table
    HOPPING_PATTERN_TABLE: ?[]const u8 = null,
    /// Request
    REQUEST: ?[]const u8 = null,
    /// BSS Load
    BSS_LOAD: ?[]const u8 = null,
    /// EDCA Parameter Set
    EDCA_PARAMETER_SET: ?[]const u8 = null,
    /// TSPEC
    TSPEC: ?[]const u8 = null,
    /// TCLAS
    TCLAS: ?[]const u8 = null,
    /// Schedule
    SCHEDULE: ?[]const u8 = null,
    /// Challenge Text
    CHALLENGE_TEXT: ?[]const u8 = null,
    /// Power Constraint
    POWER_CONSTRAINT: ?[]const u8 = null,
    /// Power Capability
    POWER_CAPABILITY: ?[]const u8 = null,
    /// TPC Request
    TPC_REQUEST: ?[]const u8 = null,
    /// TPC Report
    TPC_REPORT: ?[]const u8 = null,
    /// Supported Channels
    SUPPORTED_CHANNELS: ?[]const u8 = null,
    /// Channel Switch Announcement
    CHANNEL_SWITCH_ANNOUNCEMENT: ?[]const u8 = null,
    /// Measurement Request
    MEASUREMENT_REQUEST: ?[]const u8 = null,
    /// Measurement Report
    MEASUREMENT_REPORT: ?[]const u8 = null,
    /// Quiet
    QUIET: ?[]const u8 = null,
    /// IBSS DFS
    IBSS_DFS: ?[]const u8 = null,
    /// ERP Information
    ERP_INFORMATION: ?[]const u8 = null,
    /// HT Capabilities
    HT_CAPABILITIES: ?[]const u8 = null,
    /// HT Operation
    HT_OPERATION: ?[]const u8 = null,
    /// Secondary Channel Offset
    SECONDARY_CHANNEL_OFFSET: ?[]const u8 = null,
    /// RSN Information
    RSN: ?RobustSecurityNetwork = null,
    /// Extended Supported Rates
    EXTENDED_SUPPORTED_RATES: ?[]const u8 = null,
    /// Mesh Configuration
    MESH_CONFIGURATION: ?[]const u8 = null,
    /// Mesh ID
    MESH_ID: ?[]const u8 = null,
    /// Multi-band
    MULTI_BAND: ?[]const u8 = null,
    /// Extended Capabilities
    EXTENDED_CAPABILITIES: ?[]const u8 = null,
    /// VHT Capabilities
    VHT_CAPABILITIES: ?[]const u8 = null,
    /// VHT Operation
    VHT_OPERATION: ?[]const u8 = null,
    /// Vendor Specific
    VENDOR_SPECIFIC: ?[]const []const u8 = null,
};

pub const AKM_SUITES = enum(u32) {
    /// WPA2-PSK (Pre-Shared Key)
    PSK = 0x000FAC02,
    /// 802.1X (used in WPA2/WPA3 Enterprise)
    EAP = 0x000FAC01,
    /// Fast BSS Transition (802.11r) with PSK
    FT_PSK = 0x000FAC03,
    /// Fast BSS Transition (802.11r) with EAP
    FT_EAP = 0x000FAC04,
    /// Simultaneous Authentication of Equals (SAE), used in WPA3-Personal
    SAE = 0x000FAC08,
    /// Suite B-192, used in WPA3-Enterprise for high-security environments
    SUITE_B_192 = 0x000FAC0C,
    /// Opportunistic Wireless Encryption (OWE), used for open networks with encryption
    OWE = 0x000FAC12,
    /// DPP (Device Provisioning Protocol), used in WPA3 for easy device onboarding
    DPP = 0x000FAC14,
};

pub const CIPHER_SUITES = enum(u32) {
    /// No encryption (open network)
    NONE = 0x00000000,
    /// WEP-40 encryption (insecure, deprecated)
    WEP40 = 0x000FAC01,
    /// TKIP (Temporal Key Integrity Protocol), used in WPA (insecure)
    TKIP = 0x000FAC02,
    /// AES-CCMP (Counter Mode with Cipher Block Chaining Message Authentication Code Protocol), used in WPA2/WPA3
    CCMP = 0x000FAC04,
    /// WEP-104 encryption (insecure, deprecated)
    WEP104 = 0x000FAC05,
    /// AES-GCMP (Galois/Counter Mode Protocol) encryption, used in WPA3
    GCMP_128 = 0x000FAC08,
    /// AES-GCMP-256 encryption, used in WPA3 for enhanced security
    GCMP_256 = 0x000FAC09,
    ///// Group addressed traffic using AES-CCMP (Group Cipher Suite)
    //GROUP_CCMP = 0x000FAC04,
    ///// Group addressed traffic using TKIP (Group Cipher Suite)
    //GROUP_TKIP = 0x000FAC02,
    /// BIP-GMAC-128, used for Management Frame Protection (MFP) in WPA3
    BIP_GMAC_128 = 0x000FAC0B,
    /// BIP-GMAC-256, used for Management Frame Protection (MFP) in WPA3
    BIP_GMAC_256 = 0x000FAC0C,
    /// BIP-CMAC-256, another option for Management Frame Protection (MFP)
    BIP_CMAC_256 = 0x000FAC0D,
};


/// Get Netlink 80211 Control Info
/// This will be stored in a Global Variable that should be deinialized with `deinitCtrlInfo()`.
pub fn initCtrlInfo(alloc: mem.Allocator) !void {
    log.debug("Collecting NL80211 Control Info...", .{});
    defer log.debug("NL80211 Control Info Collected!", .{});

    ctrl_info = nl.generic.CtrlInfo.init(alloc, "nl80211") catch return error.NetlinkFamilyNotFound;
}
/// Deinitialize Control Info
pub fn deinitCtrlInfo(alloc: mem.Allocator) void {
    var info = ctrl_info orelse return;
    info.deinit(alloc);
}

/// Take Ownership of a Wireless Interface.
/// This ensures that only the current process can manipulate the give interface.
pub fn takeOwnership(if_index: i32) !void {
    const info = ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
    const fam_id = info.FAMILY_ID;
    const buf_len = comptime mem.alignForward(usize, (nl.generic.req_len + nl.attr_hdr_len + 8) * 4, 4);
    var req_buf: [buf_len]u8 = .{ 0 } ** buf_len;
    var fba = heap.FixedBufferAllocator.init(req_buf[0..]);
    const nl_sock = try nl.request(
        fba.allocator(),
        nl.NETLINK.GENERIC,
        nl.generic.Request,
        .{
            .nlh = .{
                .len = 0,
                .type = fam_id,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .pid = 0,
                .seq = 12321,
            },
            .genh = .{
                .cmd = c(CMD).SET_INTERFACE,
                .version = 1,
            },
        },
        &.{
            .{ .hdr = .{ .type = c(ATTR).IFINDEX }, .data = mem.toBytes(if_index)[0..] },
            .{ .hdr = .{ .type = c(ATTR).SOCKET_OWNER }, .data = &.{} },
        },
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);
}

/// Set the Mode for the Interface
pub fn setMode(if_index: i32, mode: u32) !void {
    const info = ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
    const fam_id = info.FAMILY_ID;
    const buf_len = comptime mem.alignForward(usize, (nl.generic.req_len + nl.attr_hdr_len + 8) * 4, 4);
    var req_buf: [buf_len]u8 = .{ 0 } ** buf_len;
    var fba = heap.FixedBufferAllocator.init(req_buf[0..]);
    const nl_sock = try nl.request(
        fba.allocator(),
        nl.NETLINK.GENERIC,
        nl.generic.Request,
        .{
            .nlh = .{
                .len = 0,
                .type = fam_id,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .pid = 0,
                .seq = 12321,
            },
            .genh = .{
                .cmd = c(CMD).SET_INTERFACE,
                .version = 1,
            },
        },
        &.{
            .{ .hdr = .{ .type = c(ATTR).IFINDEX }, .data = mem.toBytes(if_index)[0..] },
            .{ .hdr = .{ .type = c(ATTR).IFTYPE }, .data = mem.toBytes(mode)[0..] },
        },
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);
}

/// Scan for the Information Element of a specific SSID.
pub fn scanSSID(alloc: mem.Allocator, if_index: i32, ssid: []const u8) !ScanResults {
    const info = ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
    var ssid_data = try alloc.alloc(u8, switch (ssid.len) {
        0...8 => 8,
        9...16 => 16,
        17...32 => 32,
        else => return error.SSIDTooLong,
    });
    defer alloc.free(ssid_data);
    @memset(ssid_data[0..], 0);
    ssid_data[0] = @intCast(ssid.len + 4);
    ssid_data[2] = 1;
    @memcpy(ssid_data[(ssid_data.len - ssid.len)..], ssid);
    const nl_sock = try nl.request(
        alloc,
        nl.NETLINK.GENERIC,
        nl.generic.Request,
        .{
            .nlh = .{
                .len = 0,
                .type = info.FAMILY_ID,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .seq = 12321,
                .pid = 12321,
            },
            .genh = .{
                .cmd = c(CMD).TRIGGER_SCAN,
                .version = 0,
            },
        },
        &.{
            .{ .hdr = .{ .type = c(ATTR).IFINDEX }, .data = mem.toBytes(if_index)[0..] },
            .{ .hdr = .{ .type = c(ATTR).SCAN_SSIDS }, .data = ssid_data },
            .{ .hdr = .{ .type = c(ATTR).SCAN_FLAGS }, .data = mem.toBytes(c(SCAN_FLAG).COLOCATED_6GHZ)[0..] },
        },
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);

    const buf_size: u32 = 64_000;
    var timeout: usize = 3;
    var res_sock = try posix.socket(nl.AF.NETLINK, posix.SOCK.RAW, nl.NETLINK.GENERIC);
    defer posix.close(res_sock);
    const sa_nl = posix.sockaddr.nl{
        .pid = 0,
        .groups = c(nl.route.RTMGRP).LINK | c(nl.route.RTMGRP).IPV4_IFADDR,
    };
    try posix.bind(
        res_sock,
        @ptrCast(&sa_nl),
        16,
    );
    var timeout_opt = mem.toBytes(posix.timeval{ .tv_sec = @intCast(timeout), .tv_usec = 0 });
    try posix.setsockopt(res_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeout_opt[0..]);
    try posix.setsockopt(res_sock, posix.SOL.SOCKET, nl.NETLINK_OPT.RX_RING, mem.toBytes(buf_size)[0..]);
    try posix.setsockopt(
        res_sock,
        posix.SOL.NETLINK,
        nl.NETLINK_OPT.ADD_MEMBERSHIP,
        mem.toBytes(info.MCAST_GROUPS.get("scan").?)[0..],
    );
    var resp_timer = try time.Timer.start();
    var tried_get = false;
    var resp_count: usize = 1;
    var resp_multi = false;
    respLoop: while (resp_timer.read() / time.ns_per_s < timeout * 2 or resp_multi) : (resp_count += 1) {
        log.debug("Listening for response #{d}...", .{ resp_count });
        var resp_buf: [buf_size]u8 = .{ 0 } ** buf_size;
        const resp_len = posix.recv(
            res_sock,
            resp_buf[0..],
            0,
        ) catch |err| switch (err) {
            error.WouldBlock => {
                //return error.NoScanResults;
                if (tried_get) return error.NoScanResults;
                tried_get = true;
                log.debug("Attempting to Get Scan.", .{});
                posix.close(res_sock);
                res_sock = try nl.request(
                    alloc,
                    nl.NETLINK.GENERIC,
                    nl.generic.Request,
                    .{
                        .nlh = .{
                            .len = 0,
                            .type = info.FAMILY_ID,
                            .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK | c(nl.NLM_F).DUMP | c(nl.NLM_F).EXCL,
                            .seq = 12321,
                            .pid = 0,
                        },
                        .genh = .{
                            .cmd = c(CMD).GET_SCAN,
                            .version = 0,
                        },
                    },
                    &.{
                        .{ .hdr = .{ .type = c(ATTR).IFINDEX }, .data = mem.toBytes(if_index)[0..] },
                    },
                );
                timeout *= 3;
                timeout_opt = mem.toBytes(posix.timeval{ .tv_sec = @intCast(timeout), .tv_usec = 0 });
                try posix.setsockopt(res_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeout_opt[0..]);
                //try nl.handleAck(get_sock);
                resp_timer.reset();
                continue :respLoop;
            },
            else => return err,
        };
        log.debug("\n==================\nRESPONSE LEN: {d}B\n==================", .{ resp_len });
        var offset: usize = 0;
        var inner_count: usize = 1;
        while (offset < resp_len) : (inner_count += 1) {
            log.debug("\n------------------------------\nInner Message: {d} | Offest: {d}B", .{ inner_count, offset });
            // Netlink Header
            var start: usize = offset;
            var end: usize = offset + @sizeOf(nl.MessageHeader);
            const nl_resp_hdr: *const nl.MessageHeader = @alignCast(@ptrCast(resp_buf[start..end]));
            log.debug("- Message Len: {d}B", .{ nl_resp_hdr.len });
            if (nl_resp_hdr.len < @sizeOf(nl.MessageHeader))
                return error.InvalidMessage;
            if (nl_resp_hdr.type == c(nl.NLMSG).ERROR) {
                start = end;
                end += @sizeOf(nl.ErrorHeader);
                const nl_err: *const nl.ErrorHeader = @alignCast(@ptrCast(resp_buf[start..end]));
                switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                    .SUCCESS => {},
                    .BUSY => return error.BUSY,
                    else => |err| {
                        log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                        return error.OSError;
                    },
                }
            }
            resp_multi = nl_resp_hdr.flags & c(nl.NLM_F).MULTI == c(nl.NLM_F).MULTI;
            if (resp_multi) log.debug("Multi Part Message", .{});
            if (nl_resp_hdr.type == c(nl.NLMSG).DONE) {
                log.debug("Done w/ Multi Part Message.", .{});
                resp_multi = false;
            }
            // General Header
            start = end;
            end += @sizeOf(nl.generic.Header);
            const gen_hdr: *const nl.generic.Header = @alignCast(@ptrCast(resp_buf[start..end]));
            if (gen_hdr.cmd != c(CMD).NEW_SCAN_RESULTS and gen_hdr.cmd != c(CMD).SCAN_ABORTED) {
                log.debug("Not a Scan Result. Command: {s}", .{ @tagName(@as(CMD, @enumFromInt(gen_hdr.cmd))) });
                continue :respLoop;
            }
            log.debug("Received Scan Results. Command: {s}", .{ @tagName(@as(CMD, @enumFromInt(gen_hdr.cmd))) });

            start = end;
            end += nl_resp_hdr.len - @sizeOf(nl.MessageHeader);
            const results = try nl.parse.fromBytes(alloc, ScanResults, resp_buf[start..end]);
            errdefer nl.parse.freeBytes(alloc, ScanResults, results);
            if (results.BSS) |bss| {
                if (bss.INFORMATION_ELEMENTS) |ies| {
                    if (ies.SSID) |scan_ssid| {
                        log.debug("Scan Result SSID: {s}", .{ scan_ssid });
                        if (mem.eql(u8, scan_ssid, ssid)) return results;
                    }
                }
            }
            nl.parse.freeBytes(alloc, ScanResults, results);
            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
            //return error.Testing;
        }
    }
    return error.NoScanResults;
}

/// Determine Authentication Algorithm from the provided `scan_results`.
pub fn determineAuthAlg(scan_results: ScanResults) AUTHTYPE {
    const bss = scan_results.BSS orelse return .OPEN;
    const ies = bss.INFORMATION_ELEMENTS orelse return .OPEN;
    // TODO: Check for WEP (somehow) and WPA1 in VENDOR_SPECIFIC
    const rsn = ies.RSN orelse return .OPEN;
    const akms = rsn.AKM_SUITES orelse return .OPEN;
    return switch (@as(InformationElements.RobustSecurityNetwork.RSN.AKM, @enumFromInt(akms[0].TYPE))) {
        .PSK => .OPEN,
        .EAP, .SUITE_B_192 => .NETWORK_EAP,
        .SAE => .SAE,
        .FT_EAP, .FT_PSK => .FT,
    };
}

/// Authenticate to the provided WPA2 Network `ssid`.
pub fn authWPA2(
    alloc: mem.Allocator,
    if_index: i32,
    ssid: []const u8,
    scan_results: ScanResults,
) !void {
    const info = ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
    const auth_type = determineAuthAlg(scan_results);
    const bss = scan_results.BSS orelse return error.MissingBSS;
    const wiphy_freq = bss.FREQUENCY orelse return error.MissingFreq;
    const bssid = bss.BSSID orelse return error.MissingBSSID;

    const nl_sock = try nl.request(
        alloc, 
        nl.NETLINK.GENERIC,
        nl.generic.Request,
        .{
            .nlh = .{
                .len = 0,
                .type = info.FAMILY_ID,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .seq = 12321,
                .pid = 0,
            },
            .genh = .{
                .cmd = c(CMD).AUTHENTICATE,
                .version = 1,
            },
        },
        &.{
            .{ 
                .hdr = .{ .type = c(ATTR).IFINDEX },
                .data = mem.toBytes(if_index)[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).SSID },
                .data = ssid,
            },
            .{ 
                .hdr = .{ .type = c(ATTR).AUTH_TYPE },
                .data = mem.toBytes(@intFromEnum(auth_type))[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).WPA_VERSIONS },
                .data = mem.toBytes(WPA.VERSION_2)[0..],
            },
            .{
                .hdr = .{ .type = c(ATTR).AKM_SUITES, .len = 8 },
                .data = mem.toBytes(AKM_SUITES.PSK)[0..],
            },
            .{
                .hdr = .{ .type = c(ATTR).WIPHY_FREQ },
                .data = mem.toBytes(wiphy_freq)[0..],
            },
            .{
                .hdr = .{ .type = c(ATTR).MAC, .len = 10 },
                .data = bssid[0..],
            },
        },
    );
    try nl.handleAck(nl_sock);
}

/// Associate to the provided WPA2 Network `ssid`.
pub fn assocWPA2(
    alloc: mem.Allocator,
    if_index: i32,
    ssid: []const u8,
    scan_results: ScanResults,
) !void {
    const info = ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
    const auth_type = determineAuthAlg(scan_results);
    const bss = scan_results.BSS orelse return error.MissingBSS;
    const wiphy_freq = bss.FREQUENCY orelse return error.MissingFreq;
    const bssid = bss.BSSID orelse return error.MissingBSSID;
    const ies = bss.INFORMATION_ELEMENTS orelse return error.MissingIEs;
    const ie_bytes = try nl.parse.toBytes(alloc, InformationElements, ies);
    defer alloc.free(ie_bytes);

    const nl_sock = try nl.request(
        alloc, 
        nl.NETLINK.GENERIC,
        nl.generic.Request,
        .{
            .nlh = .{
                .len = 0,
                .type = info.FAMILY_ID,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .seq = 12321,
                .pid = 0,
            },
            .genh = .{
                .cmd = c(CMD).ASSOCIATE,
                .version = 1,
            },
        },
        &.{
            .{ 
                .hdr = .{ .type = c(ATTR).IFINDEX },
                .data = mem.toBytes(if_index)[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).SSID },
                .data = ssid,
            },
            .{ 
                .hdr = .{ .type = c(ATTR).AUTH_TYPE },
                .data = mem.toBytes(@intFromEnum(auth_type))[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).WPA_VERSIONS },
                .data = mem.toBytes(WPA.VERSION_2)[0..],
            },
            .{
                .hdr = .{ .type = c(ATTR).AKM_SUITES, .len = 8 },
                .data = mem.toBytes(AKM_SUITES.PSK)[0..],
            },
            .{
                .hdr = .{ .type = c(ATTR).WIPHY_FREQ },
                .data = mem.toBytes(wiphy_freq)[0..],
            },
            .{
                .hdr = .{ .type = c(ATTR).MAC, .len = 10 },
                .data = bssid[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).CIPHER_SUITE_GROUP },
                .data = mem.toBytes(CIPHER_SUITES.CCMP)[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).CIPHER_SUITES_PAIRWISE },
                .data = mem.toBytes(CIPHER_SUITES.CCMP)[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).IE, .len = @intCast(ie_bytes.len + nl.attr_hdr_len) },
                .data = ie_bytes,
            },
        },
    );
    try nl.handleAck(nl_sock);
}

/// Connect to a WPA2 Network
pub fn connectWPA2(
    alloc: mem.Allocator, 
    if_index: i32, 
    ssid: []const u8, 
    pmk: []const u8
) !void {
    const info = ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
    try takeOwnership(if_index);
    time.sleep(10 * time.ns_per_ms);
    try nl.route.setState(if_index, c(nl.route.IFF).DOWN);
    time.sleep(10 * time.ns_per_ms);
    try setMode(if_index, c(IFTYPE).STATION);
    time.sleep(10 * time.ns_per_ms);
    try nl.route.setState(if_index, c(nl.route.IFF).UP);
    time.sleep(10 * time.ns_per_ms);
    const scan_results = try scanSSID(alloc, if_index, ssid);
    defer nl.parse.freeBytes(alloc, ScanResults, scan_results);
    const ie_bytes = try nl.parse.toBytes(alloc, InformationElements, scan_results.BSS.?.INFORMATION_ELEMENTS.?);
    defer alloc.free(ie_bytes);
    const auth_type = determineAuthAlg(scan_results);
    try authWPA2(alloc, if_index, ssid, scan_results);
    time.sleep(100 * time.ns_per_ms);
    try assocWPA2(alloc, if_index, ssid, scan_results);
    log.debug("IE Bytes Len: {d}B", .{ ie_bytes.len });
    const nl_sock = try nl.request(
        alloc, 
        nl.NETLINK.GENERIC,
        nl.generic.Request,
        .{
            .nlh = .{
                .len = 0,
                .type = info.FAMILY_ID,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .seq = 12321,
                .pid = 0,
            },
            .genh = .{
                .cmd = c(CMD).CONNECT,
                .version = 1,
            },
        },
        &.{
            .{ 
                .hdr = .{ .type = c(ATTR).IFINDEX },
                .data = mem.toBytes(if_index)[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).WPA_VERSIONS },
                .data = mem.toBytes(@as(u32, 2))[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).AUTH_TYPE },
                .data = mem.toBytes(@intFromEnum(auth_type))[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).CIPHER_SUITE_GROUP },
                .data = mem.toBytes(@as(u32, 0x000fac04))[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).CIPHER_SUITES_PAIRWISE },
                .data = mem.toBytes(@as(u32, 0x000fac04))[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).AKM_SUITES },
                .data = mem.toBytes(@as(u32, 1027074))[0..],
            },
            .{ 
                .hdr = .{ .type = c(ATTR).SSID },
                .data = ssid,
            },
            .{ 
                .hdr = .{ .type = c(ATTR).PMK },
                .data = pmk,
            },
            .{ 
                .hdr = .{ .type = c(ATTR).IE, .len = @intCast(ie_bytes.len + nl.attr_hdr_len) },
                .data = ie_bytes,
            },
            .{
                .hdr = .{ .type = c(ATTR).WIPHY_FREQ },
                .data = mem.toBytes(scan_results.BSS.?.FREQUENCY.?)[0..],
            },
            .{
                .hdr = .{ .type = c(ATTR).MAC, .len = 10 },
                .data = scan_results.BSS.?.BSSID.?[0..],
            },
        },
    );
    defer posix.close(nl_sock);

    try nl.handleAck(nl_sock);
}
