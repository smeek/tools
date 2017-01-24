#!/usr/bin/python

# Imports
import os, sys, getopt, struct

# Useful Defines
OTA_UPG_FILE_ID = 0x0beef11e
OTA_UPG_HDR_VER = 0x0100
OTA_UPG_HDR_MIN_HDR_LEN = 0x0038
OTA_UPG_HDR_FIELD_CTRL_SECURITY_CREDENTIAL_VER = 0x0001
OTA_UPG_HDR_FIELD_CTRL_DEVICE_SPECIFIC = 0x0002
OTA_UPG_HDR_FIELD_CTRL_HARDWARE_VER = 0x0004
OTA_UPG_HDR_FIELD_CTRL_MASK = (OTA_UPG_HDR_FIELD_CTRL_SECURITY_CREDENTIAL_VER | OTA_UPG_HDR_FIELD_CTRL_DEVICE_SPECIFIC | OTA_UPG_HDR_FIELD_CTRL_HARDWARE_VER)
OTA_UPG_HDR_ZIGBEE_STACK_2006 = 0x0000
OTA_UPG_HDR_ZIGBEE_STACK_2007 = 0x0001
OTA_UPG_HDR_ZIGBEE_STACK_PRO = 0x0002
OTA_UPG_HDR_ZIGBEE_STACK_IP = 0x0003
OTA_UPG_HDR_SEC_CRED_VER_SE_1_0 = 0x00
OTA_UPG_HDR_SEC_CRED_VER_SE_1_1 = 0x01
OTA_UPG_HDR_SEC_CRED_VER_SE_2_0 = 0x02
OTA_UPG_TAG_ID_UPG_IMG = 0x0000
OTA_UPG_TAG_ID_ECDSA_SIG = 0x0001
OTA_UPG_TAG_ID_ECDSA_SIGN_CERT = 0x0002

# ZigBee Manufacturer Codes
# "Borrowed" from the nice list in Wireshark (epan/dissectors/packet-zbee.h)
# Codes less than 0x1000 were issued for RF4CE
ZBEE_MFG_CODE_PANASONIC_RF4CE     = 0x0001
ZBEE_MFG_CODE_SONY_RF4CE          = 0x0002
ZBEE_MFG_CODE_SAMSUNG_RF4CE       = 0x0003
ZBEE_MFG_CODE_PHILIPS_RF4CE       = 0x0004
ZBEE_MFG_CODE_FREESCALE_RF4CE     = 0x0005
ZBEE_MFG_CODE_OKI_SEMI_RF4CE      = 0x0006
ZBEE_MFG_CODE_TI_RF4CE            = 0x0007

# Manufacturer Codes for non RF4CE devices
ZBEE_MFG_CODE_CIRRONET            = 0x1000
ZBEE_MFG_CODE_CHIPCON             = 0x1001
ZBEE_MFG_CODE_EMBER               = 0x1002
ZBEE_MFG_CODE_NTS                 = 0x1003
ZBEE_MFG_CODE_FREESCALE           = 0x1004
ZBEE_MFG_CODE_IPCOM               = 0x1005
ZBEE_MFG_CODE_SAN_JUAN            = 0x1006
ZBEE_MFG_CODE_TUV                 = 0x1007
ZBEE_MFG_CODE_COMPXS              = 0x1008
ZBEE_MFG_CODE_BM                  = 0x1009
ZBEE_MFG_CODE_AWAREPOINT          = 0x100a
ZBEE_MFG_CODE_PHILIPS             = 0x100b
ZBEE_MFG_CODE_LUXOFT              = 0x100c
ZBEE_MFG_CODE_KORWIN              = 0x100d
ZBEE_MFG_CODE_1_RF                = 0x100e
ZBEE_MFG_CODE_STG                 = 0x100f
ZBEE_MFG_CODE_TELEGESIS           = 0x1010
ZBEE_MFG_CODE_VISIONIC            = 0x1011
ZBEE_MFG_CODE_INSTA               = 0x1012
ZBEE_MFG_CODE_ATALUM              = 0x1013
ZBEE_MFG_CODE_ATMEL               = 0x1014
ZBEE_MFG_CODE_DEVELCO             = 0x1015
ZBEE_MFG_CODE_HONEYWELL1          = 0x1016
ZBEE_MFG_CODE_RADIO_PULSE         = 0x1017
ZBEE_MFG_CODE_RENESAS             = 0x1018
ZBEE_MFG_CODE_XANADU              = 0x1019
ZBEE_MFG_CODE_NEC                 = 0x101a
ZBEE_MFG_CODE_YAMATAKE            = 0x101b
ZBEE_MFG_CODE_TENDRIL             = 0x101c
ZBEE_MFG_CODE_ASSA                = 0x101d
ZBEE_MFG_CODE_MAXSTREAM           = 0x101e
ZBEE_MFG_CODE_NEUROCOM            = 0x101f
ZBEE_MFG_CODE_III                 = 0x1020
ZBEE_MFG_CODE_VANTAGE             = 0x1021
ZBEE_MFG_CODE_ICONTROL            = 0x1022
ZBEE_MFG_CODE_RAYMARINE           = 0x1023
ZBEE_MFG_CODE_LSR                 = 0x1024
ZBEE_MFG_CODE_ONITY               = 0x1025
ZBEE_MFG_CODE_MONO                = 0x1026
ZBEE_MFG_CODE_RFT                 = 0x1027
ZBEE_MFG_CODE_ITRON               = 0x1028
ZBEE_MFG_CODE_TRITECH             = 0x1029
ZBEE_MFG_CODE_EMBEDIT             = 0x102a
ZBEE_MFG_CODE_S3C                 = 0x102b
ZBEE_MFG_CODE_SIEMENS             = 0x102c
ZBEE_MFG_CODE_MINDTECH            = 0x102d
ZBEE_MFG_CODE_LGE                 = 0x102e
ZBEE_MFG_CODE_MITSUBISHI          = 0x102f
ZBEE_MFG_CODE_JOHNSON             = 0x1030
ZBEE_MFG_CODE_PRI                 = 0x1031
ZBEE_MFG_CODE_KNICK               = 0x1032
ZBEE_MFG_CODE_VICONICS            = 0x1033
ZBEE_MFG_CODE_FLEXIPANEL          = 0x1034
ZBEE_MFG_CODE_PIASIM              = 0x1035
ZBEE_MFG_CODE_TRANE               = 0x1036
ZBEE_MFG_CODE_JENNIC              = 0x1037
ZBEE_MFG_CODE_LIG                 = 0x1038
ZBEE_MFG_CODE_ALERTME             = 0x1039
ZBEE_MFG_CODE_DAINTREE            = 0x103a
ZBEE_MFG_CODE_AIJI                = 0x103b
ZBEE_MFG_CODE_TEL_ITALIA          = 0x103c
ZBEE_MFG_CODE_MIKROKRETS          = 0x103d
ZBEE_MFG_CODE_OKI_SEMI            = 0x103e
ZBEE_MFG_CODE_NEWPORT             = 0x103f
ZBEE_MFG_CODE_C4                  = 0x1040
ZBEE_MFG_CODE_STM                 = 0x1041
ZBEE_MFG_CODE_ASN                 = 0x1042
ZBEE_MFG_CODE_DCSI                = 0x1043
ZBEE_MFG_CODE_FRANCE_TEL          = 0x1044
ZBEE_MFG_CODE_MUNET               = 0x1045
ZBEE_MFG_CODE_AUTANI              = 0x1046
ZBEE_MFG_CODE_COL_VNET            = 0x1047
ZBEE_MFG_CODE_AEROCOMM            = 0x1048
ZBEE_MFG_CODE_SI_LABS             = 0x1049
ZBEE_MFG_CODE_INNCOM              = 0x104a
ZBEE_MFG_CODE_CANNON              = 0x104b
ZBEE_MFG_CODE_SYNAPSE             = 0x104c
ZBEE_MFG_CODE_FPS                 = 0x104d
ZBEE_MFG_CODE_CLS                 = 0x104e
ZBEE_MFG_CODE_CRANE               = 0x104F
ZBEE_MFG_CODE_MOBILARM            = 0x1050
ZBEE_MFG_CODE_IMONITOR            = 0x1051
ZBEE_MFG_CODE_BARTECH             = 0x1052
ZBEE_MFG_CODE_MESHNETICS          = 0x1053
ZBEE_MFG_CODE_LS_IND              = 0x1054
ZBEE_MFG_CODE_CASON               = 0x1055
ZBEE_MFG_CODE_WLESS_GLUE          = 0x1056
ZBEE_MFG_CODE_ELSTER              = 0x1057
ZBEE_MFG_CODE_SMS_TEC             = 0x1058
ZBEE_MFG_CODE_ONSET               = 0x1059
ZBEE_MFG_CODE_RIGA                = 0x105a
ZBEE_MFG_CODE_ENERGATE            = 0x105b
ZBEE_MFG_CODE_CONMED              = 0x105c
ZBEE_MFG_CODE_POWERMAND           = 0x105d
ZBEE_MFG_CODE_SCHNEIDER           = 0x105e
ZBEE_MFG_CODE_EATON               = 0x105f
ZBEE_MFG_CODE_TELULAR             = 0x1060
ZBEE_MFG_CODE_DELPHI              = 0x1061
ZBEE_MFG_CODE_EPISENSOR           = 0x1062
ZBEE_MFG_CODE_LANDIS_GYR          = 0x1063
ZBEE_MFG_CODE_KABA                = 0x1064
ZBEE_MFG_CODE_SHURE               = 0x1065
ZBEE_MFG_CODE_COMVERGE            = 0x1066
ZBEE_MFG_CODE_DBS_LODGING         = 0x1067
ZBEE_MFG_CODE_ENERGY_AWARE        = 0x1068
ZBEE_MFG_CODE_HIDALGO             = 0x1069
ZBEE_MFG_CODE_AIR2APP             = 0x106a
ZBEE_MFG_CODE_AMX                 = 0x106b
ZBEE_MFG_CODE_EDMI                = 0x106c
ZBEE_MFG_CODE_CYAN                = 0x106d
ZBEE_MFG_CODE_SYS_SPA             = 0x106e
ZBEE_MFG_CODE_TELIT               = 0x106f
ZBEE_MFG_CODE_KAGA                = 0x1070
ZBEE_MFG_CODE_4_NOKS              = 0x1071
ZBEE_MFG_CODE_CERTICOM            = 0x1072
ZBEE_MFG_CODE_GRIDPOINT           = 0x1073
ZBEE_MFG_CODE_PROFILE_SYS         = 0x1074
ZBEE_MFG_CODE_COMPACTA            = 0x1075
ZBEE_MFG_CODE_FREESTYLE           = 0x1076
ZBEE_MFG_CODE_ALEKTRONA           = 0x1077
ZBEE_MFG_CODE_COMPUTIME           = 0x1078
ZBEE_MFG_CODE_REMOTE_TECH         = 0x1079
ZBEE_MFG_CODE_WAVECOM             = 0x107a
ZBEE_MFG_CODE_ENERGY              = 0x107b
ZBEE_MFG_CODE_GE                  = 0x107c
ZBEE_MFG_CODE_JETLUN              = 0x107d
ZBEE_MFG_CODE_CIPHER              = 0x107e
ZBEE_MFG_CODE_CORPORATE           = 0x107f
ZBEE_MFG_CODE_ECOBEE              = 0x1080
ZBEE_MFG_CODE_SMK                 = 0x1081
ZBEE_MFG_CODE_MESHWORKS           = 0x1082
ZBEE_MFG_CODE_ELLIPS              = 0x1083
ZBEE_MFG_CODE_SECURE              = 0x1084
ZBEE_MFG_CODE_CEDO                = 0x1085
ZBEE_MFG_CODE_TOSHIBA             = 0x1086
ZBEE_MFG_CODE_DIGI                = 0x1087
ZBEE_MFG_CODE_UBILOGIX            = 0x1088
ZBEE_MFG_CODE_ECHELON             = 0x1089
#
ZBEE_MFG_CODE_GREEN_ENERGY        = 0x1090
ZBEE_MFG_CODE_SILVER_SPRING       = 0x1091
ZBEE_MFG_CODE_BLACK               = 0x1092
ZBEE_MFG_CODE_AZTECH_ASSOC        = 0x1093
ZBEE_MFG_CODE_A_AND_D             = 0x1094
ZBEE_MFG_CODE_RAINFOREST          = 0x1095
ZBEE_MFG_CODE_CARRIER             = 0x1096
ZBEE_MFG_CODE_SYCHIP              = 0x1097
ZBEE_MFG_CODE_OPEN_PEAK           = 0x1098
ZBEE_MFG_CODE_PASSIVE             = 0x1099
ZBEE_MFG_CODE_MMB                 = 0x109a
ZBEE_MFG_CODE_LEVITON             = 0x109b
ZBEE_MFG_CODE_KOREA_ELEC          = 0x109c
ZBEE_MFG_CODE_COMCAST1            = 0x109d
ZBEE_MFG_CODE_NEC_ELEC            = 0x109e
ZBEE_MFG_CODE_NETVOX              = 0x109f
ZBEE_MFG_CODE_UCONTROL            = 0x10a0
ZBEE_MFG_CODE_EMBEDIA             = 0x10a1
ZBEE_MFG_CODE_SENSUS              = 0x10a2
ZBEE_MFG_CODE_SUNRISE             = 0x10a3
ZBEE_MFG_CODE_MEMTECH             = 0x10a4
ZBEE_MFG_CODE_FREEBOX             = 0x10a5
ZBEE_MFG_CODE_M2_LABS             = 0x10a6
ZBEE_MFG_CODE_BRITISH_GAS         = 0x10a7
ZBEE_MFG_CODE_SENTEC              = 0x10a8
ZBEE_MFG_CODE_NAVETAS             = 0x10a9
ZBEE_MFG_CODE_LIGHTSPEED          = 0x10aa
ZBEE_MFG_CODE_OKI                 = 0x10ab
ZBEE_MFG_CODE_SISTEMAS            = 0x10ac
ZBEE_MFG_CODE_DOMETIC             = 0x10ad
ZBEE_MFG_CODE_APLS                = 0x10ae
ZBEE_MFG_CODE_ENERGY_HUB          = 0x10af
ZBEE_MFG_CODE_KAMSTRUP            = 0x10b0
ZBEE_MFG_CODE_ECHOSTAR            = 0x10b1
ZBEE_MFG_CODE_ENERNOC             = 0x10b2
ZBEE_MFG_CODE_ELTAV               = 0x10b3
ZBEE_MFG_CODE_BELKIN              = 0x10b4
ZBEE_MFG_CODE_XSTREAMHD           = 0x10b5
ZBEE_MFG_CODE_SATURN_SOUTH        = 0x10b6
ZBEE_MFG_CODE_GREENTRAP           = 0x10b7
ZBEE_MFG_CODE_SMARTSYNCH          = 0x10b8
ZBEE_MFG_CODE_NYCE                = 0x10b9
ZBEE_MFG_CODE_ICM_CONTROLS        = 0x10ba
ZBEE_MFG_CODE_MILLENNIUM          = 0x10bb
ZBEE_MFG_CODE_MOTOROLA            = 0x10bc
ZBEE_MFG_CODE_EMERSON             = 0x10bd
ZBEE_MFG_CODE_RADIO_THERMOSTAT    = 0x10be
ZBEE_MFG_CODE_OMRON               = 0x10bf
ZBEE_MFG_CODE_GIINII              = 0x10c0
ZBEE_MFG_CODE_FUJITSU             = 0x10c1
ZBEE_MFG_CODE_PEEL                = 0x10c2
ZBEE_MFG_CODE_ACCENT              = 0x10c3
ZBEE_MFG_CODE_BYTESNAP            = 0x10c4
ZBEE_MFG_CODE_NEC_TOKIN           = 0x10c5
ZBEE_MFG_CODE_G4S_JUSTICE         = 0x10c6
ZBEE_MFG_CODE_TRILLIANT           = 0x10c7
ZBEE_MFG_CODE_ELECTROLUX          = 0x10c8
ZBEE_MFG_CODE_ONZO                = 0x10c9
ZBEE_MFG_CODE_ENTEK               = 0x10ca
ZBEE_MFG_CODE_PHILIPS2            = 0x10cb
ZBEE_MFG_CODE_MAINSTREAM          = 0x10cc
ZBEE_MFG_CODE_INDESIT             = 0x10cd
ZBEE_MFG_CODE_THINKECO            = 0x10ce
ZBEE_MFG_CODE_2D2C                = 0x10cf
ZBEE_MFG_CODE_GREENPEAK           = 0x10d0
ZBEE_MFG_CODE_INTERCEL            = 0x10d1
ZBEE_MFG_CODE_LG                  = 0x10d2
ZBEE_MFG_CODE_MITSUMI1            = 0x10d3
ZBEE_MFG_CODE_MITSUMI2            = 0x10d4
ZBEE_MFG_CODE_ZENTRUM             = 0x10d5
ZBEE_MFG_CODE_NEST                = 0x10d6
ZBEE_MFG_CODE_EXEGIN              = 0x10d7
ZBEE_MFG_CODE_HONEYWELL2          = 0x10d8
ZBEE_MFG_CODE_TAKAHATA            = 0x10d9
ZBEE_MFG_CODE_SUMITOMO            = 0x10da
ZBEE_MFG_CODE_GE_ENERGY           = 0x10db
ZBEE_MFG_CODE_GE_APPLIANCES       = 0x10dc
ZBEE_MFG_CODE_RADIOCRAFTS         = 0x10dd
ZBEE_MFG_CODE_CEIVA               = 0x10de
ZBEE_MFG_CODE_TEC_CO              = 0x10df
ZBEE_MFG_CODE_CHAMELEON           = 0x10e0
ZBEE_MFG_CODE_SAMSUNG             = 0x10e1
ZBEE_MFG_CODE_RUWIDO              = 0x10e2
ZBEE_MFG_CODE_HUAWEI_1            = 0x10e3
ZBEE_MFG_CODE_HUAWEI_2            = 0x10e4
ZBEE_MFG_CODE_GREENWAVE           = 0x10e5
ZBEE_MFG_CODE_BGLOBAL             = 0x10e6
ZBEE_MFG_CODE_MINDTECK            = 0x10e7
ZBEE_MFG_CODE_INGERSOLL_RAND      = 0x10e8
ZBEE_MFG_CODE_DIUS                = 0x10e9
ZBEE_MFG_CODE_EMBEDDED            = 0x10ea
ZBEE_MFG_CODE_ABB                 = 0x10eb
ZBEE_MFG_CODE_SONY                = 0x10ec
ZBEE_MFG_CODE_GENUS               = 0x10ed
ZBEE_MFG_CODE_UNIVERSAL1          = 0x10ee
ZBEE_MFG_CODE_UNIVERSAL2          = 0x10ef
ZBEE_MFG_CODE_METRUM              = 0x10f0
ZBEE_MFG_CODE_CISCO               = 0x10f1
ZBEE_MFG_CODE_UBISYS              = 0x10f2
ZBEE_MFG_CODE_CONSERT             = 0x10f3
ZBEE_MFG_CODE_CRESTRON            = 0x10f4
ZBEE_MFG_CODE_ENPHASE             = 0x10f5
ZBEE_MFG_CODE_INVENSYS            = 0x10f6
ZBEE_MFG_CODE_MUELLER             = 0x10f7
ZBEE_MFG_CODE_AAC_TECH            = 0x10f8
ZBEE_MFG_CODE_U_NEXT              = 0x10f9
ZBEE_MFG_CODE_STEELCASE           = 0x10fa
ZBEE_MFG_CODE_TELEMATICS          = 0x10fb
ZBEE_MFG_CODE_SAMIL               = 0x10fc
ZBEE_MFG_CODE_PACE                = 0x10fd
ZBEE_MFG_CODE_OSBORNE             = 0x10fe
ZBEE_MFG_CODE_POWERWATCH          = 0x10ff
ZBEE_MFG_CODE_CANDELED            = 0x1100
ZBEE_MFG_CODE_FLEXGRID            = 0x1101
ZBEE_MFG_CODE_HUMAX               = 0x1102
ZBEE_MFG_CODE_UNIVERSAL           = 0x1103
ZBEE_MFG_CODE_ADVANCED_ENERGY     = 0x1104
ZBEE_MFG_CODE_BEGA                = 0x1105
ZBEE_MFG_CODE_BRUNEL              = 0x1106
ZBEE_MFG_CODE_PANASONIC           = 0x1107
ZBEE_MFG_CODE_ESYSTEMS            = 0x1108
ZBEE_MFG_CODE_PANAMAX             = 0x1109
ZBEE_MFG_CODE_PHYSICAL            = 0x110a
ZBEE_MFG_CODE_EM_LITE             = 0x110b
ZBEE_MFG_CODE_OSRAM               = 0x110c
ZBEE_MFG_CODE_2_SAVE              = 0x110d
ZBEE_MFG_CODE_PLANET              = 0x110e
ZBEE_MFG_CODE_AMBIENT             = 0x110f
ZBEE_MFG_CODE_PROFALUX            = 0x1110
ZBEE_MFG_CODE_BILLION             = 0x1111
ZBEE_MFG_CODE_EMBERTEC            = 0x1112
ZBEE_MFG_CODE_IT_WATCHDOGS        = 0x1113
ZBEE_MFG_CODE_RELOC               = 0x1114
ZBEE_MFG_CODE_INTEL               = 0x1115
ZBEE_MFG_CODE_TREND               = 0x1116
ZBEE_MFG_CODE_MOXA                = 0x1117
ZBEE_MFG_CODE_QEES                = 0x1118
ZBEE_MFG_CODE_SAYME               = 0x1119
ZBEE_MFG_CODE_PENTAIR             = 0x111a
ZBEE_MFG_CODE_ORBIT               = 0x111b
ZBEE_MFG_CODE_CALIFORNIA          = 0x111c
ZBEE_MFG_CODE_COMCAST2            = 0x111d
ZBEE_MFG_CODE_IDT                 = 0x111e
ZBEE_MFG_CODE_PIXELA              = 0x111f
ZBEE_MFG_CODE_TIVO                = 0x1120
ZBEE_MFG_CODE_FIDURE              = 0x1121
ZBEE_MFG_CODE_MARVELL             = 0x1122
ZBEE_MFG_CODE_WASION              = 0x1123
ZBEE_MFG_CODE_JASCO               = 0x1124
ZBEE_MFG_CODE_SHENZHEN            = 0x1125
ZBEE_MFG_CODE_NETCOMM             = 0x1126
ZBEE_MFG_CODE_DEFINE              = 0x1127
ZBEE_MFG_CODE_IN_HOME_DISP        = 0x1128
ZBEE_MFG_CODE_MIELE               = 0x1129
ZBEE_MFG_CODE_TELEVES             = 0x112a
ZBEE_MFG_CODE_LABELEC             = 0x112b
ZBEE_MFG_CODE_CHINA_ELEC          = 0x112c
ZBEE_MFG_CODE_VECTORFORM          = 0x112d
ZBEE_MFG_CODE_BUSCH_JAEGER        = 0x112e
ZBEE_MFG_CODE_REDPINE             = 0x112f
ZBEE_MFG_CODE_BRIDGES             = 0x1130
ZBEE_MFG_CODE_SERCOMM             = 0x1131
ZBEE_MFG_CODE_WSH                 = 0x1132
ZBEE_MFG_CODE_BOSCH               = 0x1133
ZBEE_MFG_CODE_EZEX                = 0x1134
ZBEE_MFG_CODE_DRESDEN             = 0x1135
ZBEE_MFG_CODE_MEAZON              = 0x1136
ZBEE_MFG_CODE_CROW                = 0x1137
ZBEE_MFG_CODE_HARVARD             = 0x1138
ZBEE_MFG_CODE_ANDSON              = 0x1139
ZBEE_MFG_CODE_ADHOCO              = 0x113a
ZBEE_MFG_CODE_WAXMAN              = 0x113b
ZBEE_MFG_CODE_OWON                = 0x113c
ZBEE_MFG_CODE_HITRON              = 0x113d
ZBEE_MFG_CODE_SCEMTEC             = 0x113e
ZBEE_MFG_CODE_WEBEE               = 0x113f
ZBEE_MFG_CODE_GRID2HOME           = 0x1140
ZBEE_MFG_CODE_TELINK              = 0x1141
ZBEE_MFG_CODE_JASMINE             = 0x1142
ZBEE_MFG_CODE_BIDGELY             = 0x1143
ZBEE_MFG_CODE_LUTRON              = 0x1144
ZBEE_MFG_CODE_IJENKO              = 0x1145
ZBEE_MFG_CODE_STARFIELD           = 0x1146
ZBEE_MFG_CODE_TCP                 = 0x1147
ZBEE_MFG_CODE_ROGERS              = 0x1148
ZBEE_MFG_CODE_CREE                = 0x1149
ZBEE_MFG_CODE_ROBERT_BOSCH        = 0x114a
ZBEE_MFG_CODE_IBIS                = 0x114b
ZBEE_MFG_CODE_QUIRKY              = 0x114c
ZBEE_MFG_CODE_EFERGY              = 0x114d
ZBEE_MFG_CODE_SMARTLABS           = 0x114e
ZBEE_MFG_CODE_EVERSPRING          = 0x114f
ZBEE_MFG_CODE_SWANN               = 0x1150

ZBEE_MFG_CODE_BOSCH2              = 0x1155
ZBEE_MFG_CODE_LEEDARSON           = 0x1168

# Manufacturer Names
ZBEE_MFG_CIRRONET                 = "Cirronet"
ZBEE_MFG_CHIPCON                  = "Chipcon"
ZBEE_MFG_EMBER                    = "Ember"
ZBEE_MFG_NTS                      = "National Tech"
ZBEE_MFG_FREESCALE                = "Freescale"
ZBEE_MFG_IPCOM                    = "IPCom"
ZBEE_MFG_SAN_JUAN                 = "San Juan Software"
ZBEE_MFG_TUV                      = "TUV"
ZBEE_MFG_COMPXS                   = "CompXs"
ZBEE_MFG_BM                       = "BM SpA"
ZBEE_MFG_AWAREPOINT               = "AwarePoint"
ZBEE_MFG_PHILIPS                  = "Philips"
ZBEE_MFG_LUXOFT                   = "Luxoft"
ZBEE_MFG_KORWIN                   = "Korvin"
ZBEE_MFG_1_RF                     = "One RF"
ZBEE_MFG_STG                      = "Software Technology Group"
ZBEE_MFG_TELEGESIS                = "Telegesis"
ZBEE_MFG_VISIONIC                 = "Visionic"
ZBEE_MFG_INSTA                    = "Insta"
ZBEE_MFG_ATALUM                   = "Atalum"
ZBEE_MFG_ATMEL                    = "Atmel"
ZBEE_MFG_DEVELCO                  = "Develco"
ZBEE_MFG_HONEYWELL                = "Honeywell"
ZBEE_MFG_RADIO_PULSE              = "RadioPulse"
ZBEE_MFG_RENESAS                  = "Renesas"
ZBEE_MFG_XANADU                   = "Xanadu Wireless"
ZBEE_MFG_NEC                      = "NEC Engineering"
ZBEE_MFG_YAMATAKE                 = "Yamatake"
ZBEE_MFG_TENDRIL                  = "Tendril"
ZBEE_MFG_ASSA                     = "Assa Abloy"
ZBEE_MFG_MAXSTREAM                = "Maxstream"
ZBEE_MFG_NEUROCOM                 = "Neurocom"
ZBEE_MFG_III                      = "Institute for Information Industry"
ZBEE_MFG_VANTAGE                  = "Vantage Controls"
ZBEE_MFG_ICONTROL                 = "iControl"
ZBEE_MFG_RAYMARINE                = "Raymarine"
ZBEE_MFG_LSR                      = "LS Research"
ZBEE_MFG_ONITY                    = "Onity"
ZBEE_MFG_MONO                     = "Mono Products"
ZBEE_MFG_RFT                      = "RF Tech"
ZBEE_MFG_ITRON                    = "Itron"
ZBEE_MFG_TRITECH                  = "Tritech"
ZBEE_MFG_EMBEDIT                  = "Embedit"
ZBEE_MFG_S3C                      = "S3C"
ZBEE_MFG_SIEMENS                  = "Siemens"
ZBEE_MFG_MINDTECH                 = "Mindtech"
ZBEE_MFG_LGE                      = "LG Electronics"
ZBEE_MFG_MITSUBISHI               = "Mitsubishi"
ZBEE_MFG_JOHNSON                  = "Johnson Controls"
ZBEE_MFG_PRI                      = "PRI"
ZBEE_MFG_KNICK                    = "Knick"
ZBEE_MFG_VICONICS                 = "Viconics"
ZBEE_MFG_FLEXIPANEL               = "Flexipanel"
ZBEE_MFG_PIASIM                   = "Piasim Corporation"
ZBEE_MFG_TRANE                    = "Trane"
ZBEE_MFG_JENNIC                   = "Jennic"
ZBEE_MFG_LIG                      = "Living Independently"
ZBEE_MFG_ALERTME                  = "AlertMe"
ZBEE_MFG_DAINTREE                 = "Daintree"
ZBEE_MFG_AIJI                     = "Aiji"
ZBEE_MFG_TEL_ITALIA               = "Telecom Italia"
ZBEE_MFG_MIKROKRETS               = "Mikrokrets"
ZBEE_MFG_OKI_SEMI                 = "Oki Semi"
ZBEE_MFG_NEWPORT                  = "Newport Electronics"
ZBEE_MFG_C4                       = "Control4"
ZBEE_MFG_STM                      = "STMicro"
ZBEE_MFG_ASN                      = "Ad-Sol Nissin"
ZBEE_MFG_DCSI                     = "DCSI"
ZBEE_MFG_FRANCE_TEL               = "France Telecom"
ZBEE_MFG_MUNET                    = "muNet"
ZBEE_MFG_AUTANI                   = "Autani"
ZBEE_MFG_COL_VNET                 = "Colorado vNet"
ZBEE_MFG_AEROCOMM                 = "Aerocomm"
ZBEE_MFG_SI_LABS                  = "Silicon Labs"
ZBEE_MFG_INNCOM                   = "Inncom"
ZBEE_MFG_CANNON                   = "Cannon"
ZBEE_MFG_SYNAPSE                  = "Synapse"
ZBEE_MFG_FPS                      = "Fisher Pierce/Sunrise"
ZBEE_MFG_CLS                      = "CentraLite"
ZBEE_MFG_CRANE                    = "Crane"
ZBEE_MFG_MOBILARM                 = "Mobilarm"
ZBEE_MFG_IMONITOR                 = "iMonitor"
ZBEE_MFG_BARTECH                  = "Bartech"
ZBEE_MFG_MESHNETICS               = "Meshnetics"
ZBEE_MFG_LS_IND                   = "LS Industrial"
ZBEE_MFG_CASON                    = "Cason"
ZBEE_MFG_WLESS_GLUE               = "Wireless Glue"
ZBEE_MFG_ELSTER                   = "Elster"
ZBEE_MFG_SMS_TEC                  = "SMS Tec"
ZBEE_MFG_ONSET                    = "Onset Computer"
ZBEE_MFG_RIGA                     = "Riga Development"
ZBEE_MFG_ENERGATE                 = "Energate"
ZBEE_MFG_CONMED                   = "ConMed Linvatec"
ZBEE_MFG_POWERMAND                = "PowerMand"
ZBEE_MFG_SCHNEIDER                = "Schneider Electric"
ZBEE_MFG_EATON                    = "Eaton"
ZBEE_MFG_TELULAR                  = "Telular"
ZBEE_MFG_DELPHI                   = "Delphi Medical"
ZBEE_MFG_EPISENSOR                = "EpiSensor"
ZBEE_MFG_LANDIS_GYR               = "Landis+Gyr"
ZBEE_MFG_KABA                     = "Kaba Group"
ZBEE_MFG_SHURE                    = "Shure"
ZBEE_MFG_COMVERGE                 = "Comverge"
ZBEE_MFG_DBS_LODGING              = "DBS Lodging"
ZBEE_MFG_ENERGY_AWARE             = "Energy Aware"
ZBEE_MFG_HIDALGO                  = "Hidalgo"
ZBEE_MFG_AIR2APP                  = "Air2App"
ZBEE_MFG_AMX                      = "AMX"
ZBEE_MFG_EDMI                     = "EDMI Pty"
ZBEE_MFG_CYAN                     = "Cyan Ltd"
ZBEE_MFG_SYS_SPA                  = "System SPA"
ZBEE_MFG_TELIT                    = "Telit"
ZBEE_MFG_KAGA                     = "Kaga Electronics"
ZBEE_MFG_4_NOKS                   = "4-noks s.r.l."
ZBEE_MFG_CERTICOM                 = "Certicom"
ZBEE_MFG_GRIDPOINT                = "Gridpoint"
ZBEE_MFG_PROFILE_SYS              = "Profile Systems"
ZBEE_MFG_COMPACTA                 = "Compacta International"
ZBEE_MFG_FREESTYLE                = "Freestyle Technology"
ZBEE_MFG_ALEKTRONA                = "Alektrona"
ZBEE_MFG_COMPUTIME                = "Computime"
ZBEE_MFG_REMOTE_TECH              = "Remote Technologies"
ZBEE_MFG_WAVECOM                  = "Wavecom"
ZBEE_MFG_ENERGY                   = "Energy Optimizers"
ZBEE_MFG_GE                       = "GE"
ZBEE_MFG_JETLUN                   = "Jetlun"
ZBEE_MFG_CIPHER                   = "Cipher Systems"
ZBEE_MFG_CORPORATE                = "Corporate Systems Eng"
ZBEE_MFG_ECOBEE                   = "ecobee"
ZBEE_MFG_SMK                      = "SMK"
ZBEE_MFG_MESHWORKS                = "Meshworks Wireless"
ZBEE_MFG_ELLIPS                   = "Ellips B.V."
ZBEE_MFG_SECURE                   = "Secure electrans"
ZBEE_MFG_CEDO                     = "CEDO"
ZBEE_MFG_TOSHIBA                  = "Toshiba"
ZBEE_MFG_DIGI                     = "Digi International"
ZBEE_MFG_UBILOGIX                 = "Ubilogix"
ZBEE_MFG_ECHELON                  = "Echelon"
ZBEE_MFG_GREEN_ENERGY             = "Green Energy Options"
ZBEE_MFG_SILVER_SPRING            = "Silver Spring Networks"
ZBEE_MFG_BLACK                    = "Black & Decker"
ZBEE_MFG_AZTECH_ASSOC             = "Aztech AssociatesInc."
ZBEE_MFG_A_AND_D                  = "A&D Co"
ZBEE_MFG_RAINFOREST               = "Rainforest Automation"
ZBEE_MFG_CARRIER                  = "Carrier Electronics"
ZBEE_MFG_SYCHIP                   = "SyChip/Murata"
ZBEE_MFG_OPEN_PEAK                = "OpenPeak"
ZBEE_MFG_PASSIVE                  = "Passive Systems"
ZBEE_MFG_G4S_JUSTICE              = "G4S JusticeServices"
ZBEE_MFG_MMB                      = "MMBResearch"
ZBEE_MFG_LEVITON                  = "Leviton"
ZBEE_MFG_KOREA_ELEC               = "Korea Electric Power Data Network"
ZBEE_MFG_COMCAST                  = "Comcast"
ZBEE_MFG_NEC_ELEC                 = "NEC Electronics"
ZBEE_MFG_NETVOX                   = "Netvox"
ZBEE_MFG_UCONTROL                 = "U-Control"
ZBEE_MFG_EMBEDIA                  = "Embedia Technologies"
ZBEE_MFG_SENSUS                   = "Sensus"
ZBEE_MFG_SUNRISE                  = "SunriseTechnologies"
ZBEE_MFG_MEMTECH                  = "MemtechCorp"
ZBEE_MFG_FREEBOX                  = "Freebox"
ZBEE_MFG_M2_LABS                  = "M2 Labs"
ZBEE_MFG_BRITISH_GAS              = "BritishGas"
ZBEE_MFG_SENTEC                   = "Sentec"
ZBEE_MFG_NAVETAS                  = "Navetas"
ZBEE_MFG_LIGHTSPEED               = "Lightspeed Technologies"
ZBEE_MFG_OKI                      = "Oki Electric"
ZBEE_MFG_SISTEMAS                 = "Sistemas Inteligentes"
ZBEE_MFG_DOMETIC                  = "Dometic"
ZBEE_MFG_APLS                     = "Alps"
ZBEE_MFG_ENERGY_HUB               = "EnergyHub"
ZBEE_MFG_KAMSTRUP                 = "Kamstrup"
ZBEE_MFG_ECHOSTAR                 = "EchoStar"
ZBEE_MFG_ENERNOC                  = "EnerNOC"
ZBEE_MFG_ELTAV                    = "Eltav"
ZBEE_MFG_BELKIN                   = "Belkin"
ZBEE_MFG_XSTREAMHD                = "XStreamHD Wireless"
ZBEE_MFG_SATURN_SOUTH             = "Saturn South"
ZBEE_MFG_GREENTRAP                = "GreenTrapOnline"
ZBEE_MFG_SMARTSYNCH               = "SmartSynch"
ZBEE_MFG_NYCE                     = "Nyce Control"
ZBEE_MFG_ICM_CONTROLS             = "ICM Controls"
ZBEE_MFG_MILLENNIUM               = "Millennium Electronics"
ZBEE_MFG_MOTOROLA                 = "Motorola"
ZBEE_MFG_EMERSON                  = "EmersonWhite-Rodgers"
ZBEE_MFG_RADIO_THERMOSTAT         = "Radio Thermostat"
ZBEE_MFG_OMRON                    = "OMRONCorporation"
ZBEE_MFG_GIINII                   = "GiiNii GlobalLimited"
ZBEE_MFG_FUJITSU                  = "Fujitsu GeneralLimited"
ZBEE_MFG_PEEL                     = "Peel Technologies"
ZBEE_MFG_ACCENT                   = "Accent"
ZBEE_MFG_BYTESNAP                 = "ByteSnap Design"
ZBEE_MFG_NEC_TOKIN                = "NEC TOKIN Corporation"
ZBEE_MFG_TRILLIANT                = "Trilliant Networks"
ZBEE_MFG_ELECTROLUX               = "Electrolux Italia"
ZBEE_MFG_ONZO                     = "OnzoLtd"
ZBEE_MFG_ENTEK                    = "EnTekSystems"
#
ZBEE_MFG_MAINSTREAM               = "MainstreamEngineering"
ZBEE_MFG_INDESIT                  = "IndesitCompany"
ZBEE_MFG_THINKECO                 = "THINKECO"
ZBEE_MFG_2D2C                     = "2D2C"
ZBEE_MFG_GREENPEAK                = "GreenPeak"
ZBEE_MFG_INTERCEL                 = "InterCEL"
ZBEE_MFG_LG                       = "LG Electronics"
ZBEE_MFG_MITSUMI1                 = "Mitsumi Electric"
ZBEE_MFG_MITSUMI2                 = "Mitsumi Electric"
ZBEE_MFG_ZENTRUM                  = "Zentrum Mikroelektronik Dresden"
ZBEE_MFG_NEST                     = "Nest Labs"
ZBEE_MFG_EXEGIN                   = "Exegin Technologies"
ZBEE_MFG_HONEYWELL                = "Honeywell"
ZBEE_MFG_TAKAHATA                 = "Takahata Precision"
ZBEE_MFG_SUMITOMO                 = "Sumitomo Electric Networks"
ZBEE_MFG_GE_ENERGY                = "GE Energy"
ZBEE_MFG_GE_APPLIANCES            = "GE Appliances"
ZBEE_MFG_RADIOCRAFTS              = "Radiocrafts AS"
ZBEE_MFG_CEIVA                    = "Ceiva"
ZBEE_MFG_TEC_CO                   = "TEC CO Co., Ltd"
ZBEE_MFG_CHAMELEON                = "Chameleon Technology (UK) Ltd"
ZBEE_MFG_SAMSUNG                  = "Samsung"
ZBEE_MFG_RUWIDO                   = "ruwido austria gmbh"
ZBEE_MFG_HUAWEI                   = "Huawei Technologies Co., Ltd."
ZBEE_MFG_GREENWAVE                = "Greenwave Reality"
ZBEE_MFG_BGLOBAL                  = "BGlobal Metering Ltd"
ZBEE_MFG_MINDTECK                 = "Mindteck"
ZBEE_MFG_INGERSOLL_RAND           = "Ingersoll-Rand"
ZBEE_MFG_DIUS                     = "Dius Computing Pty Ltd"
ZBEE_MFG_EMBEDDED                 = "Embedded Automation, Inc."
ZBEE_MFG_ABB                      = "ABB"
ZBEE_MFG_SONY                     = "Sony"
ZBEE_MFG_GENUS                    = "Genus Power Infrastructures Limited"
ZBEE_MFG_UNIVERSAL                = "Universal Electronics, Inc."
ZBEE_MFG_METRUM                   = "Metrum Technologies, LLC"
ZBEE_MFG_CISCO                    = "Cisco"
ZBEE_MFG_UBISYS                   = "Ubisys technologies GmbH"
ZBEE_MFG_CONSERT                  = "Consert"
ZBEE_MFG_CRESTRON                 = "Crestron Electronics"
ZBEE_MFG_ENPHASE                  = "Enphase Energy"
ZBEE_MFG_INVENSYS                 = "Invensys Controls"
ZBEE_MFG_MUELLER                  = "Mueller Systems, LLC"
ZBEE_MFG_AAC_TECH                 = "AAC Technologies Holding"
ZBEE_MFG_U_NEXT                   = "U-NEXT Co., Ltd"
ZBEE_MFG_STEELCASE                = "Steelcase Inc."
ZBEE_MFG_TELEMATICS               = "Telematics Wireless"
ZBEE_MFG_SAMIL                    = "Samil Power Co., Ltd"
ZBEE_MFG_PACE                     = "Pace Plc"
ZBEE_MFG_OSBORNE                  = "Osborne Coinage Co."
ZBEE_MFG_POWERWATCH               = "Powerwatch"
ZBEE_MFG_CANDELED                 = "CANDELED GmbH"
ZBEE_MFG_FLEXGRID                 = "FlexGrid S.R.L"
ZBEE_MFG_HUMAX                    = "Humax"
ZBEE_MFG_UNIVERSAL                = "Universal Devices"
ZBEE_MFG_ADVANCED_ENERGY          = "Advanced Energy"
ZBEE_MFG_BEGA                     = "BEGA Gantenbrink-Leuchten"
ZBEE_MFG_BRUNEL                   = "Brunel University"
ZBEE_MFG_PANASONIC                = "Panasonic R&D Center Singapore"
ZBEE_MFG_ESYSTEMS                 = "eSystems Research"
ZBEE_MFG_PANAMAX                  = "Panamax"
ZBEE_MFG_PHYSICAL                 = "Physical Graph Corporation"
ZBEE_MFG_EM_LITE                  = "EM-Lite Ltd."
ZBEE_MFG_OSRAM                    = "Osram Sylvania"
ZBEE_MFG_2_SAVE                   = "2 Save Energy Ltd."
ZBEE_MFG_PLANET                   = "Planet Innovation Products Pty Ltd"
ZBEE_MFG_AMBIENT                  = "Ambient Devices, Inc."
ZBEE_MFG_PROFALUX                 = "Profalux"
ZBEE_MFG_BILLION                  = "Billion Electric Company (BEC)"
ZBEE_MFG_EMBERTEC                 = "Embertec Pty Ltd"
ZBEE_MFG_IT_WATCHDOGS             = "IT Watchdogs"
ZBEE_MFG_RELOC                    = "Reloc"
ZBEE_MFG_INTEL                    = "Intel Corporation"
ZBEE_MFG_TREND                    = "Trend Electronics Limited"
ZBEE_MFG_MOXA                     = "Moxa"
ZBEE_MFG_QEES                     = "QEES"
ZBEE_MFG_SAYME                    = "SAYME Wireless Sensor Networks"
ZBEE_MFG_PENTAIR                  = "Pentair Aquatic Systems"
ZBEE_MFG_ORBIT                    = "Orbit Irrigation"
ZBEE_MFG_CALIFORNIA               = "California Eastern Laboratories"
ZBEE_MFG_COMCAST                  = "Comcast"
ZBEE_MFG_IDT                      = "IDT Technology Limited"
ZBEE_MFG_PIXELA                   = "Pixela"
ZBEE_MFG_TIVO                     = "TiVo"
ZBEE_MFG_FIDURE                   = "Fidure"
ZBEE_MFG_MARVELL                  = "Marvell Semiconductor"
ZBEE_MFG_WASION                   = "Wasion Group"
ZBEE_MFG_JASCO                    = "Jasco Products"
ZBEE_MFG_SHENZHEN                 = "Shenzhen Kaifa Technology"
ZBEE_MFG_NETCOMM                  = "Netcomm Wireless"
ZBEE_MFG_DEFINE                   = "Define Instruments"
ZBEE_MFG_IN_HOME_DISP             = "In Home Displays"
ZBEE_MFG_MIELE                    = "Miele & Cie. KG"
ZBEE_MFG_TELEVES                  = "Televes S.A."
ZBEE_MFG_LABELEC                  = "Labelec"
ZBEE_MFG_CHINA_ELEC               = "China Electronics Standardization Institute"
ZBEE_MFG_VECTORFORM               = "Vectorform"
ZBEE_MFG_BUSCH_JAEGER             = "Busch-Jaeger Elektro"
ZBEE_MFG_REDPINE                  = "Redpine Signals"
ZBEE_MFG_BRIDGES                  = "Bridges Electronic Technology"
ZBEE_MFG_SERCOMM                  = "Sercomm"
ZBEE_MFG_WSH                      = "WSH GmbH wirsindheller"
ZBEE_MFG_BOSCH                    = "Bosch Security Systems"
ZBEE_MFG_EZEX                     = "eZEX Corporation"
ZBEE_MFG_DRESDEN                  = "Dresden Elektronik Ingenieurtechnik GmbH"
ZBEE_MFG_MEAZON                   = "MEAZON S.A."
ZBEE_MFG_CROW                     = "Crow Electronic Engineering"
ZBEE_MFG_HARVARD                  = "Harvard Engineering"
ZBEE_MFG_ANDSON                   = "Andson(Beijing) Technology"
ZBEE_MFG_ADHOCO                   = "Adhoco AG"
ZBEE_MFG_WAXMAN                   = "Waxman Consumer Products Group"
ZBEE_MFG_OWON                     = "Owon Technology"
ZBEE_MFG_HITRON                   = "Hitron Technologies"
ZBEE_MFG_SCEMTEC                  = "Scemtec Steuerungstechnik GmbH"
ZBEE_MFG_WEBEE                    = "Webee"
ZBEE_MFG_GRID2HOME                = "Grid2Home"
ZBEE_MFG_TELINK                   = "Telink Micro"
ZBEE_MFG_JASMINE                  = "Jasmine Systems"
ZBEE_MFG_BIDGELY                  = "Bidgely"
ZBEE_MFG_LUTRON                   = "Lutron"
ZBEE_MFG_IJENKO                   = "IJENKO"
ZBEE_MFG_STARFIELD                = "Starfield Electronic"
ZBEE_MFG_TCP                      = "TCP"
ZBEE_MFG_ROGERS                   = "Rogers Communications Partnership"
ZBEE_MFG_CREE                     = "Cree"
ZBEE_MFG_ROBERT_BOSCH             = "Robert Bosch"
ZBEE_MFG_IBIS                     = "Ibis Networks"
ZBEE_MFG_QUIRKY                   = "Quirky"
ZBEE_MFG_EFERGY                   = "Efergy Technologies"
ZBEE_MFG_SMARTLABS                = "Smartlabs"
ZBEE_MFG_EVERSPRING               = "Everspring Industry"
ZBEE_MFG_SWANN                    = "Swann Communications"
ZBEE_MFG_TI                       = "Texas Instruments"

ZBEE_MFG_BOSCH2                   = "Bosch Connected Boiler"
ZBEE_MFG_LEEDARSON                = "Leedarson"

# Helper Functions
def usage():
    """Prints out usage info."""
    print "\nValidates ZigBee OTA Upgrade images."
    print "\nUsage:"
    print "\t$ %s -f <zigbee-ota-image>" % (sys.argv[0])
    print "\nWhere:"
    print "\t-f, --file"
    print "\t\tThe path to the file to validate"
    print "\t-h, --help"
    print "\t\tShows this usage info"

def mfg_code_str(mfg):
    """Converts from a ZigBee Manufacturer Code to a string."""
    if mfg == ZBEE_MFG_CODE_PANASONIC_RF4CE:
        mfg_str = ZBEE_MFG_PANASONIC
    elif mfg == ZBEE_MFG_CODE_SONY_RF4CE:
        mfg_str = ZBEE_MFG_SONY
    elif mfg == ZBEE_MFG_CODE_SAMSUNG_RF4CE:
        mfg_str = ZBEE_MFG_SAMSUNG
    elif mfg == ZBEE_MFG_CODE_PHILIPS_RF4CE:
        mfg_str = ZBEE_MFG_PHILIPS
    elif mfg == ZBEE_MFG_CODE_FREESCALE_RF4CE:
        mfg_str = ZBEE_MFG_FREESCALE
    elif mfg == ZBEE_MFG_CODE_OKI_SEMI_RF4CE:
        mfg_str = ZBEE_MFG_OKI_SEMI
    elif mfg == ZBEE_MFG_CODE_TI_RF4CE:
        mfg_str = ZBEE_MFG_TI
    elif mfg == ZBEE_MFG_CODE_CIRRONET:
        mfg_str = ZBEE_MFG_CIRRONET
    elif mfg == ZBEE_MFG_CODE_CHIPCON:
        mfg_str = ZBEE_MFG_CHIPCON
    elif mfg == ZBEE_MFG_CODE_EMBER:
        mfg_str = ZBEE_MFG_EMBER
    elif mfg == ZBEE_MFG_CODE_NTS:
        mfg_str = ZBEE_MFG_NTS
    elif mfg == ZBEE_MFG_CODE_FREESCALE:
        mfg_str = ZBEE_MFG_FREESCALE
    elif mfg == ZBEE_MFG_CODE_IPCOM:
        mfg_str = ZBEE_MFG_IPCOM
    elif mfg == ZBEE_MFG_CODE_SAN_JUAN:
        mfg_str = ZBEE_MFG_SAN_JUAN
    elif mfg == ZBEE_MFG_CODE_TUV:
        mfg_str = ZBEE_MFG_TUV
    elif mfg == ZBEE_MFG_CODE_COMPXS:
        mfg_str = ZBEE_MFG_COMPXS
    elif mfg == ZBEE_MFG_CODE_BM:
        mfg_str = ZBEE_MFG_BM
    elif mfg == ZBEE_MFG_CODE_AWAREPOINT:
        mfg_str = ZBEE_MFG_AWAREPOINT
    elif mfg == ZBEE_MFG_CODE_PHILIPS:
        mfg_str = ZBEE_MFG_PHILIPS
    elif mfg == ZBEE_MFG_CODE_LUXOFT:
        mfg_str = ZBEE_MFG_LUXOFT
    elif mfg == ZBEE_MFG_CODE_KORWIN:
        mfg_str = ZBEE_MFG_KORWIN
    elif mfg == ZBEE_MFG_CODE_1_RF:
        mfg_str = ZBEE_MFG_1_RF
    elif mfg == ZBEE_MFG_CODE_STG:
        mfg_str = ZBEE_MFG_STG
    elif mfg == ZBEE_MFG_CODE_TELEGESIS:
        mfg_str = ZBEE_MFG_TELEGESIS
    elif mfg == ZBEE_MFG_CODE_VISIONIC:
        mfg_str = ZBEE_MFG_VISIONIC
    elif mfg == ZBEE_MFG_CODE_INSTA:
        mfg_str = ZBEE_MFG_INSTA
    elif mfg == ZBEE_MFG_CODE_ATALUM:
        mfg_str = ZBEE_MFG_ATALUM
    elif mfg == ZBEE_MFG_CODE_ATMEL:
        mfg_str = ZBEE_MFG_ATMEL
    elif mfg == ZBEE_MFG_CODE_DEVELCO:
        mfg_str = ZBEE_MFG_DEVELCO
    elif mfg == ZBEE_MFG_CODE_HONEYWELL1:
        mfg_str = ZBEE_MFG_HONEYWELL1
    elif mfg == ZBEE_MFG_CODE_RADIO_PULSE:
        mfg_str = ZBEE_MFG_RADIO_PULSE
    elif mfg == ZBEE_MFG_CODE_RENESAS:
        mfg_str = ZBEE_MFG_RENESAS
    elif mfg == ZBEE_MFG_CODE_XANADU:
        mfg_str = ZBEE_MFG_XANADU
    elif mfg == ZBEE_MFG_CODE_NEC:
        mfg_str = ZBEE_MFG_NEC
    elif mfg == ZBEE_MFG_CODE_YAMATAKE:
        mfg_str = ZBEE_MFG_YAMATAKE
    elif mfg == ZBEE_MFG_CODE_TENDRIL:
        mfg_str = ZBEE_MFG_TENDRIL
    elif mfg == ZBEE_MFG_CODE_ASSA:
        mfg_str = ZBEE_MFG_ASSA
    elif mfg == ZBEE_MFG_CODE_MAXSTREAM:
        mfg_str = ZBEE_MFG_MAXSTREAM
    elif mfg == ZBEE_MFG_CODE_NEUROCOM:
        mfg_str = ZBEE_MFG_NEUROCOM
    elif mfg == ZBEE_MFG_CODE_III:
        mfg_str = ZBEE_MFG_III
    elif mfg == ZBEE_MFG_CODE_VANTAGE:
        mfg_str = ZBEE_MFG_VANTAGE
    elif mfg == ZBEE_MFG_CODE_ICONTROL:
        mfg_str = ZBEE_MFG_ICONTROL
    elif mfg == ZBEE_MFG_CODE_RAYMARINE:
        mfg_str = ZBEE_MFG_RAYMARINE
    elif mfg == ZBEE_MFG_CODE_LSR:
        mfg_str = ZBEE_MFG_LSR
    elif mfg == ZBEE_MFG_CODE_ONITY:
        mfg_str = ZBEE_MFG_ONITY
    elif mfg == ZBEE_MFG_CODE_MONO:
        mfg_str = ZBEE_MFG_MONO
    elif mfg == ZBEE_MFG_CODE_RFT:
        mfg_str = ZBEE_MFG_RFT
    elif mfg == ZBEE_MFG_CODE_ITRON:
        mfg_str = ZBEE_MFG_ITRON
    elif mfg == ZBEE_MFG_CODE_TRITECH:
        mfg_str = ZBEE_MFG_TRITECH
    elif mfg == ZBEE_MFG_CODE_EMBEDIT:
        mfg_str = ZBEE_MFG_EMBEDIT
    elif mfg == ZBEE_MFG_CODE_S3C:
        mfg_str = ZBEE_MFG_S3C
    elif mfg == ZBEE_MFG_CODE_SIEMENS:
        mfg_str = ZBEE_MFG_SIEMENS
    elif mfg == ZBEE_MFG_CODE_MINDTECH:
        mfg_str = ZBEE_MFG_MINDTECH
    elif mfg == ZBEE_MFG_CODE_LGE:
        mfg_str = ZBEE_MFG_LGE
    elif mfg == ZBEE_MFG_CODE_MITSUBISHI:
        mfg_str = ZBEE_MFG_MITSUBISHI
    elif mfg == ZBEE_MFG_CODE_JOHNSON:
        mfg_str = ZBEE_MFG_JOHNSON
    elif mfg == ZBEE_MFG_CODE_PRI:
        mfg_str = ZBEE_MFG_PRI
    elif mfg == ZBEE_MFG_CODE_KNICK:
        mfg_str = ZBEE_MFG_KNICK
    elif mfg == ZBEE_MFG_CODE_VICONICS:
        mfg_str = ZBEE_MFG_VICONICS
    elif mfg == ZBEE_MFG_CODE_FLEXIPANEL:
        mfg_str = ZBEE_MFG_FLEXIPANEL
    elif mfg == ZBEE_MFG_CODE_PIASIM:
        mfg_str = ZBEE_MFG_PIASIM
    elif mfg == ZBEE_MFG_CODE_TRANE:
        mfg_str = ZBEE_MFG_TRANE
    elif mfg == ZBEE_MFG_CODE_JENNIC:
        mfg_str = ZBEE_MFG_JENNIC
    elif mfg == ZBEE_MFG_CODE_LIG:
        mfg_str = ZBEE_MFG_LIG
    elif mfg == ZBEE_MFG_CODE_ALERTME:
        mfg_str = ZBEE_MFG_ALERTME
    elif mfg == ZBEE_MFG_CODE_DAINTREE:
        mfg_str = ZBEE_MFG_DAINTREE
    elif mfg == ZBEE_MFG_CODE_AIJI:
        mfg_str = ZBEE_MFG_AIJI
    elif mfg == ZBEE_MFG_CODE_TEL_ITALIA:
        mfg_str = ZBEE_MFG_TEL_ITALIA
    elif mfg == ZBEE_MFG_CODE_MIKROKRETS:
        mfg_str = ZBEE_MFG_MIKROKRETS
    elif mfg == ZBEE_MFG_CODE_OKI_SEMI:
        mfg_str = ZBEE_MFG_OKI_SEMI
    elif mfg == ZBEE_MFG_CODE_NEWPORT:
        mfg_str = ZBEE_MFG_NEWPORT
    elif mfg == ZBEE_MFG_CODE_C4:
        mfg_str = ZBEE_MFG_C4
    elif mfg == ZBEE_MFG_CODE_STM:
        mfg_str = ZBEE_MFG_STM
    elif mfg == ZBEE_MFG_CODE_ASN:
        mfg_str = ZBEE_MFG_ASN
    elif mfg == ZBEE_MFG_CODE_DCSI:
        mfg_str = ZBEE_MFG_DCSI
    elif mfg == ZBEE_MFG_CODE_FRANCE_TEL:
        mfg_str = ZBEE_MFG_FRANCE_TEL
    elif mfg == ZBEE_MFG_CODE_MUNET:
        mfg_str = ZBEE_MFG_MUNET
    elif mfg == ZBEE_MFG_CODE_AUTANI:
        mfg_str = ZBEE_MFG_AUTANI
    elif mfg == ZBEE_MFG_CODE_COL_VNET:
        mfg_str = ZBEE_MFG_COL_VNET
    elif mfg == ZBEE_MFG_CODE_AEROCOMM:
        mfg_str = ZBEE_MFG_AEROCOMM
    elif mfg == ZBEE_MFG_CODE_SI_LABS:
        mfg_str = ZBEE_MFG_SI_LABS
    elif mfg == ZBEE_MFG_CODE_INNCOM:
        mfg_str = ZBEE_MFG_INNCOM
    elif mfg == ZBEE_MFG_CODE_CANNON:
        mfg_str = ZBEE_MFG_CANNON
    elif mfg == ZBEE_MFG_CODE_SYNAPSE:
        mfg_str = ZBEE_MFG_SYNAPSE
    elif mfg == ZBEE_MFG_CODE_FPS:
        mfg_str = ZBEE_MFG_FPS
    elif mfg == ZBEE_MFG_CODE_CLS:
        mfg_str = ZBEE_MFG_CLS
    elif mfg == ZBEE_MFG_CODE_CRANE:
        mfg_str = ZBEE_MFG_CRANE
    elif mfg == ZBEE_MFG_CODE_MOBILARM:
        mfg_str = ZBEE_MFG_MOBILARM
    elif mfg == ZBEE_MFG_CODE_IMONITOR:
        mfg_str = ZBEE_MFG_IMONITOR
    elif mfg == ZBEE_MFG_CODE_BARTECH:
        mfg_str = ZBEE_MFG_BARTECH
    elif mfg == ZBEE_MFG_CODE_MESHNETICS:
        mfg_str = ZBEE_MFG_MESHNETICS
    elif mfg == ZBEE_MFG_CODE_LS_IND:
        mfg_str = ZBEE_MFG_LS_IND
    elif mfg == ZBEE_MFG_CODE_CASON:
        mfg_str = ZBEE_MFG_CASON
    elif mfg == ZBEE_MFG_CODE_WLESS_GLUE:
        mfg_str = ZBEE_MFG_WLESS_GLUE
    elif mfg == ZBEE_MFG_CODE_ELSTER:
        mfg_str = ZBEE_MFG_ELSTER
    elif mfg == ZBEE_MFG_CODE_SMS_TEC:
        mfg_str = ZBEE_MFG_SMS_TEC
    elif mfg == ZBEE_MFG_CODE_ONSET:
        mfg_str = ZBEE_MFG_ONSET
    elif mfg == ZBEE_MFG_CODE_RIGA:
        mfg_str = ZBEE_MFG_RIGA
    elif mfg == ZBEE_MFG_CODE_ENERGATE:
        mfg_str = ZBEE_MFG_ENERGATE
    elif mfg == ZBEE_MFG_CODE_CONMED:
        mfg_str = ZBEE_MFG_CONMED
    elif mfg == ZBEE_MFG_CODE_POWERMAND:
        mfg_str = ZBEE_MFG_POWERMAND
    elif mfg == ZBEE_MFG_CODE_SCHNEIDER:
        mfg_str = ZBEE_MFG_SCHNEIDER
    elif mfg == ZBEE_MFG_CODE_EATON:
        mfg_str = ZBEE_MFG_EATON
    elif mfg == ZBEE_MFG_CODE_TELULAR:
        mfg_str = ZBEE_MFG_TELULAR
    elif mfg == ZBEE_MFG_CODE_DELPHI:
        mfg_str = ZBEE_MFG_DELPHI
    elif mfg == ZBEE_MFG_CODE_EPISENSOR:
        mfg_str = ZBEE_MFG_EPISENSOR
    elif mfg == ZBEE_MFG_CODE_LANDIS_GYR:
        mfg_str = ZBEE_MFG_LANDIS_GYR
    elif mfg == ZBEE_MFG_CODE_KABA:
        mfg_str = ZBEE_MFG_KABA
    elif mfg == ZBEE_MFG_CODE_SHURE:
        mfg_str = ZBEE_MFG_SHURE
    elif mfg == ZBEE_MFG_CODE_COMVERGE:
        mfg_str = ZBEE_MFG_COMVERGE
    elif mfg == ZBEE_MFG_CODE_DBS_LODGING:
        mfg_str = ZBEE_MFG_DBS_LODGING
    elif mfg == ZBEE_MFG_CODE_ENERGY_AWARE:
        mfg_str = ZBEE_MFG_ENERGY_AWARE
    elif mfg == ZBEE_MFG_CODE_HIDALGO:
        mfg_str = ZBEE_MFG_HIDALGO
    elif mfg == ZBEE_MFG_CODE_AIR2APP:
        mfg_str = ZBEE_MFG_AIR2APP
    elif mfg == ZBEE_MFG_CODE_AMX:
        mfg_str = ZBEE_MFG_AMX
    elif mfg == ZBEE_MFG_CODE_EDMI:
        mfg_str = ZBEE_MFG_EDMI
    elif mfg == ZBEE_MFG_CODE_CYAN:
        mfg_str = ZBEE_MFG_CYAN
    elif mfg == ZBEE_MFG_CODE_SYS_SPA:
        mfg_str = ZBEE_MFG_SYS_SPA
    elif mfg == ZBEE_MFG_CODE_TELIT:
        mfg_str = ZBEE_MFG_TELIT
    elif mfg == ZBEE_MFG_CODE_KAGA:
        mfg_str = ZBEE_MFG_KAGA
    elif mfg == ZBEE_MFG_CODE_4_NOKS:
        mfg_str = ZBEE_MFG_4_NOKS
    elif mfg == ZBEE_MFG_CODE_CERTICOM:
        mfg_str = ZBEE_MFG_CERTICOM
    elif mfg == ZBEE_MFG_CODE_GRIDPOINT:
        mfg_str = ZBEE_MFG_GRIDPOINT
    elif mfg == ZBEE_MFG_CODE_PROFILE_SYS:
        mfg_str = ZBEE_MFG_PROFILE_SYS
    elif mfg == ZBEE_MFG_CODE_COMPACTA:
        mfg_str = ZBEE_MFG_COMPACTA
    elif mfg == ZBEE_MFG_CODE_FREESTYLE:
        mfg_str = ZBEE_MFG_FREESTYLE
    elif mfg == ZBEE_MFG_CODE_ALEKTRONA:
        mfg_str = ZBEE_MFG_ALEKTRONA
    elif mfg == ZBEE_MFG_CODE_COMPUTIME:
        mfg_str = ZBEE_MFG_COMPUTIME
    elif mfg == ZBEE_MFG_CODE_REMOTE_TECH:
        mfg_str = ZBEE_MFG_REMOTE_TECH
    elif mfg == ZBEE_MFG_CODE_WAVECOM:
        mfg_str = ZBEE_MFG_WAVECOM
    elif mfg == ZBEE_MFG_CODE_ENERGY:
        mfg_str = ZBEE_MFG_ENERGY
    elif mfg == ZBEE_MFG_CODE_GE:
        mfg_str = ZBEE_MFG_GE
    elif mfg == ZBEE_MFG_CODE_JETLUN:
        mfg_str = ZBEE_MFG_JETLUN
    elif mfg == ZBEE_MFG_CODE_CIPHER:
        mfg_str = ZBEE_MFG_CIPHER
    elif mfg == ZBEE_MFG_CODE_CORPORATE:
        mfg_str = ZBEE_MFG_CORPORATE
    elif mfg == ZBEE_MFG_CODE_ECOBEE:
        mfg_str = ZBEE_MFG_ECOBEE
    elif mfg == ZBEE_MFG_CODE_SMK:
        mfg_str = ZBEE_MFG_SMK
    elif mfg == ZBEE_MFG_CODE_MESHWORKS:
        mfg_str = ZBEE_MFG_MESHWORKS
    elif mfg == ZBEE_MFG_CODE_ELLIPS:
        mfg_str = ZBEE_MFG_ELLIPS
    elif mfg == ZBEE_MFG_CODE_SECURE:
        mfg_str = ZBEE_MFG_SECURE
    elif mfg == ZBEE_MFG_CODE_CEDO:
        mfg_str = ZBEE_MFG_CEDO
    elif mfg == ZBEE_MFG_CODE_TOSHIBA:
        mfg_str = ZBEE_MFG_TOSHIBA
    elif mfg == ZBEE_MFG_CODE_DIGI:
        mfg_str = ZBEE_MFG_DIGI
    elif mfg == ZBEE_MFG_CODE_UBILOGIX:
        mfg_str = ZBEE_MFG_UBILOGIX
    elif mfg == ZBEE_MFG_CODE_ECHELON:
        mfg_str = ZBEE_MFG_ECHELON
# Gap in the codes (0x108a to 0x108f)
    elif mfg == ZBEE_MFG_CODE_GREEN_ENERGY:
        mfg_str = ZBEE_MFG_GREEN_ENERGY
    elif mfg == ZBEE_MFG_CODE_SILVER_SPRING:
        mfg_str = ZBEE_MFG_SILVER_SPRING
    elif mfg == ZBEE_MFG_CODE_BLACK:
        mfg_str = ZBEE_MFG_BLACK
    elif mfg == ZBEE_MFG_CODE_AZTECH_ASSOC:
        mfg_str = ZBEE_MFG_AZTECH_ASSOC
    elif mfg == ZBEE_MFG_CODE_A_AND_D:
        mfg_str = ZBEE_MFG_A_AND_D
    elif mfg == ZBEE_MFG_CODE_RAINFOREST:
        mfg_str = ZBEE_MFG_RAINFOREST
    elif mfg == ZBEE_MFG_CODE_CARRIER:
        mfg_str = ZBEE_MFG_CARRIER
    elif mfg == ZBEE_MFG_CODE_SYCHIP:
        mfg_str = ZBEE_MFG_SYCHIP
    elif mfg == ZBEE_MFG_CODE_OPEN_PEAK:
        mfg_str = ZBEE_MFG_OPEN_PEAK
    elif mfg == ZBEE_MFG_CODE_PASSIVE:
        mfg_str = ZBEE_MFG_PASSIVE
    elif mfg == ZBEE_MFG_CODE_MMB:
        mfg_str = ZBEE_MFG_MMB
    elif mfg == ZBEE_MFG_CODE_LEVITON:
        mfg_str = ZBEE_MFG_LEVITON
    elif mfg == ZBEE_MFG_CODE_KOREA_ELEC:
        mfg_str = ZBEE_MFG_KOREA_ELEC
    elif mfg == ZBEE_MFG_CODE_COMCAST1:
        mfg_str = ZBEE_MFG_COMCAST1
    elif mfg == ZBEE_MFG_CODE_NEC_ELEC:
        mfg_str = ZBEE_MFG_NEC_ELEC
    elif mfg == ZBEE_MFG_CODE_NETVOX:
        mfg_str = ZBEE_MFG_NETVOX
    elif mfg == ZBEE_MFG_CODE_UCONTROL:
        mfg_str = ZBEE_MFG_UCONTROL
    elif mfg == ZBEE_MFG_CODE_EMBEDIA:
        mfg_str = ZBEE_MFG_EMBEDIA
    elif mfg == ZBEE_MFG_CODE_SENSUS:
        mfg_str = ZBEE_MFG_SENSUS
    elif mfg == ZBEE_MFG_CODE_SUNRISE:
        mfg_str = ZBEE_MFG_SUNRISE
    elif mfg == ZBEE_MFG_CODE_MEMTECH:
        mfg_str = ZBEE_MFG_MEMTECH
    elif mfg == ZBEE_MFG_CODE_FREEBOX:
        mfg_str = ZBEE_MFG_FREEBOX
    elif mfg == ZBEE_MFG_CODE_M2_LABS:
        mfg_str = ZBEE_MFG_M2_LABS
    elif mfg == ZBEE_MFG_CODE_BRITISH_GAS:
        mfg_str = ZBEE_MFG_BRITISH_GAS
    elif mfg == ZBEE_MFG_CODE_SENTEC:
        mfg_str = ZBEE_MFG_SENTEC
    elif mfg == ZBEE_MFG_CODE_NAVETAS:
        mfg_str = ZBEE_MFG_NAVETAS
    elif mfg == ZBEE_MFG_CODE_LIGHTSPEED:
        mfg_str = ZBEE_MFG_LIGHTSPEED
    elif mfg == ZBEE_MFG_CODE_OKI:
        mfg_str = ZBEE_MFG_OKI
    elif mfg == ZBEE_MFG_CODE_SISTEMAS:
        mfg_str = ZBEE_MFG_SISTEMAS
    elif mfg == ZBEE_MFG_CODE_DOMETIC:
        mfg_str = ZBEE_MFG_DOMETIC
    elif mfg == ZBEE_MFG_CODE_APLS:
        mfg_str = ZBEE_MFG_APLS
    elif mfg == ZBEE_MFG_CODE_ENERGY_HUB:
        mfg_str = ZBEE_MFG_ENERGY_HUB
    elif mfg == ZBEE_MFG_CODE_KAMSTRUP:
        mfg_str = ZBEE_MFG_KAMSTRUP
    elif mfg == ZBEE_MFG_CODE_ECHOSTAR:
        mfg_str = ZBEE_MFG_ECHOSTAR
    elif mfg == ZBEE_MFG_CODE_ENERNOC:
        mfg_str = ZBEE_MFG_ENERNOC
    elif mfg == ZBEE_MFG_CODE_ELTAV:
        mfg_str = ZBEE_MFG_ELTAV
    elif mfg == ZBEE_MFG_CODE_BELKIN:
        mfg_str = ZBEE_MFG_BELKIN
    elif mfg == ZBEE_MFG_CODE_XSTREAMHD:
        mfg_str = ZBEE_MFG_XSTREAMHD
    elif mfg == ZBEE_MFG_CODE_SATURN_SOUTH:
        mfg_str = ZBEE_MFG_SATURN_SOUTH
    elif mfg == ZBEE_MFG_CODE_GREENTRAP:
        mfg_str = ZBEE_MFG_GREENTRAP
    elif mfg == ZBEE_MFG_CODE_SMARTSYNCH:
        mfg_str = ZBEE_MFG_SMARTSYNCH
    elif mfg == ZBEE_MFG_CODE_NYCE:
        mfg_str = ZBEE_MFG_NYCE
    elif mfg == ZBEE_MFG_CODE_ICM_CONTROLS:
        mfg_str = ZBEE_MFG_ICM_CONTROLS
    elif mfg == ZBEE_MFG_CODE_MILLENNIUM:
        mfg_str = ZBEE_MFG_MILLENNIUM
    elif mfg == ZBEE_MFG_CODE_MOTOROLA:
        mfg_str = ZBEE_MFG_MOTOROLA
    elif mfg == ZBEE_MFG_CODE_EMERSON:
        mfg_str = ZBEE_MFG_EMERSON
    elif mfg == ZBEE_MFG_CODE_RADIO_THERMOSTAT:
        mfg_str = ZBEE_MFG_RADIO_THERMOSTAT
    elif mfg == ZBEE_MFG_CODE_OMRON:
        mfg_str = ZBEE_MFG_OMRON
    elif mfg == ZBEE_MFG_CODE_GIINII:
        mfg_str = ZBEE_MFG_GIINII
    elif mfg == ZBEE_MFG_CODE_FUJITSU:
        mfg_str = ZBEE_MFG_FUJITSU
    elif mfg == ZBEE_MFG_CODE_PEEL:
        mfg_str = ZBEE_MFG_PEEL
    elif mfg == ZBEE_MFG_CODE_ACCENT:
        mfg_str = ZBEE_MFG_ACCENT
    elif mfg == ZBEE_MFG_CODE_BYTESNAP:
        mfg_str = ZBEE_MFG_BYTESNAP
    elif mfg == ZBEE_MFG_CODE_NEC_TOKIN:
        mfg_str = ZBEE_MFG_NEC_TOKIN
    elif mfg == ZBEE_MFG_CODE_G4S_JUSTICE:
        mfg_str = ZBEE_MFG_G4S_JUSTICE
    elif mfg == ZBEE_MFG_CODE_TRILLIANT:
        mfg_str = ZBEE_MFG_TRILLIANT
    elif mfg == ZBEE_MFG_CODE_ELECTROLUX:
        mfg_str = ZBEE_MFG_ELECTROLUX
    elif mfg == ZBEE_MFG_CODE_ONZO:
        mfg_str = ZBEE_MFG_ONZO
    elif mfg == ZBEE_MFG_CODE_ENTEK:
        mfg_str = ZBEE_MFG_ENTEK
    elif mfg == ZBEE_MFG_CODE_PHILIPS2:
        mfg_str = ZBEE_MFG_PHILIPS2
    elif mfg == ZBEE_MFG_CODE_MAINSTREAM:
        mfg_str = ZBEE_MFG_MAINSTREAM
    elif mfg == ZBEE_MFG_CODE_INDESIT:
        mfg_str = ZBEE_MFG_INDESIT
    elif mfg == ZBEE_MFG_CODE_THINKECO:
        mfg_str = ZBEE_MFG_THINKECO
    elif mfg == ZBEE_MFG_CODE_2D2C:
        mfg_str = ZBEE_MFG_2D2C
    elif mfg == ZBEE_MFG_CODE_GREENPEAK:
        mfg_str = ZBEE_MFG_GREENPEAK
    elif mfg == ZBEE_MFG_CODE_INTERCEL:
        mfg_str = ZBEE_MFG_INTERCEL
    elif mfg == ZBEE_MFG_CODE_LG:
        mfg_str = ZBEE_MFG_LG
    elif mfg == ZBEE_MFG_CODE_MITSUMI1:
        mfg_str = ZBEE_MFG_MITSUMI1
    elif mfg == ZBEE_MFG_CODE_MITSUMI2:
        mfg_str = ZBEE_MFG_MITSUMI2
    elif mfg == ZBEE_MFG_CODE_ZENTRUM:
        mfg_str = ZBEE_MFG_ZENTRUM
    elif mfg == ZBEE_MFG_CODE_NEST:
        mfg_str = ZBEE_MFG_NEST
    elif mfg == ZBEE_MFG_CODE_EXEGIN:
        mfg_str = ZBEE_MFG_EXEGIN
    elif mfg == ZBEE_MFG_CODE_HONEYWELL2:
        mfg_str = ZBEE_MFG_HONEYWELL2
    elif mfg == ZBEE_MFG_CODE_TAKAHATA:
        mfg_str = ZBEE_MFG_TAKAHATA
    elif mfg == ZBEE_MFG_CODE_SUMITOMO:
        mfg_str = ZBEE_MFG_SUMITOMO
    elif mfg == ZBEE_MFG_CODE_GE_ENERGY:
        mfg_str = ZBEE_MFG_GE_ENERGY
    elif mfg == ZBEE_MFG_CODE_GE_APPLIANCES:
        mfg_str = ZBEE_MFG_GE_APPLIANCES
    elif mfg == ZBEE_MFG_CODE_RADIOCRAFTS:
        mfg_str = ZBEE_MFG_RADIOCRAFTS
    elif mfg == ZBEE_MFG_CODE_CEIVA:
        mfg_str = ZBEE_MFG_CEIVA
    elif mfg == ZBEE_MFG_CODE_TEC_CO:
        mfg_str = ZBEE_MFG_TEC_CO
    elif mfg == ZBEE_MFG_CODE_CHAMELEON:
        mfg_str = ZBEE_MFG_CHAMELEON
    elif mfg == ZBEE_MFG_CODE_SAMSUNG:
        mfg_str = ZBEE_MFG_SAMSUNG
    elif mfg == ZBEE_MFG_CODE_RUWIDO:
        mfg_str = ZBEE_MFG_RUWIDO
    elif mfg == ZBEE_MFG_CODE_HUAWEI_1:
        mfg_str = ZBEE_MFG_HUAWEI_1
    elif mfg == ZBEE_MFG_CODE_HUAWEI_2:
        mfg_str = ZBEE_MFG_HUAWEI_2
    elif mfg == ZBEE_MFG_CODE_GREENWAVE:
        mfg_str = ZBEE_MFG_GREENWAVE
    elif mfg == ZBEE_MFG_CODE_BGLOBAL:
        mfg_str = ZBEE_MFG_BGLOBAL
    elif mfg == ZBEE_MFG_CODE_MINDTECK:
        mfg_str = ZBEE_MFG_MINDTECK
    elif mfg == ZBEE_MFG_CODE_INGERSOLL_RAND:
        mfg_str = ZBEE_MFG_INGERSOLL_RAND
    elif mfg == ZBEE_MFG_CODE_DIUS:
        mfg_str = ZBEE_MFG_DIUS
    elif mfg == ZBEE_MFG_CODE_EMBEDDED:
        mfg_str = ZBEE_MFG_EMBEDDED
    elif mfg == ZBEE_MFG_CODE_ABB:
        mfg_str = ZBEE_MFG_ABB
    elif mfg == ZBEE_MFG_CODE_SONY:
        mfg_str = ZBEE_MFG_SONY
    elif mfg == ZBEE_MFG_CODE_GENUS:
        mfg_str = ZBEE_MFG_GENUS
    elif mfg == ZBEE_MFG_CODE_UNIVERSAL1:
        mfg_str = ZBEE_MFG_UNIVERSAL1
    elif mfg == ZBEE_MFG_CODE_UNIVERSAL2:
        mfg_str = ZBEE_MFG_UNIVERSAL2
    elif mfg == ZBEE_MFG_CODE_METRUM:
        mfg_str = ZBEE_MFG_METRUM
    elif mfg == ZBEE_MFG_CODE_CISCO:
        mfg_str = ZBEE_MFG_CISCO
    elif mfg == ZBEE_MFG_CODE_UBISYS:
        mfg_str = ZBEE_MFG_UBISYS
    elif mfg == ZBEE_MFG_CODE_CONSERT:
        mfg_str = ZBEE_MFG_CONSERT
    elif mfg == ZBEE_MFG_CODE_CRESTRON:
        mfg_str = ZBEE_MFG_CRESTRON
    elif mfg == ZBEE_MFG_CODE_ENPHASE:
        mfg_str = ZBEE_MFG_ENPHASE
    elif mfg == ZBEE_MFG_CODE_INVENSYS:
        mfg_str = ZBEE_MFG_INVENSYS
    elif mfg == ZBEE_MFG_CODE_MUELLER:
        mfg_str = ZBEE_MFG_MUELLER
    elif mfg == ZBEE_MFG_CODE_AAC_TECH:
        mfg_str = ZBEE_MFG_AAC_TECH
    elif mfg == ZBEE_MFG_CODE_U_NEXT:
        mfg_str = ZBEE_MFG_U_NEXT
    elif mfg == ZBEE_MFG_CODE_STEELCASE:
        mfg_str = ZBEE_MFG_STEELCASE
    elif mfg == ZBEE_MFG_CODE_TELEMATICS:
        mfg_str = ZBEE_MFG_TELEMATICS
    elif mfg == ZBEE_MFG_CODE_SAMIL:
        mfg_str = ZBEE_MFG_SAMIL
    elif mfg == ZBEE_MFG_CODE_PACE:
        mfg_str = ZBEE_MFG_PACE
    elif mfg == ZBEE_MFG_CODE_OSBORNE:
        mfg_str = ZBEE_MFG_OSBORNE
    elif mfg == ZBEE_MFG_CODE_POWERWATCH:
        mfg_str = ZBEE_MFG_POWERWATCH
    elif mfg == ZBEE_MFG_CODE_CANDELED:
        mfg_str = ZBEE_MFG_CANDELED
    elif mfg == ZBEE_MFG_CODE_FLEXGRID:
        mfg_str = ZBEE_MFG_FLEXGRID
    elif mfg == ZBEE_MFG_CODE_HUMAX:
        mfg_str = ZBEE_MFG_HUMAX
    elif mfg == ZBEE_MFG_CODE_UNIVERSAL:
        mfg_str = ZBEE_MFG_UNIVERSAL
    elif mfg == ZBEE_MFG_CODE_ADVANCED_ENERGY:
        mfg_str = ZBEE_MFG_ADVANCED_ENERGY
    elif mfg == ZBEE_MFG_CODE_BEGA:
        mfg_str = ZBEE_MFG_BEGA
    elif mfg == ZBEE_MFG_CODE_BRUNEL:
        mfg_str = ZBEE_MFG_BRUNEL
    elif mfg == ZBEE_MFG_CODE_PANASONIC:
        mfg_str = ZBEE_MFG_PANASONIC
    elif mfg == ZBEE_MFG_CODE_ESYSTEMS:
        mfg_str = ZBEE_MFG_ESYSTEMS
    elif mfg == ZBEE_MFG_CODE_PANAMAX:
        mfg_str = ZBEE_MFG_PANAMAX
    elif mfg == ZBEE_MFG_CODE_PHYSICAL:
        mfg_str = ZBEE_MFG_PHYSICAL
    elif mfg == ZBEE_MFG_CODE_EM_LITE:
        mfg_str = ZBEE_MFG_EM_LITE
    elif mfg == ZBEE_MFG_CODE_OSRAM:
        mfg_str = ZBEE_MFG_OSRAM
    elif mfg == ZBEE_MFG_CODE_2_SAVE:
        mfg_str = ZBEE_MFG_2_SAVE
    elif mfg == ZBEE_MFG_CODE_PLANET:
        mfg_str = ZBEE_MFG_PLANET
    elif mfg == ZBEE_MFG_CODE_AMBIENT:
        mfg_str = ZBEE_MFG_AMBIENT
    elif mfg == ZBEE_MFG_CODE_PROFALUX:
        mfg_str = ZBEE_MFG_PROFALUX
    elif mfg == ZBEE_MFG_CODE_BILLION:
        mfg_str = ZBEE_MFG_BILLION
    elif mfg == ZBEE_MFG_CODE_EMBERTEC:
        mfg_str = ZBEE_MFG_EMBERTEC
    elif mfg == ZBEE_MFG_CODE_IT_WATCHDOGS:
        mfg_str = ZBEE_MFG_IT_WATCHDOGS
    elif mfg == ZBEE_MFG_CODE_RELOC:
        mfg_str = ZBEE_MFG_RELOC
    elif mfg == ZBEE_MFG_CODE_INTEL:
        mfg_str = ZBEE_MFG_INTEL
    elif mfg == ZBEE_MFG_CODE_TREND:
        mfg_str = ZBEE_MFG_TREND
    elif mfg == ZBEE_MFG_CODE_MOXA:
        mfg_str = ZBEE_MFG_MOXA
    elif mfg == ZBEE_MFG_CODE_QEES:
        mfg_str = ZBEE_MFG_QEES
    elif mfg == ZBEE_MFG_CODE_SAYME:
        mfg_str = ZBEE_MFG_SAYME
    elif mfg == ZBEE_MFG_CODE_PENTAIR:
        mfg_str = ZBEE_MFG_PENTAIR
    elif mfg == ZBEE_MFG_CODE_ORBIT:
        mfg_str = ZBEE_MFG_ORBIT
    elif mfg == ZBEE_MFG_CODE_CALIFORNIA:
        mfg_str = ZBEE_MFG_CALIFORNIA
    elif mfg == ZBEE_MFG_CODE_COMCAST2:
        mfg_str = ZBEE_MFG_COMCAST2
    elif mfg == ZBEE_MFG_CODE_IDT:
        mfg_str = ZBEE_MFG_IDT
    elif mfg == ZBEE_MFG_CODE_PIXELA:
        mfg_str = ZBEE_MFG_PIXELA
    elif mfg == ZBEE_MFG_CODE_TIVO:
        mfg_str = ZBEE_MFG_TIVO
    elif mfg == ZBEE_MFG_CODE_FIDURE:
        mfg_str = ZBEE_MFG_FIDURE
    elif mfg == ZBEE_MFG_CODE_MARVELL:
        mfg_str = ZBEE_MFG_MARVELL
    elif mfg == ZBEE_MFG_CODE_WASION:
        mfg_str = ZBEE_MFG_WASION
    elif mfg == ZBEE_MFG_CODE_JASCO:
        mfg_str = ZBEE_MFG_JASCO
    elif mfg == ZBEE_MFG_CODE_SHENZHEN:
        mfg_str = ZBEE_MFG_SHENZHEN
    elif mfg == ZBEE_MFG_CODE_NETCOMM:
        mfg_str = ZBEE_MFG_NETCOMM
    elif mfg == ZBEE_MFG_CODE_DEFINE:
        mfg_str = ZBEE_MFG_DEFINE
    elif mfg == ZBEE_MFG_CODE_IN_HOME_DISP:
        mfg_str = ZBEE_MFG_IN_HOME_DISP
    elif mfg == ZBEE_MFG_CODE_MIELE:
        mfg_str = ZBEE_MFG_MIELE
    elif mfg == ZBEE_MFG_CODE_TELEVES:
        mfg_str = ZBEE_MFG_TELEVES
    elif mfg == ZBEE_MFG_CODE_LABELEC:
        mfg_str = ZBEE_MFG_LABELEC
    elif mfg == ZBEE_MFG_CODE_CHINA_ELEC:
        mfg_str = ZBEE_MFG_CHINA_ELEC
    elif mfg == ZBEE_MFG_CODE_VECTORFORM:
        mfg_str = ZBEE_MFG_VECTORFORM
    elif mfg == ZBEE_MFG_CODE_BUSCH_JAEGER:
        mfg_str = ZBEE_MFG_BUSCH_JAEGER
    elif mfg == ZBEE_MFG_CODE_REDPINE:
        mfg_str = ZBEE_MFG_REDPINE
    elif mfg == ZBEE_MFG_CODE_BRIDGES:
        mfg_str = ZBEE_MFG_BRIDGES
    elif mfg == ZBEE_MFG_CODE_SERCOMM:
        mfg_str = ZBEE_MFG_SERCOMM
    elif mfg == ZBEE_MFG_CODE_WSH:
        mfg_str = ZBEE_MFG_WSH
    elif mfg == ZBEE_MFG_CODE_BOSCH:
        mfg_str = ZBEE_MFG_BOSCH
    elif mfg == ZBEE_MFG_CODE_EZEX:
        mfg_str = ZBEE_MFG_EZEX
    elif mfg == ZBEE_MFG_CODE_DRESDEN:
        mfg_str = ZBEE_MFG_DRESDEN
    elif mfg == ZBEE_MFG_CODE_MEAZON:
        mfg_str = ZBEE_MFG_MEAZON
    elif mfg == ZBEE_MFG_CODE_CROW:
        mfg_str = ZBEE_MFG_CROW
    elif mfg == ZBEE_MFG_CODE_HARVARD:
        mfg_str = ZBEE_MFG_HARVARD
    elif mfg == ZBEE_MFG_CODE_ANDSON:
        mfg_str = ZBEE_MFG_ANDSON
    elif mfg == ZBEE_MFG_CODE_ADHOCO:
        mfg_str = ZBEE_MFG_ADHOCO
    elif mfg == ZBEE_MFG_CODE_WAXMAN:
        mfg_str = ZBEE_MFG_WAXMAN
    elif mfg == ZBEE_MFG_CODE_OWON:
        mfg_str = ZBEE_MFG_OWON
    elif mfg == ZBEE_MFG_CODE_HITRON:
        mfg_str = ZBEE_MFG_HITRON
    elif mfg == ZBEE_MFG_CODE_SCEMTEC:
        mfg_str = ZBEE_MFG_SCEMTEC
    elif mfg == ZBEE_MFG_CODE_WEBEE:
        mfg_str = ZBEE_MFG_WEBEE
    elif mfg == ZBEE_MFG_CODE_GRID2HOME:
        mfg_str = ZBEE_MFG_GRID2HOME
    elif mfg == ZBEE_MFG_CODE_TELINK:
        mfg_str = ZBEE_MFG_TELINK
    elif mfg == ZBEE_MFG_CODE_JASMINE:
        mfg_str = ZBEE_MFG_JASMINE
    elif mfg == ZBEE_MFG_CODE_BIDGELY:
        mfg_str = ZBEE_MFG_BIDGELY
    elif mfg == ZBEE_MFG_CODE_LUTRON:
        mfg_str = ZBEE_MFG_LUTRON
    elif mfg == ZBEE_MFG_CODE_IJENKO:
        mfg_str = ZBEE_MFG_IJENKO
    elif mfg == ZBEE_MFG_CODE_STARFIELD:
        mfg_str = ZBEE_MFG_STARFIELD
    elif mfg == ZBEE_MFG_CODE_TCP:
        mfg_str = ZBEE_MFG_TCP
    elif mfg == ZBEE_MFG_CODE_ROGERS:
        mfg_str = ZBEE_MFG_ROGERS
    elif mfg == ZBEE_MFG_CODE_CREE:
        mfg_str = ZBEE_MFG_CREE
    elif mfg == ZBEE_MFG_CODE_ROBERT_BOSCH:
        mfg_str = ZBEE_MFG_ROBERT_BOSCH
    elif mfg == ZBEE_MFG_CODE_IBIS:
        mfg_str = ZBEE_MFG_IBIS
    elif mfg == ZBEE_MFG_CODE_QUIRKY:
        mfg_str = ZBEE_MFG_QUIRKY
    elif mfg == ZBEE_MFG_CODE_EFERGY:
        mfg_str = ZBEE_MFG_EFERGY
    elif mfg == ZBEE_MFG_CODE_SMARTLABS:
        mfg_str = ZBEE_MFG_SMARTLABS
    elif mfg == ZBEE_MFG_CODE_EVERSPRING:
        mfg_str = ZBEE_MFG_EVERSPRING
    elif mfg == ZBEE_MFG_CODE_SWANN:
        mfg_str = ZBEE_MFG_SWANN
    elif mfg == ZBEE_MFG_CODE_BOSCH2:
        mfg_str = ZBEE_MFG_BOSCH2
    elif mfg == ZBEE_MFG_CODE_LEEDARSON:
        mfg_str = ZBEE_MFG_LEEDARSON
    else:
        mfg_str = "Unknown"
    return mfg_str

def zigbee_stack_str(ver):
    """Converts from a ZigBee Stack Version number to a string."""
    if ver == OTA_UPG_HDR_ZIGBEE_STACK_2006:
        ver_str = "2006"
    elif ver == OTA_UPG_HDR_ZIGBEE_STACK_2007:
        ver_str = "2007"
    elif ver == OTA_UPG_HDR_ZIGBEE_STACK_PRO:
        ver_str = "Pro"
    elif ver == OTA_UPG_HDR_ZIGBEE_STACK_IP:
        ver_str = "IP"
    else:
        ver_str = "Unknown"
    return ver_str

def security_credential_str(ver):
    """Converts from a Security Credential Version number to a string."""
    if ver == OTA_UPG_HDR_SEC_CRED_VER_SE_1_0:
        ver_str = "SE 1.0"
    elif ver == OTA_UPG_HDR_SEC_CRED_VER_SE_1_1:
        ver_str = "SE 1.1"
    elif ver == OTA_UPG_HDR_SEC_CRED_VER_SE_2_0:
        ver_str = "SE 2.0"
    else:
        ver_str = "Unknown"
    return ver_str

def tag_id_str(tag_id):
    """Converts from a Tag ID number to a string."""
    if tag_id == OTA_UPG_TAG_ID_UPG_IMG:
        id_str = "Upgrade Image"
    elif tag_id == OTA_UPG_TAG_ID_ECDSA_SIG:
        id_str = "ECDSA Signature"
    elif tag_id == OTA_UPG_TAG_ID_ECDSA_SIGN_CERT:
        id_str = "ECDSA Signing Certificate"
    elif (tag_id >= 0x0003) and (tag_id <= 0xefff):
        id_str = "Reserved"
    else:
        id_str = "Manufacturer Specific"
    return id_str

# Main function
def main():
    # Set-up options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:", ["help","file="])
    except getopt.GetoptError, e:
        sys.stderr.write(str(e))
        usage()
        sys.exit(1)

    # Default options
    filepath = None

    # Process options
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0) 
        elif o in ("-f", "--file"):
            filepath = a
        else:
            usage()
            sys.exit(1)

    if filepath is None:
        usage()
        sys.exit(1)

    # Open file
    with open(filepath, "rb") as myfile:
        # stat the file and squirrel away the size for later
        filestat = os.stat(filepath)
        filestat_size = filestat.st_size

        # Check for the OTA upgrade file identifier
        buf = myfile.read(4)
        (file_id, ) = struct.unpack("<I", buf)
        if file_id != OTA_UPG_FILE_ID:
            print "error: file identifier is incorrect (expected 0x%08x, got 0x%08x)" % (OTA_UPG_FILE_ID, file_id)
            sys.exit(1)
        print "OTA File Identifier: 0x%08x" % (file_id)

        # Pull in the header version and length fields
        buf = myfile.read(4)
        (hdr_ver, hdr_len) = struct.unpack("<HH", buf)
        print "OTA Header"
        print "\tVersion: 0x%04x" % (hdr_ver)
        if hdr_ver != OTA_UPG_HDR_VER:
            print "error: header version is unsupported (expected 0x%04x, got 0x%04x)" % (OTA_UPG_HDR_VER, hdr_ver)
            sys.exit(1)
        print "\tLength: 0x%04x (%u)" % (hdr_len, hdr_len)
        if hdr_len < OTA_UPG_HDR_MIN_HDR_LEN:
            print "error: header length is too smalled (minimum %u, got %u)" % (OTA_UPG_HDR_MIN_HDR_LEN, hdr_len)

        # Pull in the rest of the header and check it
        hdr_len = hdr_len - 8 # We've already processed 8 bytes of the header
        buf = myfile.read(hdr_len)
        (hdr_field_ctrl, hdr_mfg_code, hdr_img_type) = struct.unpack("<HHH", buf[0:6])
        buf = buf[6:]
        hdr_len = hdr_len - 6
        print "\tField Control: 0x%04x" % (hdr_field_ctrl)
        if hdr_field_ctrl & OTA_UPG_HDR_FIELD_CTRL_SECURITY_CREDENTIAL_VER:
            print "\t\tSecurity Credential Version Present"
        if hdr_field_ctrl & OTA_UPG_HDR_FIELD_CTRL_DEVICE_SPECIFIC:
            print "\t\tDevice Specific File"
        if hdr_field_ctrl & OTA_UPG_HDR_FIELD_CTRL_HARDWARE_VER:
            print "\t\tHardware Versions Present"
        if hdr_field_ctrl & ~OTA_UPG_HDR_FIELD_CTRL_MASK:
            print "error: unknown optional header fields (0x%04x)" % (hdr_field_ctrl & ~OTA_UPG_HDR_FIELD_CTRL_MASK)
            sys.exit(1)
        print "\tManufacturer Code: 0x%04x (%s)" % (hdr_mfg_code, mfg_code_str(hdr_mfg_code))
        print "\tImage Type: 0x%04x" % (hdr_img_type)
        (hdr_file_ver, hdr_zigbee_stack_ver) = struct.unpack("<IH", buf[0:6])
        buf = buf[6:]
        hdr_len = hdr_len - 6
        print "\tFile Version: 0x%08x" % (hdr_file_ver)
        print "\tZigBee Stack Version: 0x%04x (%s)" % (hdr_zigbee_stack_ver, zigbee_stack_str(hdr_zigbee_stack_ver))
        hdr_str = buf[0:32]
        buf = buf[32:]
        hdr_len = hdr_len - 32
        print "\tString: \"%s\"" % (hdr_str)
        (hdr_total_img_sz, ) = struct.unpack("<I", buf[0:4])
        buf = buf[4:]
        hdr_len = hdr_len - 4
        print "\tTotal Image Size: 0x%08x (%u)" % (hdr_total_img_sz, hdr_total_img_sz)
        if filestat_size != hdr_total_img_sz:
            print "error: file size doesn't match total image size in header (expected %u, got %u)" % (filestat_size, hdr_total_img_sz)
            #sys.exit(1)

        # Process any optional header fields
        if (hdr_len != 0) and (hdr_field_ctrl == 0):
            print "error: still header data left (%u bytes), but no optional elements" % (hdr_len)
            sys.exit(1)
        if (hdr_len == 0) and (hdr_field_ctrl != 0):
            print "error: no header data left, but optional element(s) present"
            sys.exit(1)
        if hdr_field_ctrl & OTA_UPG_HDR_FIELD_CTRL_SECURITY_CREDENTIAL_VER:
            if hdr_len >= 1:
                (hdr_sec_cred_ver, ) = struct.unpack("<B", buf[0:1])
                buf = buf[1:]
                hdr_len = hdr_len - 1
                print "\tSecurity Credential Version: 0x%02x (%s)" % (hdr_sec_cred_ver, security_credential_str(hdr_sec_cred_ver))
            else:
                print "error: insufficient header data for \"Security Credential Version\" (expected 1, got %u)" % (hdr_len)
                sys.exit(1)
        if hdr_field_ctrl & OTA_UPG_HDR_FIELD_CTRL_DEVICE_SPECIFIC:
            if hdr_len >= 8:
                (hdr_dev_spec, ) = struct.unpack("<Q", buf[0:8])
                buf = buf[8:]
                hdr_len = hdr_len - 8
                print "\tUpgrade File Destination: 0x%016x" % (hdr_dev_spec)
            else:
                print "error: insufficient header data for \"Upgrade File Destination\" (expected 8, got %u)" % (hdr_len)
                sys.exit(1)
        if hdr_field_ctrl & OTA_UPG_HDR_FIELD_CTRL_HARDWARE_VER:
            if hdr_len >= 4:
                (hdr_min_hw, hdr_max_hw) = struct.unpack("<HH", buf[0:4])
                buf = buf[4:]
                hdr_len = hdr_len - 4
                print "\tMinimum Hardware Version: 0x%04x" % (hdr_min_hw)
                print "\tMaximum Hardware Version: 0x%04x" % (hdr_max_hw)
            else:
                print "error: insufficient header data for \"Hardware Version\" (expected 4, got %u)" % (hdr_len)
                sys.exit(1)
        if hdr_len > 0:
            print "error: still header data left (%u bytes)" % (hdr_len)
            sys.exit(1)

        # Process sub-elements (Tag, Length, Value)
        while True:
            buf = myfile.read(6)
            if len(buf) == 6:
                (tag_id, sub_len) = struct.unpack("<HI", buf[0:6])
                print "Sub-element"
                print "\tTag ID: 0x%04x (%s)" % (tag_id, tag_id_str(tag_id))
                print "\tLength: 0x%08x (%u)" % (sub_len, sub_len)
                buf = myfile.read(sub_len)
                if len(buf) != sub_len:
                    print "error: insufficient data for sub-element (expected %u, got %u)" % (sub_len, len(buf))
                    sys.exit(1)
            else:
                break # EOF

if __name__ == "__main__":
    main()

