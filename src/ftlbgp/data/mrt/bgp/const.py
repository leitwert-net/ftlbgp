# -*- coding: utf-8 -*-
# pylint: disable=I0011,I0020,I0021,I0023
# pylint: disable=W0149,W0717,R0902,R0904,R0911,R0912,R0913,R0914,R0915,R1702,R1734,R1735,R2044,R6103,C0103,C0209,C2001
# pylint: enable=I0011
# flake8: noqa
""" ftlbgp
Copyright (C) 2014-2024 Leitwert GmbH

This software is distributed under the terms of the MIT license.
It can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Author Johann SCHLAMP <schlamp@leitwert.net>
"""

###################
# BGP SAFI VALUES #
###################

BGP_SAFI_RESERVED        = 0    # Defined in RFC4760
BGP_SAFI_UNICAST         = 1    # Defined in RFC4760
BGP_SAFI_MULTICAST       = 2    # Defined in RFC4760
BGP_SAFI_BOTH            = 3    # Deprecated in RFC4760
BGP_SAFI_MPLS            = 4    # Defined in RFC8277
BGP_SAFI_MCAST_VPN       = 5    # Defined in RFC6514
BGP_SAFI_PSEUDOWIRE      = 6    # Defined in RFC7267
BGP_SAFI_ENCAPSULATION   = 7    # Deprecated in RFC9012
BGP_SAFI_MCAST_VPLS      = 8    # Defined in RFC7117
BGP_SAFI_BGP_SFC         = 9    # Defined in RFC9015
BGP_SAFI_TUNNEL          = 64   # Proposed in draft_nalawade_kapoor_tunnel_safi
BGP_SAFI_VPLS            = 65   # Defined in RFC4761
BGP_SAFI_MDT             = 66   # Defined in RFC6037
BGP_SAFI_4OVER6          = 67   # Defined in RFC5747
BGP_SAFI_6OVER4          = 68   # Proposed by Yong Cui
BGP_SAFI_L1VPN           = 69   # Defined in RFC5195
BGP_SAFI_EVPN            = 70   # Defined in RFC7432
BGP_SAFI_LS              = 71   # Defined in RFC9552
BGP_SAFI_LS_VPN          = 72   # Defined in RFC9552
BGP_SAFI_SR_TE_POLICY    = 73   # Proposed in draft_ietf_idr_segment_routing_te_policy
BGP_SAFI_SD_WAN          = 74   # Proposed in draft_ietf_idr_sdwan_edge_discovery
BGP_SAFI_NG_POLICY       = 75   # Proposed in draft_ietf_idr_rpd
BGP_SAFI_CT              = 76   # Proposed in draft_ietf_idr_ct
BGP_SAFI_TUNNEL_FLOWSPEC = 77   # Proposed in draft_ietf_idr_flowspec_nvo3
BGP_SAFI_MCAST_TREE      = 78   # Proposed in draft_ietf_bess_multicast
BGP_SAFI_DPS             = 79   # Proposed by https://eos.arista.com/eos_4_26_2f/dps_vpn_scaling_using_bgp
BGP_SAFI_LSVR_SPF        = 80   # Proposed in draft_ietf_lsvr_spf
BGP_SAFI_CAR             = 83   # Proposed in draft_ietf_idr_car
BGP_SAFI_VPN_CAR         = 84   # Proposed in draft_ietf_idr_car
BGP_SAFI_MUP             = 85   # Proposed in draft_mpmz_bess_mup_safi
BGP_SAFI_L3VPN           = 128  # Defined in RFC4364
BGP_SAFI_L3VPN_MULTICAST = 129  # Defined in RFC6513
BGP_SAFI_ROUTE_TARGET    = 132  # Defined in RFC4684
BGP_SAFI_FLOWSPEC        = 133  # Defined in RFC8955
BGP_SAFI_L3VPN_FLOWSPEC  = 134  # Defined in RFC8955
BGP_SAFI_L3VPN_AUTO      = 140  # Proposed in draft_ietf_l3vpn_bgpvpn_auto
BGP_SAFI_RESERVED_255    = 255  # Defined in RFC4760

################
# BGP MESSAGES #
################

# BGP messages
BGP_BGP4MP_RESERVED      = 0  # Defined in RFC4271
BGP_BGP4MP_OPEN          = 1  # Defined in RFC4271
BGP_BGP4MP_UPDATE        = 2  # Defined in RFC4271
BGP_BGP4MP_NOTIFICATION  = 3  # Defined in RFC4271
BGP_BGP4MP_KEEPALIVE     = 4  # Defined in RFC4271
BGP_BGP4MP_ROUTE_REFRESH = 5  # Defined in RFC2918

##############
# BGP STATES #
##############

# BGP states
BGP_STATE_IDLE         = 1  # Defined in RFC6396
BGP_STATE_CONNECT      = 2  # Defined in RFC6396
BGP_STATE_ACTIVE       = 3  # Defined in RFC6396
BGP_STATE_OPEN_SENT    = 4  # Defined in RFC6396
BGP_STATE_OPEN_CONFIRM = 5  # Defined in RFC6396
BGP_STATE_ESTABLISHED  = 6  # Defined in RFC6396
BGP_STATE_CLEARING     = 7  # Quagga/FRR
BGP_STATE_DELETED      = 8  # Quagga/FRR

##############
# BGP PARAMS #
##############

# BGP parameters
BGP_PARAMS_RESERVED        = 0    # Defined in RFC5492
BGP_PARAMS_AUTHENTICATION  = 1    # Deprecated in RFC5492
BGP_PARAMS_CAPABILITIES    = 2    # Defined in RFC5492
BGP_PARAMS_EXTENDED_LENGTH = 255  # Defined in RFC9072

####################
# BGP CAPABILITIES #
####################

# BGP capabilities
BGP_CAPABILITY_RESERVED_0                 = 0    # Defined in RFC5492
BGP_CAPABILITY_BGP4MP                     = 1    # Defined in RFC2858
BGP_CAPABILITY_ROUTE_REFRESH              = 2    # Defined in RFC2918
BGP_CAPABILITY_OUTBOUND_FILTER            = 3    # Defined in RFC5291
BGP_CAPABILITY_MULTIPLE_ROUTES            = 4    # Deprecated in RFC8277
BGP_CAPABILITY_EXTENDED_NEXT_HOP          = 5    # Defined in RFC8950
BGP_CAPABILITY_BGP4MP_ET                  = 6    # Defined in RFC8654
BGP_CAPABILITY_BGPSEC                     = 7    # Defined in RFC8205
BGP_CAPABILITY_MULTIPLE_LABELS            = 8    # Defined in RFC8277
BGP_CAPABILITY_BGP_ROLE                   = 9    # Defined in RFC9234
BGP_CAPABILITY_GRACEFUL_RESTART           = 64   # Defined in RFC4724
BGP_CAPABILITY_AS4                        = 65   # Defined in RFC6793
BGP_CAPABILITY_UNKNOWN_66                 = 66   # Deprecated on 2003-03-06
BGP_CAPABILITY_DYNAMIC                    = 67   # Proposed in draft-ietf-idr-dynamic-cap
BGP_CAPABILITY_MULTISESSION               = 68   # Proposed in draft-ietf-idr-bgp-multisession
BGP_CAPABILITY_ADDPATH                    = 69   # Defined in RFC7911
BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH     = 70   # Defined in RFC7313
BGP_CAPABILITY_LLGR                       = 71   # Proposed in draft-ietf-idr-long-lived-gr
BGP_CAPABILITY_POLICY_DISTRIBUTION        = 72   # Proposed in draft-ietf-idr-rpd-04
BGP_CAPABILITY_FQDN                       = 73   # Proposed in draft-walton-bgp-hostname-capability
BGP_CAPABILITY_BFD                        = 74   # Proposed in draft-ietf-idr-bgp-bfd-strict-mode
BGP_CAPABILITY_SOFTWARE_VERSION           = 75   # Proposed in draft-abraitis-bgp-version-capability
BGP_CAPABILITY_PRESTD_ROUTE_REFRESH       = 128  # Deprecated in RFC8810
BGP_CAPABILITY_PRESTD_POLICY_DISTRIBUTION = 129  # Deprecated in RFC8810
BGP_CAPABILITY_PRESTD_OUTBOUND_FILTER     = 130  # Deprecated in RFC8810
BGP_CAPABILITY_PRESTD_MULTISESSION        = 131  # Deprecated in RFC8810
BGP_CAPABILITY_PRESTD_FQDN                = 184  # Deprecated in RFC8810
BGP_CAPABILITY_PRESTD_OPERATIONAL         = 185  # Deprecated in RFC8810
BGP_CAPABILITY_RESERVED_255               = 255  # Defined in RFC8810

##############
# BGP ERRORS #
##############

# BGP error codes
BGP_ERROR_RESERVED           = 0  # Defined in RFC4271
BGP_ERROR_MESSAGE_HEADER     = 1  # Defined in RFC4271
BGP_ERROR_OPEN_MESSAGE       = 2  # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE     = 3  # Defined in RFC4271
BGP_ERROR_HOLD_TIMER_EXPIRED = 4  # Defined in RFC4271
BGP_ERROR_FSM                = 5  # Defined in RFC4271
BGP_ERROR_CEASE              = 6  # Defined in RFC4271
BGP_ERROR_ROUTE_REFRESH      = 7  # Defined in RFC7313

# BGP message header error subcodes
BGP_ERROR_MESSAGE_HEADER_UNSPECIFIC                  = 0  # Defined in RFC4493
BGP_ERROR_MESSAGE_HEADER_CONNECTION_NOT_SYNCHRONIZED = 1  # Defined in RFC4271
BGP_ERROR_MESSAGE_HEADER_BAD_MESSAGE_LENGTH          = 2  # Defined in RFC4271
BGP_ERROR_MESSAGE_HEADER_BAD_MESSAGE_TYPE            = 3  # Defined in RFC4271

# BGP OPEN message error subcodes
BGP_ERROR_OPEN_MESSAGE_UNSPECIFIC                     = 0   # Defined in RFC4493
BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_VERSION_NUMBER     = 1   # Defined in RFC4271
BGP_ERROR_OPEN_MESSAGE_BAD_PEER_AS                    = 2   # Defined in RFC4271
BGP_ERROR_OPEN_MESSAGE_BAD_BGP_IDENTIFIER             = 3   # Defined in RFC4271
BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_OPTIONAL_PARAMETER = 4   # Defined in RFC4271
BGP_ERROR_OPEN_MESSAGE_AUTHENTICATION_FAILURE         = 5   # Deprecated in RFC4271
BGP_ERROR_OPEN_MESSAGE_UNACCEPTABLE_HOLD_TIME         = 6   # Defined in RFC4271
BGP_ERROR_OPEN_MESSAGE_UNSUPPORTED_CAPABILITY         = 7   # Defined in RFC5492
BGP_ERROR_OPEN_MESSAGE_DEPRECATED_8                   = 8   # Deprecated in RFC9234
BGP_ERROR_OPEN_MESSAGE_DEPRECATED_9                   = 9   # Deprecated in RFC9234
BGP_ERROR_OPEN_MESSAGE_DEPRECATED_10                  = 10  # Deprecated in RFC9234
BGP_ERROR_OPEN_MESSAGE_ROLE_MISMATCH                  = 11  # Defined in RFC9234

# BGP UPDATE message error subcodes
BGP_ERROR_UPDATE_MESSAGE_UNSPECIFIC                       = 0   # Defined in RFC4493
BGP_ERROR_UPDATE_MESSAGE_MALFORMED_ATTRIBUTE_LIST         = 1   # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_UNRECOGNIZED_WELLKNOWN_ATTRIBUTE = 2   # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_MISSING_WELLKNOWN_ATTRIBUTE      = 3   # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_INVALID_ATTRIBUTE_FLAGS          = 4   # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_INVALID_ATTRIBUTE_LENGTH         = 5   # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_INVALID_ORIGIN_ATTRIBUTE         = 6   # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_AS_ROUTING_LOOP                  = 7   # Deprecated in RFC4271
BGP_ERROR_UPDATE_MESSAGE_INVALID_NEXTHOP_ATTRIBUTE        = 8   # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_INVALID_OPTIONAL_ATTRIBUTE       = 9   # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_INVALID_NETWORK_FIELD            = 10  # Defined in RFC4271
BGP_ERROR_UPDATE_MESSAGE_MALFORMED_AS_PATH                = 11  # Defined in RFC4271

# BGP finite state machine error subcodes
BGP_ERROR_FSM_UNSPECIFIED                              = 0  # Defined in RFC6608
BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_OPEN_SENT_STATE    = 1  # Defined in RFC6608
BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_OPEN_CONFIRM_STATE = 2  # Defined in RFC6608
BGP_ERROR_FSM_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE  = 3  # Defined in RFC6608

# BGP cease error subcodes
BGP_ERROR_CEASE_RESERVED                        = 0   # Defined in RFC4486
BGP_ERROR_CEASE_MAX_NUMBER_PREFIXES_REACHED     = 1   # Defined in RFC4486
BGP_ERROR_CEASE_ADMINISTRATIVE_SHUTDOWN         = 2   # Defined in RFC9003
BGP_ERROR_CEASE_PEER_DECONFIGURED               = 3   # Defined in RFC4486
BGP_ERROR_CEASE_ADMINISTRATIVE_RESET            = 4   # Defined in RFC9003
BGP_ERROR_CEASE_CONNECTION_REJECTED             = 5   # Defined in RFC4486
BGP_ERROR_CEASE_OTHER_CONFIGURATION_CHANGE      = 6   # Defined in RFC4486
BGP_ERROR_CEASE_CONNECTION_COLLISION_RESOLUTION = 7   # Defined in RFC4486
BGP_ERROR_CEASE_OUT_OF_RESOURCES                = 8   # Defined in RFC4486
BGP_ERROR_CEASE_HARD_RESET                      = 9   # Defined in RFC8538
BGP_ERROR_CEASE_BFD_DOWN                        = 10  # Defined in RFC9384

# BGP route refresh error subcodes
BGP_ERROR_ROUTE_REFRESH_RESERVED               = 0  # Defined in RFC7313
BGP_ERROR_ROUTE_REFRESH_INVALID_MESSAGE_LENGTH = 1  # Defined in RFC7313

#######################
# BGP PATH ATTRIBUTES #
#######################

# BGP path attribute types
BGP_PATH_ATTR_RESERVED                  = 0    # Defined in RFC4271
BGP_PATH_ATTR_ORIGIN                    = 1    # Defined in RFC4271
BGP_PATH_ATTR_AS_PATH                   = 2    # Defined in RFC4271
BGP_PATH_ATTR_NEXT_HOP                  = 3    # Defined in RFC4271
BGP_PATH_ATTR_MULTI_EXIT_DISC           = 4    # Defined in RFC4271
BGP_PATH_ATTR_LOCAL_PREF                = 5    # Defined in RFC4271
BGP_PATH_ATTR_ATOMIC_AGGREGATE          = 6    # Defined in RFC4271
BGP_PATH_ATTR_AGGREGATOR                = 7    # Defined in RFC4271
BGP_PATH_ATTR_COMMUNITIES               = 8    # Defined in RFC1997
BGP_PATH_ATTR_ORIGINATOR_ID             = 9    # Defined in RFC4456
BGP_PATH_ATTR_CLUSTER_LIST              = 10   # Defined in RFC4456
BGP_PATH_ATTR_DPA                       = 11   # Deprecated in RFC6938
BGP_PATH_ATTR_ADVERTISER                = 12   # Deprecated in RFC6938
BGP_PATH_ATTR_RCID_CLUSTER_ID           = 13   # Deprecated in RFC6938
BGP_PATH_ATTR_MP_REACH_NLRI             = 14   # Defined in RFC4760
BGP_PATH_ATTR_MP_UNREACH_NLRI           = 15   # Defined in RFC4760
BGP_PATH_ATTR_EXTENDED_COMMUNITIES      = 16   # Defined in RFC4360
BGP_PATH_ATTR_AS4_PATH                  = 17   # Defined in RFC6793
BGP_PATH_ATTR_AS4_AGGREGATOR            = 18   # Defined in RFC6793
BGP_PATH_ATTR_SAFI_SPECIFIC             = 19   # Proposed in draft-kapoor-nalawade-idr-bgp-ssa
BGP_PATH_ATTR_CONNECTOR                 = 20   # Deprecated in RFC6037
BGP_PATH_ATTR_AS_PATHLIMIT              = 21   # Proposed in draft-ietf-idr-as-pathlimit
BGP_PATH_ATTR_PMSI_TUNNEL               = 22   # Defined in RFC6514
BGP_PATH_ATTR_TUNNEL_ENCAPSULATION      = 23   # Defined in RFC5512
BGP_PATH_ATTR_TRAFFIC_ENGINEERING       = 24   # Defined in RFC5543
BGP_PATH_ATTR_IPV6_EXTENDED_COMMUNITIES = 25   # Defined in RFC5701
BGP_PATH_ATTR_AIGP                      = 26   # Defined in RFC7311
BGP_PATH_ATTR_PE_DISTINGUISHER_LABELS   = 27   # Defined in RFC6514
BGP_PATH_ATTR_ENTROPY_LABEL_CAPABILITY  = 28   # Deprecated in RFC7447
BGP_PATH_ATTR_LS                        = 29   # Defined in RFC7752
BGP_PATH_ATTR_VENDOR_30                 = 30   # Deprecated in RFC8093
BGP_PATH_ATTR_VENDOR_31                 = 31   # Deprecated in RFC8093
BGP_PATH_ATTR_LARGE_COMMUNITIES         = 32   # Defined in RFC8092
BGP_PATH_ATTR_BGPSEC_PATH               = 33   # Defined in RFC8205
BGP_PATH_ATTR_COMMUNITY_CONTAINER       = 34   # Proposed in draft-ietf-idr-wide-bgp-communities
BGP_PATH_ATTR_ONLY_TO_CUSTOMER          = 35   # Proposed in draft-ietf-idr-bgp-open-policy
BGP_PATH_ATTR_DOMAIN_PATH               = 36   # Proposed in draft-ietf-bess-evpn-ipvpn-interworking
BGP_PATH_ATTR_SFP                       = 37   # Defined in RFC9015
BGP_PATH_ATTR_BFD_DISCRIMINATOR         = 38   # Defined in RFC9026
BGP_PATH_ATTR_NHC_TMP                   = 39   # Proposed in draft-ietf-idr-entropy-label
BGP_PATH_ATTR_PREFIX_SID                = 40   # Defined in RFC8669
BGP_PATH_ATTR_ATTR_SET                  = 128  # Defined in RFC6368
BGP_PATH_ATTR_VENDOR_129                = 129  # Deprecated in RFC8093
BGP_PATH_ATTR_VENDOR_241                = 241  # Deprecated in RFC8093
BGP_PATH_ATTR_VENDOR_242                = 242  # Deprecated in RFC8093
BGP_PATH_ATTR_VENDOR_243                = 243  # Deprecated in RFC8093
BGP_PATH_ATTR_RESERVED_FOR_DEV          = 255  # Defined in RFC2042

# AS path segment types
BGP_PATH_ATTR_AS_PATH_SEGMENT_SET             = 1  # Defined in RFC4271
BGP_PATH_ATTR_AS_PATH_SEGMENT_SEQUENCE        = 2  # Defined in RFC4271
BGP_PATH_ATTR_AS_PATH_SEGMENT_CONFED_SEQUENCE = 3  # Defined in RFC5065
BGP_PATH_ATTR_AS_PATH_SEGMENT_CONFED_SET      = 4  # Defined in RFC5065

# AS4 path transition
BGP_PATH_ATTR_AS4_PATH_AS_TRANS = 23456  # Defined in RFC6793

# Origin types
BGP_PATH_ATTR_ORIGIN_IGP        = 0  # Defined in RFC4271
BGP_PATH_ATTR_ORIGIN_EGP        = 1  # Defined in RFC4271
BGP_PATH_ATTR_ORIGIN_INCOMPLETE = 2  # Defined in RFC4271
