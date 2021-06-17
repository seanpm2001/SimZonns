# API and realization of GSM 03.48 / ETSI TS 102 225 / ETSI TS 131 115 / 3GPP TS 31.115 standard for Java

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.opentelecoms.gsm0348/gsm0348/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.opentelecoms.gsm0348/gsm0348)

## Scope
The project provides API and realization of the Secured Packets. It can use different formats, used for different transport protocols.
The transport Short Message Service Point-to-Point (SMS-PP) is the mainly used, but it also supports SMS-CN, CAT_TP, TCP/IP and USSD.
It is used to the exchange of secured packets between an entity in a GSM/UMTS/LTE PLMN and an entity in the SIM/UICC.
Secured Packets contain application messages to which certain mechanisms according to GSM 03.48 / ETSI 102 225 have been applied.
Application messages are commands or data exchanged between an application resident in or behind the GSM/3G/4G PLMN and on the SIM/UICC.

## History
The project was originally developed by Victor Platov. Initially the code was hosted on Google Code (https://code.google.com/archive/p/gsm0348/).
After Google shutdown Google Code, the code was moved to GitHub (https://github.com/TapuGithub/gsm0348).
Finally, the code was adopted by the Open Telecoms project.

## News

0. Fixed bug in the ciphered MAC implementations (DESMACISO9797M1) when the data size was a multiple of 8.
0. Fixed bug in CardProfileCoder for AES. Use AES_CMAC_64 as default signature algorithm for AES.
0. Use NoPadding ciphers to retrieve padding data when data or signature ends with zeros.
0. Replaced the SecurityBytesType with TransportProtocol enum to support the different formats.
0. Added the proprietary XOR4 and XOR8 signing algorithms.
0. Using the SMS implementation, use the SecurityBytesType.WITH_LENGTHS.
0. Minimum Java is now 1.7, rewrite using ByteBuffer. The goal is to fully support ETSI TS 102 225, ETSI TS 131 115, and 3GPP TS 31.115.
0. Added AES ciphering and RC signatures, including proprietary implementation XOR4 and XOR8.
0. Moved to the Open Telecoms GitHub and published in Maven Central repository.
0. TODO: TCP/IP identification packet and digital signatures.

## System Overview

The Sending Application prepares an Application Message and forwards it to the Sending Entity, with an indication of the security to be applied to the message. The Sending Entity prepends a Security Header (the Command Header) to the Application Message. It then applies the requested security to part of the Command Header and all of the Application Message, including any padding octets. The resulting structure is here referred to as the (Secured) Command Packet.

Under normal circumstances the Receiving Entity receives the Command Packet and unpacks it according to the security parameters indicated in the Command Header.
The Receiving Entity subsequently forwards the Application Message to the Receiving Application indicating to the Receiving Application the security that was applied.
The interface between the Sending Application and Sending Entity and the interface between the Receiving Entity and Receiving Application are proprietary.

If so indicated in the Command Header, the Receiving Entity shall create a (Secured) Response Packet.
The Response Packet consists of a Security Header (the Response Header) and optionally, application specific data supplied by the Receiving Application.
Both the Response Header and the application specific data are secured using the security mechanisms indicated in the received Command Packet.
The Response Packet will be returned to the Sending Entity, subject to constraints in the transport layer, (e.g. timing).

![System overview](/resources/system-overview.png?raw=true "System overview")

### The project
This project designed to help building an Receiving/Sending Entity.
It provides a library for construction of Secured Packets with all required security procedures - signing and ciphering, padding, redundancy checking and etc.

### Capability
Short Message Service Point-to-Point (SMS-PP), Cell Broadcast (SMS-CB), USSD, CAT_TP and TCP/IP (HTTPS) are supported, except for the identification packer for TCP/IP.

### Links
* [ETSI TS 102 225 v16.0.0](https://www.etsi.org/deliver/etsi_ts/102200_102299/102225/16.00.00_60/ts_102225v160000p.pdf)
* [ETSI TS 102 225 v13.0.0](https://www.etsi.org/deliver/etsi_ts/102200_102299/102225/13.00.00_60/ts_102225v130000p.pdf)
* [ETSI TS 131 115 v12.1.0](https://www.etsi.org/deliver/etsi_ts/131100_131199/131115/12.01.00_60/ts_131115v120100p.pdf)
* [3GPP TS 31.115](https://www.3gpp.org/DynaReport/31115.htm)

### Maven Config
```
<dependencies>
   <dependency>
      <groupId>org.opentelecoms.gsm0348</groupId>
      <artifactId>gsm0348-api</artifactId>
      <version>1.3.2</version>
   </dependency>
   <dependency>
      <groupId>org.opentelecoms.gsm0348</groupId>
      <artifactId>gsm0348-impl</artifactId>
      <version>1.3.2</version>
   </dependency>
</dependencies>
```

### Maven Central Release
For a snapshot:
```
mvn clean deploy
```
For a proper release:
```
mvn versions:set -DnewVersion=1.3.3
git commit -a -m "Set version to release 1.3.3"
git push origin
git tag -a 1.3.3 -m "1.3.3"
git push --tags origin
mvn clean deploy -P release
mvn nexus-staging:release
mvn versions:set -DnewVersion=1.3.4-SNAPSHOT
git commit -a -m "Set version to 1.3.4-SNAPSHOT"

# Or when something went wrong
mvn nexus-staging:drop
```