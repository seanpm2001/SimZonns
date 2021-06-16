
***

# SimZonns draft 1B

An open source SIM card implementation because SIM cards are too proprietary and difficult (I have been suffering with a failing S20 FE 5G and I am prompted to solve the problem with this project)

## Names and pronunciations

SimZon - Taken

SimZonns (pronunciation: Sim Zawns, or Simpsons (unoffficial))

### Legacy mode 

Legacy mode (for the current SIM card structures) {

### Emulation

Verizon (vz-vm)

Sprint (spr-vm)

T-mobile (tmo-vm)

### Network modes

GLOBAL

LTE/CDMA

LTE/GSM/UMTS

### Tethering

Tethering protection: disabled by default (as tethering is OK and shouldn't be mandatorially disallowed)

### ICCID

#### Issuer Identifier Number

standard: max=7 digits
  
Major industry identifier (MII), 2 fixed digits, 89 for telecommunication purposes.

Country code, 2 or 3 digits, as defined by ITU-T recommendation E.164.

NANP countries, apart from Canada, use 01, i.e. prepending a zero to their common calling code +1

Canada uses 302

Russia uses 701, i.e. appending 01 to its calling code +7

Kazakhstan uses 997, even though it shares the calling code +7 with Russia

Issuer identifier, 1–4 digits.

Often identical to the mobile network code (MNC).


### Encryption

Encryption: 128 bit    
      
}

## ZSIM 

ZSIM mode (an experimental branch that fixes shortcomings with the strutures of SIM cards) {
	
  // I have noted many flaws with the structure of SIM cards and I am going to attempt to try and improve them for a better open source standard and for future proofing.
  
### Encryption
 
  Encryption: 128, 256, or 512 bit (default is 256 bit)
	
### Area codes

  Area code:

#### Galaxies

  Galaxies: (2-64 digit code)
	
  MilyWay - Milky Way (MW:)
	
#### Planets

  Planets: (2-32 digit code)
	
  EarthPrime - Earth (MW:EARTH_PRIME)
	
  Mars - Mars (MW:MARS)
	
##### Continents (Earth)

  Continent: (6 digit code)
	
  NOR_AM - North America (MW:EARTH_PRIME/NOR_AM)
	
  SOU_AM - North America (MW:EARTH_PRIME/SOU_AM)
	
  EUR_OP - Europe (MW:EARTH_PRIME/EUR_OP)
	
  A_SIA0 - Asia (MW:EARTH_PRIME/A-SIA0)
	
  OCE-NA - Oceania (MW:EARTH_PRIME/OCE-NA)
	
  AFR_CA - Africa (MW:EARTH_PRIME/AFR_CA)
	
  ANT_AR - Antarctica (MW:EARTH_PRIME/ANT_AR)
	
  Alternatively, you can just name the continent, it just isn't as neat
	
  NorthAmerica (MW:EARTH_PRIME/NORTH_AMERICA)
	
  SouthAmerica (MW:EARTH_PRIME/SOUTH_AMERICA)
	
  Europe (MW:EARTH_PRIME/EUROPE)
	
  Asia (MW:EARTH_PRIME/ASIA)
	
  Oceania (MW:EARTH_PRIME/OCEANIA)
	
  Africa (MW:EARTH_PRIME/AFRICA)
	
  Antarctica (MW:EARTH_PRIME/ANTARCTICA)
	
##### Countries (Earth)

  Country: (2-16 digit code)	
  
###### North America

  NOR_AM {
	
  USOA - United States of America (MW:EARTH_PRIME/NOR_AM/USOA)
	
  CAN - Canada (MW:EARTH_PRIME/NOR_AM/CAN)
	
  Other/unlisted
	
  }

###### South America

  SOU_AM {
	
  ARG - Argentina (MW:EARTH_PRIME/SOU_AM/ARG)
  
  BOL - Bolivia (MW:EARTH_PRIME/SOU_AM/BOL)
	
  BRA - Brazil (MW:EARTH_PRIME/SOU_AM/BRA)
  
  CHL - Chili (MW:EARTH_PRIME/SOU_AM/CHL)
	
  COL - Columbia (MW:EARTH_PRIME/SOU_AM/COL)
  
  ECU - Ecuador (MW:EARTH_PRIME/SOU_AM/ECU)
	
  GUY - Guyana (MW:EARTH_PRIME/SOU_AM/GUY)
	
  PRY - Paraguay (MW:EARTH_PRIME/SOU_AM/PRY)
	
  PER - Peru (MW:EARTH_PRIME/SOU_AM/PER)
	
  SUR - Suriname (MW:EARTH_PRIME/SOU_AM/SUR)
	
  URY - Uruguay (MW:EARTH_PRIME/SOU_AM/URY)
	
  VEN - Venezuela (MW:EARTH_PRIME/SOU_AM/VEN)
	
  Other/unlisted
	
  }
	
###### Europe

  EUR_OP {
	
  I don't have the time to continue naming right now
	
  Other/unlisted
	
  }
	
###### Asia

  A_SIA0 {
	
  I don't have the time to continue naming right now
	
  Other/unlisted
	
  }
  
###### Oceania

  OCE-NA {
	
  I don't have the time to continue naming right now
	
  Other/unlisted
	
  }
	
###### Africa

  AFR_CA {
	
  I don't have the time to continue naming right now
	
  Other/unlisted
	
  }
	
###### Antarctica

  ANT_AR {
  
  I don't have the time to continue naming right now
	
  Other/unlisted
	
  }
  
###### Identifier numbers

Identifier numbers are encrypted. I am not sure how to set them up at the moment.

}

## Extra:

### What happened to draft 1A?

It isn't being released to this repository, as it contains a rant that seemed a bit unprofessional and not in the scope of my main projects guidelines. It also had some copyright issues that were kind of stupid related to 20th century Fox. I have been low energy today, and I kept the old draft. I am still trying to figure out where and how I will release it. Draft 1B is much more refined.
  
***
