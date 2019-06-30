## This script will get a list of IP addresses and give you the country code of the IP addresses.  Great for sifting through a bunch of logs


#!/usr/bin/env bash
cat /Users/%YOURUSER-OR-OTHER-PATH%/Desktop/source.txt | awk '{print $1}' > ips.txt
uniq ips.txt > uniqips.txt
IPS=`cat uniqips.txt`
for i in $IPS
do
  echo "$i,`geoiplookup $i | cut -d "," -f2 | sed -e 's/^[\t]//'`" >> ipinfo.csv
done



# ##NOTE: You need 
# ##
# ##git clone https://github.com/maxmind/geoip-api-c.git cd geoip-api-c/ autoreconf -ivf ./configure make sudo make install
# ##
# ##cd /tmp/
# ##curl -O http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
# ##curl -O http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
# ##curl -O http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
# ##curl -O http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
# ##curl -O http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
# ##curl -O http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz
# ##
# ##find . -name "Geo*.gz"| xargs -I {} gunzip {}
# ##
# ##you may need to create the folder manually @ /usr/local/share/GeoIP/
# ##
# ##mv GeoLiteCityv6.dat GeoIPCityv6.dat
# ##mv GeoLiteCity.dat GeoIPCity.dat sudo
# ##mv Geo*.dat /usr/local/share/GeoIP/