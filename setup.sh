#! /bin/bash

export ARTEX_PATH=/opt/ProjectArtex
#export ARTEX_PATH=/home/$USER/ProjectArtex

sudo apt update

sudo apt-get install python-dev
sudo apt-get install python3-dev

sudo apt-get install python-pip 
sudo apt-get install python3-pip
sudo apt-get install python3-setuptools
sudo apt-get install vlc
sudo apt-get install flac

sudo apt-get install portaudio19-dev python-all-dev python3-all-dev

sudo apt-get install libatlas-base-dev

sudo apt-get install python-pyaudio python3-pyaudio sox

# install prerequisite 
sudo apt-get install libpcre3-dev

ln -s /usr/lib/arm-linux-gnueabihf/libfreetype.so.6 /usr/lib/
ln -s /usr/lib/arm-linux-gnueabihf/libjpeg.so.8 /usr/lib/
ln -s /usr/lib/arm-linux-gnueabihf/libz.so /usr/lib/

sudo apt-get install libjpeg-dev

sudo pip install --upgrade pip
sudo pip3 install --upgrade pip

sudo pip install -r requirements.txt
sudo pip3 install -r requirements.txt

sudo -H pip3 install --ignore-installed pyaudio

pip install --no-cache-dir -I pillow
pip3 install --no-cache-dir -I pillow

# http://weegreenblobbie.com/?p=263
# download swig 3.0.12
wget -O "swig-3.0.12.tar.gz" "https://downloads.sourceforge.net/project/swig/swig/swig-3.0.12/swig-3.0.12.tar.gz?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fswig%2Ffiles%2Fswig%2Fswig-3.0.12%2Fswig-3.0.12.tar.gz%2Fdownload&ts=1486782132&use_mirror=superb-sea2" --no-check-certificate

# extract and configure
tar xf swig-3.0.12.tar.gz

# delete tar.gz file
rm swig-3.0.12.tar.gz

cd swig-3.0.12/

./configure --prefix=/usr

# build
make -j 4

# install
make install

# check version
swig -version
#SWIG Version 3.0.12

cd ..

git clone https://github.com/Kitt-AI/snowboy.git

cd snowboy/swig/Python3
make
cp _snowboydetect.so $ARTEX_PATH
cp snowboydetect.py $ARTEX_PATH

cd ../..
cd examples/Python3/
cp snowboydecoder.py $ARTEX_PATH

cd ../..
cp -r resources $ARTEX_PATH

cd ..

# duzgun calismasini etkileyen snowbodecoder.py icerisindeki
# from . import kisimi import kismi olarak duzeltiyor.
sudo sed -i 's/from . //g' snowboydecoder.py

# OrangePi uzerinde GPIO pinlerini kontrol etmek icin kullanılacak kutuphane
git clone https://github.com/muminkoykiran/orangepi_PC_gpio_pyH3.git
python orangepi_PC_gpio_pyH3/setup.py install

cd orangepi_PC_gpio_pyH3/examples/RgbLed
cp rgbControlClass.py $ARTEX_PATH
cd ../../..

#apt-get install libasound2-dev memcached python-pip python-alsaaudio vlc

sudo chmod +x $ARTEX_PATH/Artex

cp $ARTEX_PATH/resources/Artex.service /etc/systemd/system/
mkdir -p /etc/systemd/system/Artex.service.d/
cp $ARTEX_PATH/resources/usergroup-root.conf /etc/systemd/system/Artex.service.d/
systemctl daemon-reload
systemctl enable Artex.service

touch /var/log/artex.log

echo "OrangePi Pinleri Kullanilsin mi?:"
read UsePins
echo UsePins = \"$UsePins\" >> creds.py

echo "Kullanici Adinizi Girin:"
read Username
echo Username = \"$Username\" >> creds.py

echo "Parolanizi Girin:"
read Password
echo Password = \"$Password\" >> creds.py

echo "Domaini Girin:"
read BaseUrl
echo BaseUrl = \"$BaseUrl\" >> creds.py

echo "Salt:"
read Salt
echo Salt = \"$Salt\" >> creds.py


# My shell variable 
f=$BaseUrl
 
## Remove protocol part of url  ##
f="${f#http://}"
f="${f#https://}"
f="${f#ftp://}"
f="${f#scp://}"
f="${f#scp://}"
f="${f#sftp://}"
 
## Remove username and/or username:password part of URL  ##
f="${f#*:*@}"
f="${f#*@}"
 
## Remove rest of urls ##
f=${f%%/*}
 
## Show domain name only ##
echo "$f"

echo | openssl s_client -servername $f -connect $f:443 |\
  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > certificate.crt


echo "Yeniden baslatabilirsiniz."
