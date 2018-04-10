#! /bin/bash

export ARTEX_PATH=/home/$USER/ProjectArtex
#export ARTEX_PATH=/home/$USER/Desktop/ProjectArtex

sudo apt-get install python-dev
sudo apt-get install python3-dev

sudo apt-get install python-pip 
sudo apt-get install python3-pip
sudo apt-get install vlc

sudo pip install -r requirements.txt
sudo pip3 install -r requirements.txt

sudo apt-get install portaudio19-dev python-all-dev python3-all-dev

sudo apt-get install libatlas-base-dev

#apt-get install swig3.0 python-pyaudio python3-pyaudio sox

# install prerequisite 
sudo apt-get install libpcre3-dev

# http://weegreenblobbie.com/?p=263
# download swig 3.0.12
wget -O "swig-3.0.12.tar.gz" "https://downloads.sourceforge.net/project/swig/swig/swig-3.0.12/swig-3.0.12.tar.gz?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fswig%2Ffiles%2Fswig%2Fswig-3.0.12%2Fswig-3.0.12.tar.gz%2Fdownload&ts=1486782132&use_mirror=superb-sea2"

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

#apt-get install libasound2-dev memcached python-pip python-alsaaudio vlc -y
#cp initd_artex.sh /etc/init.d/ArtexPi
#update-rc.d ArtexPi defaults
#touch /var/log/artex.log

echo "OrangePi Pinleri Kullanilsin mi?:"
read UsePins
echo UsePins = \"$UsePins\" >> creds.py

echo "Kullanici Adinizi Girin:"
read KullaniciAdi
echo KullaniciAdi = \"$KullaniciAdi\" >> creds.py

echo "Sifrenizi Girin:"
read Sifre
echo Sifre = \"$Sifre\" >> creds.py

echo "Domaini Girin:"
read Domain
echo Domain = \"$Domain\" >> creds.py

echo "Salt:"
read Salt
echo Salt = \"$Salt\" >> creds.py


echo "Yeniden baslatabilirsiniz."
