#! /bin/bash

apt-get update

apt-get install python-dev
apt-get install python3-dev

apt-get install python-pip 
apt-get install python3-pip

pip install -r requirements.txt

#pip2 install setuptools
#pip3 install setuptools

#pip2 install wheel
#pip3 install wheel

#pip2 install PyCrypto
#pip3 install PyCrypto

#pip3 install SpeechRecognition

apt-get install portaudio19-dev python-all-dev python3-all-dev

#pip3 install pyaudio
#pip install pyaudio

apt-get install libatlas-base-dev

#apt-get install swig3.0 python-pyaudio python3-pyaudio sox

# install prerequisite 
apt-get install libpcre3-dev

# http://weegreenblobbie.com/?p=263

# download swig 3.0.12
wget -O swig-3.0.12.tar.gz https://downloads.sourceforge.net/project/swig/swig/swig-3.0.12/swig-3.0.12.tar.gz?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fswig%2Ffiles%2Fswig%2Fswig-3.0.12%2Fswig-3.0.12.tar.gz%2Fdownload&ts=1486782132&use_mirror=superb-sea2

# extract and configure
tar xf swig-3.0.12.tar.gz
cd /swig-3.0.12
./configure --prefix=/usr

# build
make -j 4

# install
make install

# check version reported
swig -version

#SWIG Version 3.0.12


cd ..
git clone https://github.com/Kitt-AI/snowboy.git

git clone https://github.com/duxingkei33/orangepi_PC_gpio_pyH3.git
python orangepi_PC_gpio_pyH3/setup.py install 
wget --output-document vlc.py "http://git.videolan.org/?p=vlc/bindings/python.git;a=blob_plain;f=generated/vlc.py;hb=HEAD"

#apt-get install libasound2-dev memcached python-pip python-alsaaudio vlc -y
#pip install -r requirements.txt
#cp initd_alexa.sh /etc/init.d/AlexaPi
#update-rc.d AlexaPi defaults
#touch /var/log/alexa.log

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



echo "You can now reboot"
