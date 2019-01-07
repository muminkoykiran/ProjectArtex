from Crypto import Random
from Crypto.Cipher import AES
import base64
from hashlib import md5
import snowboydecoder
import signal
from urllib.parse import urlencode, quote_plus
from creds import *
import requests
import sys
import speech_recognition as sr
from threading import Thread
import time
import json
from urllib.request import urlretrieve
import hashlib
import shutil
import os
import vlc
import logging

#Debug
debug = 1

if debug:
	log_level = logging.DEBUG
else:
	log_level = logging.getLevelName('INFO')

# Logger oluşturalım.
logger = logging.getLogger("ProjectArtex")
logger.setLevel(log_level) # Uygulamız şuanda çalışıyor.

# Consol yapısını oluşturduk
ch = logging.StreamHandler()
ch.setLevel(log_level) # Hata ayıklama tipini belirledik.

formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
 
# Konsol Formatı
ch.setFormatter(formatter)
 
# logger için konsol
logger.addHandler(ch)
 
# Log kayıt yolunu belirleme
logging.basicConfig(filename='artex.log', filemode='w', level=log_level)

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'

if(UsePins):
    from rgbControlClass import RGBControl

interrupted = False

if len(sys.argv) == 1:
    logger.error("HATA: özel bir model ismi gerekiyor")
    logger.info("ÖRNEK KULLANIM: python3 yz.py modeldosyasi.model")
    sys.exit(-1)

def signal_handler(signal, frame):
    global interrupted
    interrupted = True

def interrupt_callback():
    global interrupted
    return interrupted

if(UsePins):
    led = RGBControl(7, 8, 9)
    led.off()

def delete_last_lines(n=1):
    for _ in range(n):
        sys.stdout.write(CURSOR_UP_ONE)
        sys.stdout.write(ERASE_LINE)

r = sr.Recognizer()
m = sr.Microphone()

#delete_last_lines(100)
#print("....")
#delete_last_lines()

logger.warning("Biraz sessiz kalın, Lütfen...")
with m as source: r.adjust_for_ambient_noise(source)
logger.debug("Minimum threshold enerjisi {} olarak tanımlandı.".format(r.energy_threshold))

dir_path = os.path.dirname(os.path.realpath(__file__))
glob_LastMessageTime = ''
playlists = set(['pls', 'm3u', 'ash'])

model = sys.argv[1]
detector = snowboydecoder.HotwordDetector(model, sensitivity=0.4)

BLOCK_SIZE = 16

def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + (chr(length)*length).encode().decode('ascii')

def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

def bytes_to_key(data, salt, output=48):
    # extended from https://gist.github.com/gsakkis/4546068
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]

def encrypt(message, passphrase):
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))

def decrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))

Salt = Salt.encode()

jar = requests.cookies.RequestsCookieJar()
s = requests.Session()
def Web_Request(post_url, postData, cookie_save, WantEncryption):
    try:
        global s, CryptionKey, jar
        payload = None
        if(WantEncryption == True):
            payload = urlencode(postData, quote_via=quote_plus)
            sifrele = encrypt(payload, CryptionKey)
            payload = {'_yzCryption': sifrele}
        else:
            payload = postData
        req = s.post(post_url, data=payload, cookies=jar)
        jar = req.cookies
        req.raise_for_status()

        out = None
        if(req.status_code == 200):
            out = req.text
            #logger.debug(out)
            if(not out or out == ''):
                out = None

        return out
    except requests.exceptions.Timeout as e:
        getCryptionKey()
        logger.error("exceptions.Timeout" + e)
    except requests.exceptions.TooManyRedirects as e:
        logger.error("exceptions.TooManyRedirects" + e)
    except requests.exceptions.HTTPError as e:
        getCryptionKey()
        logger.error("exceptions.HTTPError" + e)
    except requests.exceptions.RequestException as e:
        getCryptionKey()
        logger.error("exceptions.RequestException" + e)
    except:
        getCryptionKey()
        logger.error("sys.exc_info()[0]" + sys.exc_info()[0])

def getCryptionKey():
    global CryptionKey
    payload = {'sayfa': 'yz_CryptionKey'}
    output = Web_Request(Domain + 'main', payload, True, False)
    CryptionKey = decrypt(output, Salt)
    logger.debug(CryptionKey)

def controleCryptionKey():
    payload = {'sayfa': 'control_CryptionKey'}
    output = Web_Request(Domain + 'main', payload, True, False)
    if (output != None and output != ""):
        global CryptionKey
        CryptionKey = decrypt(output, Salt)
        logger.debug(CryptionKey)

def Giris():
    getCryptionKey()

    payload = {'pltfrm': 'orangepi', 'Username': KullaniciAdi, 'Password': Parola, 'Remember': 'on'}
    output = Web_Request(Domain + 'login', payload, True, True).strip()

    logger.debug(output)

    if (output == "yanlis"):
        logger.error("Kullanici Adi veya Parola Yanlis!")
        sys.exit(1)
    elif (output == "basarili"):
        logger.debug("Giris Islemi Basarili!")
        giris_durumu = "basarili"
        if UsePins: led.magenta()
        doWork("", False, False)
        t1.start()
        #burada mesaj gonderme fonksiyonunu calistiracak
        
        #if (ApplicationDeployment.IsNetworkDeployed)
        #    set_setting("csharp_version", ApplicationDeployment.CurrentDeployment.CurrentVersion.ToString())
        
        #Console.WriteLine("aracxml icindeki th_oto_soru calistirildi.")
        #oto_soru()
    elif (output == "yok"):
        logger.error("Boyle Bir Kullanici Yok!")
        sys.exit(1)
    #else:
        #logger.debug(output)
    if UsePins: led.off()

def doWork(msg="", konus=True, dinle=True):
    logger.debug("doWork Calisti, Gonderilecek Mesaj: '" + msg + "'")
    payload = {'msg': msg, 'pltfrm': 'orangepi'}
    output = Web_Request(Domain + 'message.php', payload, True, True)
    logger.debug('doWork Yanit Geldi -> ' + output)
    setAll(konus, dinle)

def setAll(konus=True, dinle=True):
    global glob_LastMessageTime
    logger.debug('setAll Calisti')
    payload = {'all': '1'}
    output = Web_Request(Domain + 'message.php', payload, True, True)
    #logger.debug(output)
    logger.debug('setAll Yanit Geldi')

    if (output and output != None and output != ''):
        try:
            array = json.loads(output)

            datas = array['datas']
            messages = array['messages']
            kendi_ismim = datas['kendi_ismim']
            bot_ismi = datas['bot_ismi']
            ses_ac_kapa = datas['ses_ac_kapa']
            ses_data = datas['ses_data']
            ses_api = datas['ses_api']
            glob_LastMessageTime = datas['LastMessageTime']

            count, i = len(messages), 1
            for message in messages:
                durum = ""
                csharp_eval = ""
                dt = message['time']
                
                if (i == count):
                    if ('msj' in message and message['msj'] != None and message['msj'] != ""):
                        logger.debug(kendi_ismim + "-> " + message['msj'] + " | " + dt)

                    if (message['cvp'] != None and message['cvp'] != ""):
                        logger.debug(bot_ismi + "-> " + message['cvp'] + " | " + dt)

                    #if (message.platform == "csharp"):
                    #    durum = message.isdurumu
                    #    if (message.csharp_eval != "" and message.csharp_eval != None):
                    #        csharp_eval = UrlDecode(message.csharp_eval)
                i += 1
            if(konus == True):
                Talk(ses_data, ses_api)
                ses_gittimi(dinle)
        except ValueError:
            logger.error("bu bir json değil")
            getCryptionKey()

intance = vlc.Instance()
player = vlc.MediaPlayer()

def Talk(ses_data, ses_api):
    hash_object = hashlib.sha1(b''+ses_data.encode('utf-8').strip())
    hash_dig = hash_object.hexdigest()
    ses_path = dir_path + "/sesler/" + ses_api + "/"

    if(not os.path.exists(ses_path)):
        logger.debug("Ses klasörü bulunamadı, oluşturuluyor..")
        os.makedirs(ses_path)

    file_path = ses_path + hash_dig + ".mp3"

    if(not os.path.isfile(file_path)):
        logger.debug("Ses dosyası bulunamadı, indiriliyor..")
        req = s.post(Domain + "main?sayfa=ses&ses=" + ses_data + "&pltfrm=csharp&ses_api=" + ses_api, stream=True)
        with open(file_path, 'wb') as f:
            shutil.copyfileobj(req.raw, f)
    if UsePins: led.blue()
    player.set_media(intance.media_new(file_path))
    player.play()

def ses_gittimi(dinle=True):
    global player
    time.sleep(0.5)
    while(player.is_playing() == True):
        pass
    
    if(dinle == True):
        DING()
        tetiklendi()

    if UsePins: led.off()

def mesaj_ici_bildirim():
    while True:
        global glob_LastMessageTime
        time.sleep(1)
        #logger.debug('mesaj_ici_bildirim Calisti')
        payload = {'sayfa': 'mesaj_ici_bildirim'}
        try:
            output = Web_Request(Domain + 'main', payload, True, True)
            #logger.debug('mesaj_ici_bildirim Yanit Geldi')
            #if UsePins: led.yellow()
            if (output and output != None and output != ''):
                try:
                    jsonObject = json.loads(output)
                    LastMessageTime = jsonObject['LastMessageTime']
                    konus = False
                    dinle = True
                    if (glob_LastMessageTime != None and glob_LastMessageTime != ''):
                        if (glob_LastMessageTime != LastMessageTime):
                            glob_LastMessageTime = LastMessageTime;
                            logger.debug(output)
                            if ('kind' in jsonObject and jsonObject['kind'] == 'bildirim'):
                                konus = True
                            if ('WaitForResponse' not in jsonObject):
                                dinle = False
    
                            logger.debug('mesaj_ici_bildirim gelen yanit > 0 oldugundan setAll calistirildi.')
                            setAll(konus, dinle)
                    else:
                        glob_LastMessageTime = LastMessageTime
                except ValueError:
                    logger.error("bu bir json değil")
                    getCryptionKey()
                    pass
        except (RuntimeError, TypeError, NameError):
            logger.error("bir hata oldu sanki :))")
            getCryptionKey()
            pass
def DING():
    if UsePins: led.cyan()
    snowboydecoder.play_audio_file(snowboydecoder.DETECT_DING)

def tetiklendi():
    try:        
        logger.debug("Bir şeyler söyle!")
        with m as source: audio = r.listen(source, timeout=5)
        if UsePins: led.yellow()
        logger.debug("Yakaladım! Şimdi sesi tanımaya çalışıyorum...")
        try:
            # Tanımlama işlemi Google Ses Tanıma servisi kullanılarak gerçekleştiriliyor.
            value = r.recognize_google(audio, language="tr-TR")
            logger.debug("Set minimum energy threshold to {}".format(r.energy_threshold))
            # we need some special handling here to correctly print unicode characters to standard output
            if str is bytes:  # this version of Python uses bytes for strings (Python 2)
                logger.debug(u"P2Dediğin: {}".format(value).encode("utf-8"))
                data = format(value).encode("utf-8")
            else:  # this version of Python uses unicode for strings (Python 3+)
                logger.debug("P3Dediğin: {}".format(value))
                data = format(value)
            if(data and data != None and data != ''):
                if UsePins: led.green()
                doWork(data, True, True)
        except sr.UnknownValueError:
            logger.warning("Eyvah! Sesi yakalayamadım!")
            if UsePins: led.red()
            snowboydecoder.play_audio_file(snowboydecoder.DETECT_DONG)
        except sr.RequestError as e:
            logger.error("Ah be! Google Ses Tanıma servisinden sonuç isteği yapılamadı; {}".format(e))
            if UsePins: led.red()
            snowboydecoder.play_audio_file(snowboydecoder.DETECT_DONG)
    except sr.WaitTimeoutError:
        logger.warning("Zaman Aşımı Gerçekleşti")
        if UsePins: led.red()
        snowboydecoder.play_audio_file(snowboydecoder.DETECT_DONG)
    if UsePins: led.off()

def detect_callback():
    delete_last_lines()
    logger.debug("...")
    delete_last_lines()
    detector.terminate()
    #tetiklendiThread = Thread(target = tetiklendi)
    #tetiklendiThread.start()
    #DING()
    DINGThread = Thread(target = DING)
    DINGThread.start()

    tetiklendi()
    logger.debug('Artex Sözcüğü Dinleniyor... Çıkış için Ctrl+C basın')
    detector.start(detected_callback=detect_callback, sleep_time=0.03)

# capture SIGINT signal, e.g., Ctrl+C
#signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    t1 = Thread(target = mesaj_ici_bildirim)
    t1.setDaemon(True)

    Giris()

    logger.debug('Artex Sözcüğü Dinleniyor... Çıkış için Ctrl+C basın')

    # Main Loop
    detector.start(detected_callback=detect_callback,interrupt_check=interrupt_callback,sleep_time=0.03)
    detector.terminate()
