import CryptoStuffClass
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
import shutil
import os
import vlc
import logging
from hashlib import sha1

CryptoClass = CryptoStuffClass.CryptoStuff()

#Debug
Debug = True

if Debug:
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
#logger.addHandler(ch)
 
# Log kayıt yolunu belirleme
logging.basicConfig(filename='artex.log', filemode='w', level=log_level)

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'

if(UsePins):
    from rgbControlClass import RGBControl

if len(sys.argv) == 1:
    logger.error("HATA: özel bir model ismi gerekiyor")
    logger.info("ÖRNEK KULLANIM: python3 yz.py modeldosyasi.model")
    sys.exit(-1)

interrupted = False

def signal_handler(signal, frame):
    global interrupted
    interrupted = True

# capture SIGINT signal, e.g., Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

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
GlobalLastMessageTime = ''
playlists = set(['pls', 'm3u', 'ash'])

model = sys.argv[1]
detector = snowboydecoder.HotwordDetector(model, sensitivity=0.4)

jar = requests.cookies.RequestsCookieJar()
requests.packages.urllib3.disable_warnings()
s = requests.Session()
s.verify = dir_path + "/certificate.crt"

def Web_Request(URL, Data, WantEncryption):
    try:
        global s, CryptionKey, jar
        payload = None
        if(WantEncryption == True):
            payload = urlencode(Data, quote_via=quote_plus)
            sifrele = CryptoClass.encrypt(payload, CryptionKey)
            payload = {'_yzCryption': sifrele}
        else:
            payload = Data
        req = s.post(URL, data=payload, cookies=jar)
        jar = req.cookies
        req.raise_for_status()

        out = None
        if(req.status_code == 200):
            out = req.text
            if(not out or out == ''):
                out = None

        return out
    except requests.exceptions.Timeout as e:
        logger.error("exceptions.Timeout => " + e)
    except requests.exceptions.TooManyRedirects as e:
        logger.error("exceptions.TooManyRedirects => " + e)
    except requests.exceptions.HTTPError as e:
        logger.error("exceptions.HTTPError => " + e)
    except requests.exceptions.RequestException as e:
        logger.error("exceptions.RequestException => " + e)
    except:
        logger.error("sys.exc_info()[0] => " + str(sys.exc_info()[0]))

def GetCryptionKey():
    try:
        global CryptionKey
        payload = {'sayfa': 'yz_CryptionKey'}
        jsonOutput = Web_Request(BaseUrl + 'main', payload, False)
        output = json.loads(jsonOutput)
        CryptionKey = CryptoClass.decrypt(output, Salt.encode())
        logger.debug(CryptionKey)
        return True
    except:
        logger.error("sys.exc_info()[0] => " + str(sys.exc_info()[0]))

def Login():
    if(GetCryptionKey() != True):
        logger.error("GetCryptionKey sırasında hata oluştu baştan başlatın!")
        return

    payload = {'pltfrm': 'orangepi', 'Username': Username, 'Password': Password, 'Remember': 'on'}
    jsonOutput = Web_Request(BaseUrl + 'login', payload, True)

    logger.debug(jsonOutput)
    output = json.loads(jsonOutput)

    if (output == "yanlis"):
        logger.error("Kullanici Adi veya Parola Yanlis!")
        sys.exit(1)
    elif (output == "basarili"):
        logger.debug("Giris Islemi Basarili!")
        if UsePins: led.magenta()
        SendMessage("", False, False)
        ThreadCheckNotifications.start()
        #burada mesaj gonderme fonksiyonunu calistiracak
        
        #if (ApplicationDeployment.IsNetworkDeployed)
        #    set_setting("csharp_version", ApplicationDeployment.CurrentDeployment.CurrentVersion.ToString())
    elif (output == "yok"):
        logger.error("Boyle Bir Kullanici Yok!")
        sys.exit(1)
    #else:
        #logger.debug(output)
    if UsePins: led.off()

def SendMessage(Message="", Talking=True, Listening=True):
    logger.debug("SendMessage Calisti, Gonderilecek Mesaj: '" + Message + "'")
    payload = {'msg': Message, 'pltfrm': 'orangepi'}
    output = Web_Request(BaseUrl + 'message.php', payload, True)
    logger.debug('SendMessage Yanit Geldi -> ' + output)
    ShowAll(Talking, Listening)

def ShowAll(Talking=True, Listening=True):
    global GlobalLastMessageTime
    logger.debug('ShowAll Calisti')
    payload = {'all': '1'}
    output = Web_Request(BaseUrl + 'message.php', payload, True)
    #logger.debug(output)
    logger.debug('ShowAll Yanit Geldi')

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
            GlobalLastMessageTime = datas['LastMessageTime']

            count, i = len(messages), 1
            for message in messages:
                dt = message['time']
                
                if (i == count):
                    if ('msj' in message and message['msj'] != None and message['msj'] != ""):
                        logger.debug(kendi_ismim + " -> " + message['msj'] + " | " + dt)

                    if (message['cvp'] != None and message['cvp'] != ""):
                        logger.debug(bot_ismi + " -> " + message['cvp'] + " | " + dt)

                    #if (message.platform == "orangepi"):
                    #    durum = message.isdurumu
                    #    if (message.csharp_eval != "" and message.csharp_eval != None):
                    #        csharp_eval = UrlDecode(message.csharp_eval)
                i += 1
            if(Talking == True):
                Talk(ses_data, ses_api)
                IsSpeaking(Listening)
        except ValueError:
            logger.error("bu bir json değil")
            GetCryptionKey()

intance = vlc.Instance()
player = vlc.MediaPlayer()

def Talk(ses_data, ses_api):
    hash_object = sha1(b''+ses_data.encode('utf-8').strip())
    hash_dig = hash_object.hexdigest()
    ses_path = dir_path + "/sesler/" + ses_api + "/"

    if(not os.path.exists(ses_path)):
        logger.debug("Ses klasörü bulunamadı, oluşturuluyor..")
        os.makedirs(ses_path)

    file_path = ses_path + hash_dig + ".mp3"

    if(not os.path.isfile(file_path)):
        logger.debug("Ses dosyası bulunamadı, indiriliyor..")
        req = s.post(BaseUrl + "main?sayfa=ses&ses=" + ses_data + "&pltfrm=csharp&ses_api=" + ses_api, stream=True)
        with open(file_path, 'wb') as f:
            shutil.copyfileobj(req.raw, f)
    if UsePins: led.blue()
    player.set_media(intance.media_new(file_path))
    player.play()

def IsSpeaking(Listening=True):
    global player
    time.sleep(0.5)
    while(player.is_playing() == True):
        pass
    
    if(Listening == True):
        DING()
        Triggered()

    if UsePins: led.off()

def CheckNotifications():
    while True:
        global GlobalLastMessageTime
        time.sleep(1)
        #logger.debug('CheckNotifications Calisti')
        payload = {'sayfa': 'mesaj_ici_bildirim'}
        try:
            output = Web_Request(BaseUrl + 'main', payload, True)
            #logger.debug('CheckNotifications Yanit Geldi')
            logger.debug(output)
            #if UsePins: led.yellow()
            if (output and output != None and output != ''):
                try:
                    jsonObject = json.loads(output)
                    LastMessageTime = jsonObject['LastMessageTime']
                    Talking = False
                    Listening = False
                    if (GlobalLastMessageTime != None and GlobalLastMessageTime != ''):
                        if (GlobalLastMessageTime != LastMessageTime):
                            GlobalLastMessageTime = GlobalLastMessageTime;
                            logger.debug(output)
                            if ('kind' in jsonObject and jsonObject['kind'] == 'bildirim'):
                                Talking = True
                            if ('WaitForResponse' in jsonObject and jsonObject['WaitForResponse'] == True):
                                Listening = True
    
                            logger.debug('CheckNotifications gelen yanit > 0 oldugundan ShowAll calistirildi.')
                            ShowAll(Talking, Listening)
                    else:
                        GlobalLastMessageTime = LastMessageTime
                except Exception as e:
                    logger.error("bir hata oldu sanki json ile ilgili olabilir.")
                    GetCryptionKey()
                    pass
        except (RuntimeError, TypeError, NameError):
            logger.error("bir hata oldu sanki :))")
            GetCryptionKey()
            pass

def DING():
    if UsePins: led.cyan()
    snowboydecoder.play_audio_file(snowboydecoder.DETECT_DING)

def Triggered():
    try:        
        logger.debug("Bir şeyler söyle!")
        with m as source: audio = r.listen(source, timeout=5)
        if UsePins: led.yellow()
        logger.debug("Yakaladım! Şimdi sesi tanımaya çalışıyorum...")
        try:
            value = r.recognize_google(audio, language="tr-TR")
            logger.debug("Minimum threshold enerjisi {} olarak tanımlandı.".format(r.energy_threshold))

            if str is bytes:
                logger.debug(u"P2Dediğin: {}".format(value).encode("utf-8"))
                data = format(value).encode("utf-8")
            else:
                logger.debug("P3Dediğin: {}".format(value))
                data = format(value)
            if(data and data != None and data != ''):
                if UsePins: led.green()
                SendMessage(data, True, True)
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
    
    DINGThread = Thread(target = DING)
    DINGThread.start()

    Triggered()
    logger.debug('Artex Sözcüğü Dinleniyor... Çıkış için Ctrl+C basın')
    detector.start(detected_callback=detect_callback, sleep_time=0.03)

if __name__ == "__main__":
    ThreadCheckNotifications = Thread(target = CheckNotifications)
    ThreadCheckNotifications.setDaemon(True)

    Login()

    logger.debug('Artex Sözcüğü Dinleniyor... Çıkış için Ctrl+C basın')

    detector.start(detected_callback=detect_callback,interrupt_check=interrupt_callback,sleep_time=0.03)
    detector.terminate()
