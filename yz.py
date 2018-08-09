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

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'

#Debug
debug = 1

if(UsePins):
    from rgbControlClass import RGBControl

#if debug: print("{}OKBLUE{}".format(bcolors.OKBLUE, bcolors.ENDC))
#if debug: print("{}OKGREEN{}".format(bcolors.OKGREEN, bcolors.ENDC))
#if debug: print("{}WARNING{}".format(bcolors.WARNING, bcolors.ENDC))
#if debug: print("{}FAIL{}".format(bcolors.FAIL, bcolors.ENDC))
#if debug: print("{}ENDC{}".format(bcolors.ENDC, bcolors.ENDC))
#if debug: print("{}BOLD{}".format(bcolors.BOLD, bcolors.ENDC))
#if debug: print("{}UNDERLINE{}".format(bcolors.UNDERLINE, bcolors.ENDC))

interrupted = False

if len(sys.argv) == 1:
    if debug: print("HATA: özel bir model ismi gerekiyor")
    if debug: print("ÖRNEK KULLANIM: python3 yz.py modeldosyasi.model")
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

delete_last_lines(100)
print("....")
delete_last_lines()

if debug: print("Biraz sessiz kalın, Lütfen...")
with m as source: r.adjust_for_ambient_noise(source)
if debug: print("Minimum threshold enerjisi {} olarak tanımlandı.".format(r.energy_threshold))

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
            #if debug: print(out)
            if(not out or out == ''):
                out = None

        return out
    except requests.exceptions.Timeout as e:
        if debug: print(e)
    except requests.exceptions.TooManyRedirects as e:
        if debug: print(e)
    except requests.exceptions.HTTPError as e:
        if debug: print(e)
        #sys.exit(1)
    except requests.exceptions.RequestException as e:
        if debug: print(e)
        #sys.exit(1)
    except:
        #s = requests.Session()
        if debug: print(sys.exc_info()[0])

def getCryptionKey():
    global CryptionKey
    payload = {'sayfa': 'yz_CryptionKey'}
    output = Web_Request(Domain + 'index.php', payload, True, False)
    CryptionKey = decrypt(output, Salt)
    if debug: print("{}{}{}".format(bcolors.HEADER, CryptionKey, bcolors.ENDC))

def controleCryptionKey():
    payload = {'sayfa': 'control_CryptionKey'}
    output = Web_Request(Domain + 'index.php', payload, True, False)
    if (output != None and output != ""):
        global CryptionKey
        CryptionKey = decrypt(output, Salt)
        if debug: print("{}{}{}".format(bcolors.HEADER, CryptionKey, bcolors.ENDC))

def Giris():
    getCryptionKey()

    payload = {'pltfrm': 'orangepi', 'kullanici_adi': KullaniciAdi, 'sifre': Sifre, 'hatirla': 'on'}
    output = Web_Request(Domain + 'giris.php', payload, True, True).strip()

    print(output)

    if (output == "yanlis"):
        if debug: print("{}Kullanici Adi ve Sifre Yanlis!{}".format(bcolors.HEADER, bcolors.ENDC))
        sys.exit(1)
    elif (output == "basarili"):
        if debug: print("{}Giris Islemi Basarili!{}".format(bcolors.HEADER, bcolors.ENDC))
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
        if debug: print("{}Boyle Bir Kullanici Yok!{}".format(bcolors.HEADER, bcolors.ENDC))
        sys.exit(1)
    #else:
        #if debug: print("{}{]{}".format(bcolors.HEADER, output, bcolors.ENDC))
    if UsePins: led.off()

def doWork(msg="", konus=True, dinle=True):
    if debug: print('doWork Calisti')
    if debug: print("Gönderilecek Mesaj: '" + msg + "'")
    payload = {'msg': msg, 'pltfrm': 'orangepi'}
    output = Web_Request(Domain + 'message.php', payload, True, True)
    if debug: print(output)
    if debug: print('doWork Yanit Geldi')
    setAll(konus, dinle)


intance = vlc.Instance()
player = vlc.MediaPlayer()
mediaP = ''
def play_audio(file):
    global intance, player, mediaP
    if debug: print("{}Play_Audio Request for:{} {}".format(bcolors.OKBLUE, bcolors.ENDC, file))
    ext = (file.rpartition(".")[2])[:3]
    #subprocess.Popen(['mpg123', '-q', '{}{}'.format(path, file)]).wait()
    #i = vlc.Instance('--aout=alsa', '--alsa-audio-device=hw:CARD=audiocodec,DEV=0')
    mrl = "{}".format(file)
    if debug: print(ext)

    if mrl != "":
        if ext in playlists:
            #Replaced code here
            
            event_manager = player.event_manager() # Attach event to player (next 3 lines)
            event = vlc.EventType()
            event_manager.event_attach(event.MediaPlayerEndReached, end_reached)
            mediaP = intance.media_new(mrl) # Create new media
            player.set_media(mediaP) # Set URL as the player's media
            mediaP.release()
            player.play() # play it
            while flag == 0: # Wait until the end of the first media has been reached.$
                time.sleep(0.5)
                if debug: print("{}Loading Playlist...{}".format(bcolors.OKBLUE, bcolors.ENDC))
            sub_list = mediaP.subitems() # .. and get the sub itmes in the playlist
            sub_list.lock()
            sub = sub_list.item_at_index(0) # Get the first sub item
            sub_list.unlock()
            sub_list.release()
            player.set_media(sub) # Set it as the new media in the player
            #End of replaced Code
        else:
            mediaP = intance.media_new(mrl)
            player = intance.media_player_new()
            player.set_media(mediaP)
            player.audio_set_volume(100)
            if debug: print("{}Requesting Stream...{}".format(bcolors.OKBLUE, bcolors.ENDC))
        player.play()
    else:
        if debug: print("(play_audio) mrl = Nothing!")

def setAll(konus=True, dinle=True):
    #global player
    global glob_LastMessageTime
    if debug: print('setAll Calisti')
    payload = {'all': '1'}
    output = Web_Request(Domain + 'message.php', payload, True, True)
    #if debug: print(output)
    if debug: print('setAll Yanit Geldi')

    if (output and output != None and output != ''):
        try:
            dizi = json.loads(output)

            datas = dizi['datas']
            messages = dizi['messages']
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
                        if debug: print(i, message['msj'], kendi_ismim, dt)

                    if (message['cvp'] != None and message['cvp'] != ""):
                        if debug: print(i, message['cvp'], bot_ismi, dt)

                    if debug: print('son mesaj bu!')
                    #if (message.platform == "csharp"):
                    #    durum = message.isdurumu
                    #    if (message.csharp_eval != "" and message.csharp_eval != None):
                    #        csharp_eval = UrlDecode(message.csharp_eval)
                i += 1
            if(konus == True):
                Talk(ses_data, ses_api)
                ses_gittimi(dinle)
        except ValueError:
            if debug: print("bu bir json değil")
            getCryptionKey()

def Talk(ses_data, ses_api):
    hash_object = hashlib.sha1(b''+ses_data.encode('utf-8').strip())
    hash_dig = hash_object.hexdigest()
    ses_path = dir_path + "/sesler/" + ses_api + "/"

    if(not os.path.exists(ses_path)):
        if debug: print("Ses klasörü bulunamadı, oluşturuluyor..")
        os.makedirs(ses_path)

    file_path = ses_path + hash_dig + ".mp3"

    if(not os.path.isfile(file_path)):
        if debug: print("Ses dosyası bulunamadı, indiriliyor..")
        req = s.post(Domain + "index.php?sayfa=ses&ses=" + ses_data + "&pltfrm=csharp&ses_api=" + ses_api, stream=True)
        with open(file_path, 'wb') as f:
            shutil.copyfileobj(req.raw, f)
    if UsePins: led.blue()
    #play_audio(file_path)
    player.set_media(intance.media_new(file_path))
    player.play()

def ses_gittimi(dinle=True):
    global player
    time.sleep(0.5)
    while(player.is_playing() == True):
        pass
    
    if(dinle == True):
        tetiklendiThread = Thread(target = tetiklendi)
        tetiklendiThread.start()
        DING()

    if UsePins: led.off()

def mesaj_ici_bildirim():
    while True:
        global glob_LastMessageTime
        time.sleep(1)
        if debug: print('mesaj_ici_bildirim Calisti')
        payload = {'sayfa': 'mesaj_ici_bildirim'}
        output = Web_Request(Domain + 'index.php', payload, True, True)
        #if debug: print('mesaj_ici_bildirim Yanit Geldi')
        #if UsePins: led.yellow()
        if (output and output != None and output != ''):
            try:
                if debug: print(output)
                jsonObject = json.loads(output)
                LastMessageTime = jsonObject['LastMessageTime']
                konus = False
                dinle = True
                if (glob_LastMessageTime != None and glob_LastMessageTime != ''):
                    if (glob_LastMessageTime != LastMessageTime):
                        glob_LastMessageTime = LastMessageTime;
                        if debug: print(output)
                        if ('kind' in jsonObject and jsonObject['kind'] == 'bildirim'):
                            konus = True
                            dinle = False

                        if debug: print('mesaj_ici_bildirim gelen yanit > 0 oldugundan setAll calistirildi.')
                        if debug: print(output)
                        setAll(konus, dinle)
                else:
                    glob_LastMessageTime = LastMessageTime
            except ValueError:
                if debug: print("bu bir json değil")
                getCryptionKey()
                continue
def DING():
    if UsePins: led.cyan()
    snowboydecoder.play_audio_file(snowboydecoder.DETECT_DING)

def tetiklendi():
    try:        
        if debug: print("{}Bir şeyler söyle!{}".format(bcolors.OKBLUE, bcolors.ENDC))
        with m as source: audio = r.listen(source, timeout=5)
        if UsePins: led.yellow()
        if debug: print("{}Yakaladım! Şimdi sesi tanımaya çalışıyorum...{}".format(bcolors.WARNING, bcolors.ENDC))
        try:
            # Tanımlama işlemi Google Ses Tanıma servisi kullanılarak gerçekleştiriliyor.
            value = r.recognize_google(audio, language="tr-TR")
            if debug: print("{}Set minimum energy threshold to {}{}".format(bcolors.WARNING, r.energy_threshold, bcolors.ENDC))
            # we need some special handling here to correctly print unicode characters to standard output
            if str is bytes:  # this version of Python uses bytes for strings (Python 2)
                if debug: print(u"P2Dediğin: {}".format(value).encode("utf-8"))
                data = format(value).encode("utf-8")
            else:  # this version of Python uses unicode for strings (Python 3+)
                if debug: print("{}P3Dediğin: {}{}".format(bcolors.WARNING, value, bcolors.ENDC))
                data = format(value)
            if(data and data != None and data != ''):
                if UsePins: led.green()
                doWork(data, True, True)
        except sr.UnknownValueError:
            if debug: print("{}Eyvah! Sesi yakalayamadım!{}".format(bcolors.FAIL, bcolors.ENDC))
            if UsePins: led.red()
            snowboydecoder.play_audio_file(snowboydecoder.DETECT_DONG)
        except sr.RequestError as e:
            if debug: print("{}Ah be! Google Ses Tanıma servisinden sonuç isteği yapılamadı; {}{}".format(bcolors.FAIL, e, bcolors.ENDC))
            if UsePins: led.red()
            snowboydecoder.play_audio_file(snowboydecoder.DETECT_DONG)
    except sr.WaitTimeoutError:
        if debug: print("{}Zaman Aşımı Gerçekleşti{}".format(bcolors.FAIL, bcolors.ENDC))
        if UsePins: led.red()
        snowboydecoder.play_audio_file(snowboydecoder.DETECT_DONG)
    if UsePins: led.off()

def detect_callback():
    delete_last_lines()
    print("...")
    delete_last_lines()
    detector.terminate()
    tetiklendiThread = Thread(target = tetiklendi)
    tetiklendiThread.start()
    DING()
    if debug: print('Artex Sözcüğü Dinleniyor... Çıkış için Ctrl+C basın')
    detector.start(detected_callback=detect_callback, sleep_time=0.03)

# capture SIGINT signal, e.g., Ctrl+C
#signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    t1 = Thread(target = mesaj_ici_bildirim)
    t1.setDaemon(True)

    Giris()

    if debug: print('Artex Sözcüğü Dinleniyor... Çıkış için Ctrl+C basın')

    # Main Loop
    detector.start(detected_callback=detect_callback,interrupt_check=interrupt_callback,sleep_time=0.03)
    detector.terminate()
