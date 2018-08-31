#! /bin/bash

### BEGIN INIT INFO
# Provides: ArtexPi
# Required-Start: $all
# Required-Stop: $all
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: ArtexPi Service
# Description: Start / Stop ArtexPi Service
### END INIT INFO

exec > /var/log/artex.log 2>&1
case "$1" in

start)
    echo "Starting Artex..."
    # python /root/ProjectArtex/yz.py &
    python3 /home/root/ProjectArtex/yz.py /home/root/ProjectArtex/Artex.pmdl &

;;

stop)
    echo "Stopping Artex.."
    pkill -SIGINT ^yz.py$
;;

restart|force-reload)
        echo "Restarting Artex.."
        $0 stop
        sleep 2
        $0 start
        echo "Restarted."

;;
*)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
esac
