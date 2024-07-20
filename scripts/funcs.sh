#!/bin/bash
# Common bash functions used by lava shell scripts

#g  Include guard
if [ -z "$LAVA_FUNCS_INCLUDED" ]; then
    LAVA_FUNCS_INCLUDED=1

    progress() {
      if [[ $2 -eq 1 ]]; then
          date
      fi
      echo -e "\e[32m[$1]\e[0m \e[1m$3\e[0m"
    }


    # start timer
    tick() {
        ns=$(date +%s%N)
        START=$(echo "scale=2; $ns/1000000000" | bc)
    }

    tock() {
        ns=$(date +%s%N)
        END=$(echo "scale=2; $ns/1000000000" | bc)
        time_diff=$(echo "scale=2; $END-$START" | bc)
    }

    deldir () {
        deldir=$1
        if [[ $ok -eq 0 ]]
        then
            # they have to actually type 'ok'
            progress "`basename \"$0\" .sh`" 0 "Deleting $deldir.    Type ok to go ahead."
            read ans
        else
            progress "`basename \"$0\" .sh`" 0 "Deleting $deldir."
            ans=ok
        fi
        if [[ "$ans" = "ok" ]]
        then
            echo "...deleting"
            rm -rf $deldir || true
        else
            echo "exiting"
            exit
        fi
    }

    run_remote() {
        remote_machine=$1
        command=$2
        logfile=$3
        if [ -z "$logfile" ]; then
            logfile=/dev/stdout
        fi
        echo $command >> $logfile;
        set +e
        docker_map_args="-v $lava:$lava -v $tarfiledir:$tarfiledir"

        if [ "$extradockerargs" = "null" ]; then
            extradockerargs="";
        fi

        if [[ "$directory" = "$tarfiledir"* ]]; then true; else
            docker_map_args="$docker_map_args -v $directory:$directory"
        fi
        if [ "$remote_machine" == "localhost" ]; then
            echo "$command"
            bash -c "$command" >> "$logfile" 2>&1
        elif [ "$remote_machine" == "docker" ]; then
            echo docker run $dockername sh -c "$command"
            DOCKER_IP=$(ifconfig docker0 | grep 'inet ' | awk '{print $2}')
            docker run --rm -it \
                -e "HTTP_PROXY=$HTTP_PROXY" \
                -e "HTTPS_PROXY=$HTTPS_PROXY" \
                -e "http_proxy=$http_proxy" \
                -e "https_proxy=$https_proxy" \
                -v /var/run/postgresql:/var/run/postgresql \
                -v "$HOME/.pgpass:$HOME/.pgpass" \
                -v /etc/passwd:/etc/passwd:ro \
                -v /etc/group:/etc/group:ro \
                -v /etc/shadow:/etc/shadow:ro \
                -v /etc/gshadow:/etc/gshadow:ro \
                -v /home:/home:ro \
                --add-host=database:$DOCKER_IP \
                $docker_map_args \
                $extradockerargs \
                $dockername sh -c "trap '' PIPE; su -l $(whoami) -c \"$command\"" \
                >> "$logfile" 2>&1
        else
            echo "ssh $remote_machine $command"
            ssh $remote_machine $command 2>&1 >> "$logfile"
        fi
        ret_code=$?
        if [ $ret_code != 0 ]; then
            echo "command failed! exit code was $ret_code"
            echo "========== end of logfile $lf: ========== "
            echo
            tail -n 30 "$lf"
            exit $ret_code
        fi
        set -e
    }

    truncate() {
        echo -n > "$1"
    }

    die() {
         printf '%s\n' "$1" >&2
         exit 1
    }

fi
