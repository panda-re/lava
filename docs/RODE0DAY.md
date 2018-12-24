Docs for rode0day development

Conventions for rode0days:
* Lava databases will be stored on pompeii named `target_rode0day[date]`, for instance `libjpeg_rode0day1809`
* Backups of lava databases will be stored on the NAS in `/nas/rode0day/[rode0day-name]/[target-name]-db` (`/nas/rode0day/rode0day1809/libjpeg-db`)
* Lava-generated corpus directories will be stored on the NAS in `/nas/rode0day/[rode0day-name]/[corpus-name]` (`/nas/rode0day/rode0day1809/libjpeg-corpus-XXX-YYY/`)


Instructions for generating competition:
1. Identify targets, build configs, run lava.sh
2. Create directory ~/rode0day/[date] and touch info.yaml
3. Run competition.sh with at least 100-200 bugs (-m 200)
4. Examine generated corpus, if you're unhappy with it, rerun competition
5. Update info.yaml with instructions to run the challenge
5. Backup corpus directory onto NAS

For binary challenges:
6. Build challenge and libraries
7. Strip symbols from everything
8. Test bugs
9. Create directory ~/rode0day/[date]/[challenge-short-name]/ with lava-install, lava-install-internal, and src dirs


For source challenges:
6. Make a backup copy of the original src directory
7. Run `~/lava/scripts/replace_macros.py *.c` to strip LAVALOGGING macros from all files in src and libs
8. Create directory ~/rode0day/[date]/[challenge-short-name]/ with src+makefile, lava-install-internal, lava-install, and original src


10. When all challenges have been collected, create ~/rode0day/[date]-public
11. In the public directory, remove secret information (lava-install-internal, private src dirs)
12. Tar public directory, scp to rode0day server
13. Update DB on rode0day server to show competition details, select random string for tarball filepath
14. Put the tarball in the static directory with the random name


Now you must set up grading on the server:
15. SCP the private rodeo directory to rodeo server
16. Place all the lava-install-internal directories into /opt/web/challenges/[rode0 shortname]/[challenge name]
17. Update DB with paths to all directories, challenge IDs and how each challenge is run

Instructions for data-release after a rode0day:
1. Find original source
2. Collect all saved uploads
2. Dump database for stats on submission times by each team
