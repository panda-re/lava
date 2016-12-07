import lava
import sys
import os

DIR = os.path.dirname(sys.argv[0])
name = os.environ['USER']
home = os.environ['HOME']
nas = '/nas/'+ name
dockername = name + "_lava32"

# killing and cleaning
rc, (out, err) = lava.run_cmd_notimeout("docker stop {}".format(dockername), None, {})
rc, (out, err) = lava.run_cmd_notimeout("docker rm {}".format(dockername), None, {})

# building and starting
rc, (out, err) = lava.run_cmd_notimeout("docker build -t {} .".format(dockername), os.path.join(DIR, "../docker"), {})
os.system("cd {} && docker build -t {} .".format(os.path.join(DIR, "../docker"),
                                                 dockername))
os.system("cd -")

rc, (out, err) = lava.run_cmd_notimeout("docker images", None, {})
try:
    personal_builds = filter(lambda line: dockername in line, out.split("\n"))
    buildhash = personal_builds[0].split()[2]
except:
    print out
    print err
    sys.exit(-1)

print "Docker image created with hash: " + buildhash

rc, (out, err_) = lava.run_cmd_notimeout("docker create -t -i --name={} -v {}:{} -v {}:{} {} /bin/bash".format(dockername, home, home, nas, nas, buildhash),
                                        None, {})
print out

rc, (out, err) = lava.run_cmd_notimeout("docker ps -a", None, {})

if out.find(dockername) == -1:
    print "Error, no docker container created"
    print err_
else:
    print "Docker container successfully created with name " + dockername

rc, (out, err) = lava.run_cmd_notimeout("docker start {}".format(dockername), None, {})

if out.strip() != dockername:
    print "Error, docker container failed to start"
else:
    print "Docker container successfully started"

rc, (out, err) = lava.run_cmd_notimeout("docker exec -ti {} useradd --shell /bin/bash -M {}".format(dockername, name), None, {})
print out
print err

