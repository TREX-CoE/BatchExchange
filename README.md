# TREX

<Project description>

#### Dependencies
- libcurl
- rapidjson

#### Compilation
```
./cmakeHelper.sh
cd cbuild
make -j $(nproc)
```
#### Usage
```
USAGE:
        ./TREX deploy <nodes> [--group] [--image <image>] [--prescripts <prescripts>]
               [--postbootscripts <postbootscripts>] [--postscripts <postscripts>] [-h] [--json] [-b
               (slurm|pbs)] [-l <path>]

        ./TREX nodes [<nodes>] [-h] [--json] [-b (slurm|pbs)] [-l <path>]
        ./TREX state [<nodes>] [--state <state>] [--reason <reason>] [-h] [--json] [-b (slurm|pbs)]
               [-l <path>]

        ./TREX jobs [<jobIDs>] [-h] [--json] [-b (slurm|pbs)] [-l <path>]
        ./TREX queues [<queues>] [-h] [--json] [-b (slurm|pbs)] [-l <path>]
        ./TREX images [<images>] [-h] [--json] [-b (slurm|pbs)] [-l <path>]
        ./TREX bootstate [<nodes>] [-h] [--json] [-b (slurm|pbs)] [-l <path>]
        ./TREX reboot <nodes> [-h] [--json] [-b (slurm|pbs)] [-l <path>]


PARAMETERS:

        COMMANDS

            deploy <nodes> --group [--image <image>] [--prescripts <prescripts>] [--postbootscripts
            <postbootscripts>] [--postscripts <postscripts>]
                    Deploy <image> on <nodes/groups>

            nodes <nodes>
                    Get node information [of <nodes>]

            state <nodes> [--state <state>] [--reason <reason>]
                    Get/Set state [of <nodes>]

            jobs <jobIDs>
                    Get job info [of <jobIDs>]

            queues <queues>
                    Get queue information [of <queues>]

            images <images>
                    Get information for available images [<images>]

            bootstate <nodes>
                    Get bootstate [of <nodes>]

            reboot <nodes>
                    Reboot <nodes>

        OPTIONS

            -h, --help
                    Shows this help message

            --json  Output as json
            -b, --batch (slurm|pbs)
                    Batch System

            -l, --loginFile <path>
                    Path for login data
```