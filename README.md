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
        ./TREX nodes [<nodes>] [-h] [--json] [-b (slurm|pbs)] [-l <path>]
        ./TREX state [<nodes>] [--state <state>] [--reason <reason>] [-h] [--json] [-b (slurm|pbs)]
               [-l <path>]

        ./TREX jobs [<jobIDs>] [-h] [--json] [-b (slurm|pbs)] [-l <path>]
        ./TREX queues [<queues>] [-h] [--json] [-b (slurm|pbs)] [-l <path>]


PARAMETERS:

        COMMANDS

            nodes <nodes>
                    Get node information [of <nodes>]

            state <nodes> [--state <state>] [--reason <reason>]
                    Get/Set state [of <nodes>]

            jobs <jobIDs>
                    Get job info [of <jobIDs>]

            queues <queues>
                    Get queue information [of <queues>]

        OPTIONS

            -h, --help
                    Shows this help message

            --json  Output as json
            -b, --batch (slurm|pbs)
                    Batch System

            -l, --loginFile <path>
                    Path for login data
```