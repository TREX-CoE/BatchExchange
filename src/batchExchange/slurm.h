#ifndef SLURM_H
#define SLURM_H

#include <string>

#include "sessionTokenTypes.h"
#include "restClient.h"

class Slurm {
private:
    RestClient *slurmSession;

public:
    Slurm();
    ~Slurm();

    void set_user_credentials(std::string username, std::string password);
    void set_host_config(std::string host, std::string port);
    void ssl_verify(bool sslVerify);

    int  login();
    void logout();

    std::string get_nodes();
};

#endif //SLURM_H