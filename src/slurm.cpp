#include <iostream>

#include "slurm.h"

Slurm::Slurm() {
    this->slurmSession = new RestClient(SESSION_TOKEN_BASIC_AUTH);
}


Slurm::~Slurm() {
    delete this->slurmSession;
}

/******************** session ********************/
int Slurm::login() {
    return slurmSession->login();
}


void Slurm::logout() {
    slurmSession->logout();
}


/******************** config ********************/
void Slurm::set_user_credentials(std::string username, std::string password) {
    slurmSession->set_user_credentials(username, password);
}


void Slurm::set_host_config(std::string host, std::string port) {
    slurmSession->set_host_config(host, port);
}


void Slurm::ssl_verify(bool sslVerify) {
    slurmSession->ssl_verify(sslVerify);
}


std::string Slurm::get_nodes() {
    std::string header, response;
    slurmSession->get("slurm/v0.0.36/nodes", response, header);
    std::cout << header << std::endl;
    std::cout << response << std::endl;

    return response;
}