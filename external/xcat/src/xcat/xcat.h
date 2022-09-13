#ifndef XCAT_H
#define XCAT_H

#include <string>
#include <system_error>
#include <functional>
#include <vector>
#include <map>

namespace xcat {

/**
 * \brief xcat error codes
 * 
 */
enum class error {
    login_failed = 1,
    no_auth,
    api_error,
    get_nodes_failed,
    get_groups_failed,
    get_bootstate_failed,
    set_bootstate_failed,
    get_osimages_failed,
    set_group_attributes_failed,
    set_nextboot_failed,
    set_powerstate_failed,
};


const std::error_category& error_category() noexcept;

std::error_code make_error_code(error e);


/**
 * \brief HTTP Method
 * 
 * Enum of HTTP Method type.
 */
enum class HttpMethod {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
};

/**
 * \brief HTTP Request
 * 
 * Abstract HTTP Request type to allow using different http libraries.
 */
struct ApiCallRequest {
    HttpMethod method = HttpMethod::GET; //!<  Method of request
    std::string uri; //!< Uri of request
    std::string body; //!< Body of request
    std::map<std::string, std::string> headers; //!< Map of header values
};

/**
 * \brief HTTP Response
 * 
 * Abstract HTTP Response type to allow using different http libraries.
 */
struct ApiCallResponse {
    unsigned int status_code = 0; //!< HTTP Response status code
    std::string body; //!< body of response
    std::map<std::string, std::string> headers; //!< Map of response header values
    std::error_code ec; //!< error code if http call failed
};

/**
 * \brief XCAT Error
 * 
 * Error wrapper that stores both failures in communication and unknown internal xcat errors with their error message.
 */
struct XcatError {
    std::error_code ec; //!< error code if http call failed
    int error_code; //!< xcat error code
    std::string msg; //!< error message
};

/**
 * \brief Abstract function interface for sending http requests
 * 
 * \param req Request to send
 * \param resp Callback to send result back if finished
 */
using http_f = std::function<void(ApiCallRequest req, std::function<void(ApiCallResponse)> resp)>;

/**
 * \brief Provisioning Node info
 * 
 * Struct containing node infos.
 */
struct NodeInfo {
    std::string name; //!< name of node
    std::string postscripts; //!< scripts called after provisioning
    std::string postbootscripts; //!< scripts called after each boot
    std::string installnic; //!< install network controller
    std::string primarynic; //!< primary network controller
    std::string mac; //!< mac address
    std::vector<std::string> groups; //!< groups that node is member of
    std::map<std::string, std::string> extra; //!< extra node attributes
};

/**
 * \brief Provisioning Group info
 * 
 * Struct containing group infos.
 */
struct GroupInfo {
    std::string name; //!< name of group
    std::string mgt; //!< management option
    std::string netboot; //!< netboot settings
    std::vector<std::string> members; //!< nodes that are members of group
};

/**
 * \brief Provisioning Image info
 * 
 * Struct containing osimage infos.
 */
struct OsimageInfo {
    std::string name; //!< name of image
    std::string profile; //!< profile of image
    std::string osname; //!< name of os
    std::string osarch; //!< architecture of os
    std::string osvers; //!< version of os
    std::string provmethod; //!< provisioning method
};

/**
 * \brief Xcat interface
 * 
 * Xcat REST API interface using an abstract HTTP call interface.
 */
class Xcat {
private:
	http_f _func;
    std::string _token;
    unsigned long int _expires;
    std::string _username;
    std::string _password;

    ApiCallRequest add_auth(ApiCallRequest req, bool has_query_params);
public:
    /**
     * \brief Construct a new Xcat object
     * 
     * \param func 
     */
	Xcat(http_f func);

    /**
     * \brief Set the token and its expire date to use for authentication
     * 
     * \param token 
     * \param expires 
     */
    void set_token(std::string token, unsigned long expires=0);

    /**
     * \brief Set the credentials for authentication
     * 
     * \param username Xcat username
     * \param password Xcat password
     */
    void set_credentials(std::string username, std::string password);

    /**
     * \brief Get the token object
     * 
     * \param cb Asynchronous get token and expire epoch time
     */
    void get_token(std::function<void(std::string token, unsigned long int expires, XcatError ec)> cb);

    /**
     * \brief Check if required token or credentials are given
     */
    bool check_auth();

    /**
     * \brief Get node infos
     *
     * \param filter Get only these nodes or all if empty
     * \param cb Asynchronous get map of all nodes
     */
    void get_nodes(const std::vector<std::string> &filter, std::function<void(std::map<std::string, NodeInfo>, XcatError ec)> cb);

    /**
     * \brief Get group infos
     * 
     * \param filter Get only these groups or all if empty
     * \param cb Asynchronous get map of all groups
     */
    void get_groups(const std::vector<std::string> &filter, std::function<void(std::map<std::string, GroupInfo>, XcatError ec)> cb);

    /**
     * \brief Get osimage infos
     * 
     * \param filter Get only these osimages or all if empty
     * \param cb Asynchronous get map of all osimages
     */
    void get_osimages(const std::vector<std::string> &filter, std::function<void(std::map<std::string, OsimageInfo>, XcatError ec)> cb);

    /**
     * \brief Get node bootstates
     * 
     * \param filter Get only bootstate these nodes or all if empty
     * \param cb Asynchronous get map of bootstate of nodes
     */
    void get_bootstate(const std::vector<std::string> &filter, std::function<void(std::map<std::string, std::string>, XcatError ec)> cb);
    
    /**
     * \brief Set node powerstates
     * 
     * \param filter Set powerstate of these nodes or all if empty
     * \param action Action like reset to trigger
     * \param cb Asynchronous done callback
     */
    void set_powerstate(const std::vector<std::string> &filter, std::string action, std::function<void(XcatError ec)> cb);
    
    /**
     * \brief Set node nextboot
     * 
     * \param filter Set nextboot of these nodes or all if empty
     * \param order Bootorder to set
     * \param cb Asynchronous done callback
     */
    void set_nextboot(const std::vector<std::string> &filter, std::string order, std::function<void(XcatError ec)> cb);
    
    /**
     * \brief Set node bootstate
     * 
     * \param filter Set bootstate of these nodes or all if empty
     * \param osimage Image to set for provisioning
     * \param cb Asynchronous done callback
     */
    void set_bootstate(const std::vector<std::string> &filter, std::string osimage, std::function<void(XcatError ec)> cb);
    
    /**
     * \brief Set group attributes
     * 
     * \param filter Set attibutes of these grpups or all if empty
     * \param attrs Map of attributes to set
     * \param cb Asynchronous done callback
     */
    void set_group_attributes(const std::vector<std::string> &filter, const std::map<std::string, std::string>& attrs, std::function<void(XcatError ec)> cb);
}; 


}

namespace std
{
  template <>
  struct is_error_code_enum<xcat::error> : true_type {};
}


#endif  // XCAT_H
