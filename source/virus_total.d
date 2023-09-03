import std.conv;
import std.digest;
import std.digest.sha;
import std.stdio;

import vibe.d;
import vibe.web.auth;

import db_conn;

static struct AuthInfo
{
@safe:
    string userEmail;
}

@path("api/v1")
@requiresAuth
interface VirusTotalAPIRoot
{
    // Users management
    @noAuth
    @method(HTTPMethod.POST)
    @path("signup")
    Json addUser(string userEmail, string username, string password, string name = "", string desc = "");

    @noAuth
    @method(HTTPMethod.POST)
    @path("login")
    Json authUser(string userEmail, string password);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_user")
    Json deleteUser(string userEmail);

    // URLs management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_url") // the path could also be "/url/add", thus defining the url "namespace" in the URL
    Json addUrl(string userEmail, string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path("url_info")
    Json getUrlInfo(string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path ("user_urls")
    Json getUserUrls(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_url")
    Json deleteUrl(string userEmail, string urlAddress);

    // Files management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_file")
    Json addFile(string userEmail, immutable ubyte[] binData, string fileName);

    @noAuth
    @method(HTTPMethod.GET)
    @path("file_info")
    Json getFileInfo(string fileSHA512Digest);

    @noAuth
    @method(HTTPMethod.GET)
    @path("user_files")
    Json getUserFiles(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_file")
    Json deleteFile(string userEmail, string fileSHA512Digest);
}

class VirusTotalAPI : VirusTotalAPIRoot
{
    this(DBConnection dbClient)
    {
        this.dbClient = dbClient;
    }

    @noRoute AuthInfo authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        // If "userEmail" is not present, an error 500 (ISE) will be returned
        string userEmail = req.json["userEmail"].get!string;
        string userAccessToken = dbClient.getUserAccessToken(userEmail);
        // Use headers.get to check if key exists
        string headerAccessToken = req.headers.get("AccessToken");
        if (headerAccessToken && headerAccessToken == userAccessToken)
            return AuthInfo(userEmail);
        throw new HTTPStatusException(HTTPStatus.unauthorized);
    }

override:

    Json addUser(string userEmail, string username, string password, string name = "", string desc = "")
    {
	    auto ret = dbClient.addUser(userEmail, username, password, name, desc);
	    if (ret == dbClient.UserRet.ERR_NULL_PASS) {
		    throw new HTTPStatusException(HTTPStatus.badRequest, "password cannot be null");  
        } else if (ret == dbClient.UserRet.ERR_INVALID_EMAIL) {
		    throw new HTTPStatusException(HTTPStatus.badRequest, "invalid email");  
        } else if (ret == dbClient.UserRet.ERR_USER_EXISTS) {
		    throw new HTTPStatusException(HTTPStatus.unauthorized, "existing user");
        } else if (ret != dbClient.UserRet.OK) {
		    throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");        
	    }
	    Json json;
        return json;
    }

    Json authUser(string userEmail, string password)
    {
	    auto ret = dbClient.authUser(userEmail, password);
        if (ret == dbClient.UserRet.ERR_NULL_PASS) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "password cannot be null");
        } else if (ret == dbClient.UserRet.ERR_INVALID_EMAIL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid email");
        } else if (ret == dbClient.UserRet.ERR_WRONG_PASS) {
            throw new HTTPStatusException(HTTPStatus.unauthorized, "wrong password");
        } else if (ret == dbClient.UserRet.ERR_WRONG_USER) {
            throw new HTTPStatusException(HTTPStatus.unauthorized, "wrong user");
        }
	    //generate token
	    string token = dbClient.generateUserAccessToken(userEmail);
        Json json = token.serializeToJson();
        return Json(["AccessToken": json]);
    }

    Json deleteUser(string userEmail)
    {
        auto ret = dbClient.deleteUser(userEmail);
	    if (ret == dbClient.UserRet.ERR_INVALID_EMAIL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid email");
        }
	    Json json;
        return json;
    }

    // URLs management

    Json addUrl(string userEmail, string urlAddress)
    {
	    auto ret = dbClient.addUrl(userEmail, urlAddress);
        if (ret == dbClient.UrlRet.ERR_EMPTY_URL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "empty url");
        }
        throw new HTTPStatusException(HTTPStatus.ok, "ok");
    }

    Json deleteUrl(string userEmail, string urlAddress)
    {
	    if (urlAddress.empty) {
		    throw new HTTPStatusException(HTTPStatus.badRequest, "empty url");
	    }
	    dbClient.deleteUrl(userEmail, urlAddress);
        throw new HTTPStatusException(HTTPStatus.ok, "ok");
    }

    Json getUrlInfo(string urlAddress)
    {
	    auto ret = dbClient.getUrl(urlAddress);
	    if (ret.isNull) {
		    throw new HTTPStatusException(HTTPStatus.notFound, "url not found");
	    }
	    Json json = ret.serializeToJson();
	    return json;
    }

    Json getUserUrls(string userEmail)
    {
	    auto ret = dbClient.getUrls(userEmail);
	    return ret.serializeToJson();
    }

    // Files management

    Json addFile(string userEmail, immutable ubyte[] binData, string fileName)
    {
	    auto ret = dbClient.addFile(userEmail, binData, fileName);
        if (ret == dbClient.FileRet.ERR_EMPTY_FILE) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "empty file");
        }
        throw new HTTPStatusException(HTTPStatus.ok, "ok");
    }

    Json getFileInfo(string fileSHA512Digest)
    {
        auto ret = dbClient.getFile(fileSHA512Digest);
        if (ret.isNull) {
            throw new HTTPStatusException(HTTPStatus.notFound, "file not found");
        }
        Json json = ret.serializeToJson();
        return json;
    }

    Json getUserFiles(string userEmail)
    {
	    auto ret = dbClient.getFiles(userEmail);
        return ret.serializeToJson();
    }

    Json deleteFile(string userEmail, string fileSHA512Digest)
    {
        if (fileSHA512Digest.empty) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "empty file");
        }
	    dbClient.deleteFile(userEmail, fileSHA512Digest);
        throw new HTTPStatusException(HTTPStatus.ok, "ok");
    }

private:
    DBConnection dbClient;
}
