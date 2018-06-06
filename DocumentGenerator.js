var mustache = require("./mustache");

var addslashes, addslashes_single_quotes, cURLCodeGenerator;

(function(root) {
  return (root.Mustache = require("mustache.js") || root.Mustache);
})(this);

(function(root) {
  return (root.Base64 = require("Base64.js") || root.Base64);
})(this);

const reqTemplate = readFile("req.mustache");

addslashes = function(str) {
  return ("" + str).replace(/[\\"]/g, "\\$&");
};

addslashes_single_quotes = function(str) {
  return ("" + str).replace(/\\/g, "\\$&").replace(/'/g, "'\"'\"'");
};

var DocumentGenerator = function() {
  var self;
  self = this;
  this.parseRequest = function(req) {
    const jsonReq = {
      id: req.id,
      name: req.name,
      description: req.description,
      order: req.order,
      parent: req.parent,
      url: req.url,
      urlBase: req.urlBase,
      urlQuery: req.urlQuery,
      method: req.method,
      headers: JSON.parse(JSON.stringify(req.headers, null, 4)),
      httpBasicAuth: req.httpBasicAuth,
      oauth1: req.oauth1,
      timeout: req.timeout,
      followRedirects: req.followRedirects,
      redirectAuthorization: req.redirectAuthorization,
      redirectMethod: req.redirectMethod,
      sendCookies: req.sendCookies,
      storeCookies: req.storeCookies,
    };

    const urlEncodedBody = {};
    const urlEncodedBodyArr = req.getUrlEncodedBodyKeys();
    if (urlEncodedBodyArr) {
      urlEncodedBodyArr.forEach(function(key) {
        urlEncodedBody[key] = req.getUrlEncodedBodyKey(key);
      });

      jsonReq.urlEncodedBody =
        "Form URL-Encoded: \n```\n" +
        JSON.stringify(urlEncodedBody, null, 4) +
        "\n```\n";
    }

    // response
    const res = req.getLastExchange();
    if (res && res.responseBody) {
      jsonReq.resBody =
        "Response: \n```\n" +
        JSON.stringify(JSON.parse(res.responseBody), null, 4) +
        "\n```\n";
    }

    // json body
    if (req.jsonBody) {
      jsonReq.jsonBody =
        "JSON Body: \n```\n" +
        JSON.stringify(req.jsonBody, null, 4) +
        "\n```\n  ";
    }

    // body
    if (req.body && !req.jsonBody) {
      jsonReq.body =
        "body: \n```\n" +
        JSON.stringify(JSON.parse(req.body), null, 4) +
        "\n```\n  ";
    }

    // multipartBody
    if (req.multipartBody) {
      jsonReq.multipartBody =
        "multipartBody: \n```\n" +
        JSON.stringify(req.multipartBody, null, 4) +
        "\n```\n  ";
    }

    // oauth2
    if (req.oauth2) {
      jsonReq.oauth2 =
        "oauth2: \n```\n" + JSON.stringify(req.oauth2, null, 4) + "\n```\n";
    }

    // remove cookie
    if (jsonReq.headers && jsonReq.headers.Cookie) {
      delete jsonReq.headers.Cookie;
    }

    // remove undefined keys
    Object.keys(jsonReq).forEach(function(key) {
      if (!jsonReq[key]) delete jsonReq[key];
    });

    // header
    jsonReq.headers = JSON.stringify(jsonReq.headers, null, 4);

    // curl
    jsonReq.curl = "Curl: \n```bash\n" + self.generateRequest(req) + "```";

    return mustache.render(reqTemplate, jsonReq) + "\n\n";
  };
  this.headers = function(request) {
    var auth, header_name, header_value, headers;
    headers = request.headers;
    auth = null;
    if (headers["Authorization"]) {
      auth = this.auth(request, headers["Authorization"]);
      if (auth) {
        delete headers["Authorization"];
      }
    }
    return {
      has_headers: Object.keys(headers).length > 0,
      header_list: (function() {
        var results;
        results = [];
        for (header_name in headers) {
          header_value = headers[header_name];
          results.push({
            header_name: addslashes_single_quotes(header_name),
            header_value: addslashes_single_quotes(header_value),
          });
        }
        return results;
      })(),
      auth: auth,
    };
  };
  this.auth = function(request, authHeader) {
    var DVpass,
      DVuser,
      decoded,
      digestDS,
      digestDV,
      err,
      match,
      params,
      password,
      scheme,
      username,
      userpass;
    if (self.options && self.options.useHeader) {
      return null;
    }
    match = authHeader.match(/([^\s]+)\s(.*)/) || [];
    scheme = match[1] || null;
    params = match[2] || null;
    if (scheme === "Basic") {
      try {
        decoded = Base64.atob(params);
      } catch (error) {
        err = error;
        return null;
      }
      userpass = decoded.match(/([^:]*):?(.*)/);
      return {
        username: addslashes_single_quotes(userpass[1] || ""),
        password: addslashes_single_quotes(userpass[2] || ""),
      };
    }
    digestDS = request.getHeaderByName("Authorization", true);
    if (
      digestDS &&
      digestDS.length === 1 &&
      digestDS.getComponentAtIndex(0).type ===
        "com.luckymarmot.PawExtensions.DigestAuthDynamicValue"
    ) {
      digestDV = digestDS.getComponentAtIndex(0);
      DVuser = digestDV.username;
      username = "";
      if (typeof DVuser === "object") {
        username = DVuser.getEvaluatedString();
      } else {
        username = DVuser;
      }
      DVpass = digestDV.password;
      password = "";
      if (typeof DVpass === "object") {
        password = DVpass.getEvaluatedString();
      } else {
        password = DVpass;
      }
      return {
        isDigest: true,
        username: addslashes_single_quotes(username),
        password: addslashes_single_quotes(password),
      };
    }
    return null;
  };
  this.body = function(request) {
    var has_tabs_or_new_lines,
      json_body,
      multipart_body,
      name,
      raw_body,
      url_encoded_body,
      value;
    url_encoded_body = request.urlEncodedBody;
    if (url_encoded_body) {
      return {
        has_url_encoded_body: true,
        url_encoded_body: (function() {
          var results;
          results = [];
          for (name in url_encoded_body) {
            value = url_encoded_body[name];
            results.push({
              name: addslashes(name),
              value: addslashes(value),
            });
          }
          return results;
        })(),
      };
    }
    multipart_body = request.multipartBody;
    if (multipart_body) {
      return {
        has_multipart_body: true,
        multipart_body: (function() {
          var results;
          results = [];
          for (name in multipart_body) {
            value = multipart_body[name];
            results.push({
              name: addslashes(name),
              value: addslashes(value),
            });
          }
          return results;
        })(),
      };
    }
    json_body = request.jsonBody;
    if (json_body != null) {
      return {
        has_raw_body_with_tabs_or_new_lines: true,
        has_raw_body_without_tabs_or_new_lines: false,
        raw_body: addslashes_single_quotes(JSON.stringify(json_body, null, 2)),
      };
    }
    raw_body = request.body;
    if (raw_body) {
      if (raw_body.length < 5000) {
        has_tabs_or_new_lines = null !== /\r|\n|\t/.exec(raw_body);
        return {
          has_raw_body_with_tabs_or_new_lines: has_tabs_or_new_lines,
          has_raw_body_without_tabs_or_new_lines: !has_tabs_or_new_lines,
          raw_body: has_tabs_or_new_lines
            ? addslashes_single_quotes(raw_body)
            : addslashes(raw_body),
        };
      } else {
        return {
          has_long_body: true,
        };
      }
    }
  };
  this.strip_last_backslash = function(string) {
    var i, j, lines, ref;
    lines = string.split("\n");
    for (
      i = j = ref = lines.length - 1;
      ref <= 0 ? j <= 0 : j >= 0;
      i = ref <= 0 ? ++j : --j
    ) {
      lines[i] = lines[i].replace(/\s*\\\s*$/, "");
      if (!lines[i].match(/^\s*$/)) {
        break;
      }
    }
    return lines.join("\n");
  };
  this.generateRequest = function(request) {
    var rendered_code, template, view;
    view = {
      request: request,
      request_is_head: request.method === "HEAD",
      specify_method: request.method !== "GET" && request.method !== "HEAD",
      headers: this.headers(request),
      body: this.body(request),
    };
    if (view.request.description) {
      view.request.cURLDescription = view.request.description
        .split("\n")
        .map(function(line, index) {
          return "# " + line;
        })
        .join("\n");
    } else {
      view.request.cURLDescription = "";
    }
    template = readFile("curl.mustache");
    rendered_code = Mustache.render(template, view);
    return this.strip_last_backslash(rendered_code);
  };
  this.generateCurl = function(context, requests, options) {
    var curls;
    self.options = (options || {}).inputs || {};
    curls = requests.map(function(request) {
      return self.generateRequest(request);
    });
    return curls.join("\n");
  };

  this.generate = function(context, requests, options) {
    var generated = "";
    requests.forEach(function(req) {
      generated += self.parseRequest(req);
    });

    return generated;
  };
};
DocumentGenerator.identifier = "com.bimsop.DocumentGenerator";
DocumentGenerator.title = "Bimsop Documentation Generator";
DocumentGenerator.fileExtension = "md";
DocumentGenerator.languageHighlighter = "markdown";
DocumentGenerator.inputs = [
  new InputField("useHeader", "do not use -u option", "Checkbox", {
    defaultValue: false,
  }),
];

registerCodeGenerator(DocumentGenerator);
