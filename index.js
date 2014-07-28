module.exports = function(clientId, clientSecret, host) {
    var module = {};

    module.authenticate = function(callback) {
        var redirectUri = chrome.identity.getRedirectURL() + "provider_cb";
        var redirectRe = new RegExp(redirectUri + '[#\?](.*)');

        var options = {
            "interactive": true,
            "url": host + "/services/oauth2/authorize?client_id=" + clientId +
                "&response_type=code" +
                "&display=page" +
                "&redirect_uri=" + encodeURIComponent(redirectUri)
        };

        chrome.identity.launchWebAuthFlow(options, function(redirectUri) {
            if (chrome.runtime.lastError) {
                return callback(new Error(chrome.runtime.lastError));
            }

            // Upon success the response is appended to redirectUri, e.g.
            // https://{app_id}.chromiumapp.org/provider_cb#access_token={value}&refresh_token={value}
            var matches = redirectUri.match(redirectRe);
            if (matches && matches.length > 1) {
                handleProviderCodeResponse(parseRedirectFragment(matches[1]));
            } else {
                callback(new Error('Invalid redirect URI'));
            }
        });

        function parseRedirectFragment(fragment) {
            var pairs = fragment.split(/&/);
            var values = {};

            pairs.forEach(function(pair) {
                var nameVal = pair.split(/=/);
                values[nameVal[0]] = nameVal[1];
            });

            return values;
        }

        function handleProviderCodeResponse(values) {
            if (values.hasOwnProperty("code")) {
                var url = host + '/services/oauth2/token' +
                    '?client_id=' + clientId +
                    '&client_secret=' + clientSecret +
                    '&grant_type=authorization_code' +
                    '&code=' + values.code +
                    '&redirect_uri=' + encodeURIComponent(redirectUri);

                var xhr = new XMLHttpRequest();
                xhr.open("POST", url, true);
                xhr.onload = function() {
                    if (this.status < 200 || this.status >=300) {
                        callback(new Error('error in handleCodeResponse.'));
                    } else {
                        handleProviderTokensResponse(JSON.parse(this.response));
                    }
                };
                xhr.send();
            } else {
                callback(new Error('error in handleProviderCodeResponse.'));
            }
        }

        function handleProviderTokensResponse(values) {
            if (values.hasOwnProperty('access_token') && values.hasOwnProperty('refresh_token')) {
                var newConnection = {
                    host: values.instance_url,
                    access_token: values.access_token,
                    refresh_token: values.refresh_token
                };
                callback(null, newConnection);
            } else {
                callback(new Error('error in handleProviderTokensResponse.'));
            }
        }
    };

    module.refreshToken = function(connection, callback) {
        var url = connection.host + '/services/oauth2/token?client_id=' + clientId +
            '&client_secret=' + clientSecret +
            '&grant_type=refresh_token' +
            '&refresh_token=' + connection.refresh_token;

        var xhr = new XMLHttpRequest();
        xhr.open("POST", url, true);
        xhr.onload = function() {
            if (this.status < 200 || this.status >=300) {
                callback(new Error('error in handleCodeResponse.'));
            } else {
                handleProviderTokenResponse(JSON.parse(this.response));
            }
        };
        xhr.send();

        function handleProviderTokenResponse(values) {
            if (values.hasOwnProperty('access_token')) {
                callback(null, values);
            } else {
                callback(new Error('error in handleProviderTokenResponse.'));
            }
        }
    };

    return module;
};

