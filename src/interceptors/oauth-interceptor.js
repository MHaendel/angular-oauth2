
/**
 * OAuth interceptor.
 *
 * @ngInject
 */

function oauthInterceptor($q, $rootScope, OAuthToken) {
  return {
    request: function(config) {
      // Inject `Authorization` header.
      if (OAuthToken.getAuthorizationHeader()) {
        config.headers = config.headers || {};
        config.headers.Authorization = OAuthToken.getAuthorizationHeader();
      }

      return config;
    },
    responseError: function(rejection) {
      // Catch `invalid_request` and `invalid_grant` errors and ensure that the `token` is removed.
      if (400 === rejection.status &&
        (rejection.data && 'invalid_grant' === rejection.data.error) ||
        (rejection.data && 'invalid_request' === rejection.data.error) ||
        (rejection.headers('www-authenticate') && 0 === rejection.headers('www-authenticate').indexOf('Bearer'))
      ) {
        OAuthToken.removeToken();
        $rootScope.$emit('oauth:error', rejection);
      }

      // Catch `invalid_grant` and `unauthorized` errors.
      // The token isn't removed here so it can be refreshed when the `invalid_grant` error occurs.
      if (401 === rejection.status &&
        (rejection.data && 'invalid_grant' === rejection.data.error) ||
        (rejection.data && 'access_denied' === rejection.data.error) ||
        (rejection.headers('www-authenticate') && 0 === rejection.headers('www-authenticate').indexOf('Bearer'))
      ) {
        $rootScope.$emit('oauth:error', rejection);
      }

      return $q.reject(rejection);
    }
  };
}

/**
 * Export `oauthInterceptor`.
 */

export default oauthInterceptor;
