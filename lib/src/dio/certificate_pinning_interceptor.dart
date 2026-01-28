import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

class CertificatePinningInterceptor extends Interceptor {
  final List<String> _allowedSHAFingerprints;
  final int _timeout;
  final bool callFollowingErrorInterceptor;

  /// A function that takes the request URL as input and returns `true` if
  /// certificate pinning validation should be skipped for that URL.
  ///
  /// This can be useful for excluding certain URLs from validation, such as
  /// external services not under your control.
  final bool Function(String)? skipValidation;

  /// Transforms the intercepted request URL into the canonical URL used for
  /// certificate pinning verification.
  ///
  /// This is useful when the base URL normally requires authentication or
  /// side effects that should be avoided during native TLS validation (e.g.
  /// iOS performing a background request during certificate checks).
  final String Function(String)? resolvePinnedUrl;
  Future<String>? secure = Future.value('');

  CertificatePinningInterceptor({
    List<String>? allowedSHAFingerprints,
    this.skipValidation,
    this.resolvePinnedUrl,
    int timeout = 0,
    this.callFollowingErrorInterceptor = false,
  })  : _allowedSHAFingerprints = allowedSHAFingerprints != null
            ? allowedSHAFingerprints
            : <String>[],
        _timeout = timeout;

  @override
  Future onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    try {
      // iOS bug: Alamofire is failing to return parallel requests for certificate validation
      if (Platform.isIOS && secure != null) {
        await secure;
      }

      var baseUrl = options.baseUrl;

      if (options.path.contains('http') || options.baseUrl.isEmpty) {
        baseUrl = options.path;
      }

      if (skipValidation != null && skipValidation!(baseUrl)) {
        return super.onRequest(options, handler);
      }
      if (resolvePinnedUrl != null) {
        baseUrl = resolvePinnedUrl!(baseUrl);
      }
      secure = HttpCertificatePinning.check(
        serverURL: baseUrl,
        headerHttp: {
          'X-From': 'Flutter-Certificate-Pinning',
        },
        sha: SHA.SHA256,
        allowedSHAFingerprints: _allowedSHAFingerprints,
        timeout: _timeout,
      );

      final secureString = await secure?.whenComplete(() => secure = null);

      if (secureString?.contains('CONNECTION_SECURE') ?? false) {
        return super.onRequest(options, handler);
      } else {
        handler.reject(
          DioException(
            requestOptions: options,
            error: CertificateNotVerifiedException(),
          ),
          callFollowingErrorInterceptor,
        );
      }
    } on Exception catch (e) {
      dynamic error;

      error = switch (e) {
        PlatformException(code: 'CONNECTION_NOT_SECURE') =>
          const CertificateNotVerifiedException(),
        PlatformException(code: 'NO_INTERNET' || 'NETWORK_ERROR') =>
          DioException.connectionError(
            requestOptions: options,
            reason: e.code,
            error: e.code,
          ),
        PlatformException(code: 'TIMEOUT') => DioException.connectionTimeout(
            requestOptions: options,
            timeout: Duration(milliseconds: _timeout),
            error: e.code,
          ),
        _ => CertificateCouldNotBeVerifiedException(e),
      };

      handler.reject(
        error is DioException
            ? error
            : DioException(
                requestOptions: options,
                error: error,
              ),
        callFollowingErrorInterceptor,
      );
    }
  }
}
