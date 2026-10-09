package com.example.keycloak.opa;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * 로그인 시점에 OPA의 keycloak/login/allow 정책을 직접(REST) 호출한다.
 * ext_authz(Envoy) 체인과는 완전히 별개의 경로 - Keycloak 프로세스 자신이
 * 평범한 HTTP 클라이언트로 OPA에게 묻는다.
 */
public class OpaDeviceAuthenticator implements Authenticator {

    private static final String OPA_URL =
            "http://opa-envoy.opa.svc.cluster.local:8181/v1/data/keycloak/login/allow";

    // 크로스 파드 mTLS 핸드셰이크 지연이 실측 7.5초 정도라 10초로 여유있게 잡음.
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String username = user != null ? user.getUsername() : null;

        if (username == null) {
            context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER,
                    context.form().setError("Unknown user").createErrorPage(Response.Status.FORBIDDEN));
            return;
        }

        boolean allowed = queryOpa(username);
        if (allowed) {
            context.success();
        } else {
            context.getEvent().error("opa_device_denied");
            context.failureChallenge(AuthenticationFlowError.ACCESS_DENIED,
                    context.form()
                            .setError("Device not trusted (denied by OPA policy).")
                            .createErrorPage(Response.Status.FORBIDDEN));
        }
    }

    private boolean queryOpa(String username) {
        try {
            String body = "{\"input\":{\"username\":\"" + username.replace("\"", "") + "\"}}";
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(TIMEOUT)
                    .build();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(OPA_URL))
                    .header("Content-Type", "application/json")
                    .timeout(TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            // OPA 응답: {"result":true} / {"result":false} / (default라 미평가시 result 필드 자체가 없음)
            return resp.statusCode() == 200 && resp.body().contains("\"result\":true");
        } catch (Exception e) {
            // 네트워크 오류/타임아웃 시 fail-closed - OPA한테 못 물어보면 로그인 거부.
            return false;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // 사용자가 제출하는 폼이 없는 단계라 할 일 없음.
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // 설정할 Required Action 없음.
    }

    @Override
    public void close() {
    }
}
