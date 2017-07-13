package io.pivotal.poc.bac.authrouteservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestOperations;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 * Created by azwickey on 6/22/17.
 */
@RestController
public class RouteServiceController {

    Logger LOG = LoggerFactory.getLogger(RouteServiceController.class);

    public static final String TARGET_URL = "X-CF-Forwarded-Url";
    public static final String AUTH_COOKIE = "SMSESSION";

    @Value("${login.url:https://pivotal.io/}")
    private String _loginTarget;

    @Autowired
    private RestOperations _rs;

    @Autowired
    private SMService _sm;

    @RequestMapping("auth")
    public ResponseEntity<?> service(RequestEntity<byte[]> incoming) {
        LOG.debug("Incoming Request: {}", incoming);

        String target = incoming.getHeaders().getFirst(TARGET_URL);
        if(target == null) {
            throw new IllegalStateException(String.format("No %s header present", TARGET_URL));
        }

        String smCookie = null;
        if(obtainCookie(incoming, target)) {
            LOG.info("Request not authenticated, logging into SiteMinder.");
            RequestEntity<?> cookieReq = getCookieRequest(incoming.getHeaders());
            LOG.debug("Login Cookie Request: {}", cookieReq);
            ResponseEntity<byte[]> cookieResp = _rs.exchange(cookieReq, byte[].class);
            LOG.debug("Login Cookie Response: {}", cookieResp);
            smCookie = cookieResp.getHeaders().getFirst(AUTH_COOKIE);
        }

        RequestEntity<?> outgoing = getOutgoingRequest(incoming, smCookie);
        LOG.debug("Outgoing Request: {}", outgoing);

        return _rs.exchange(outgoing, byte[].class);
    }

    private boolean obtainCookie(RequestEntity<byte[]> incoming, String target) {
        if(_sm.isProtected(target, incoming.getMethod())) {
            LOG.debug("Resource is protected, validating cookie");
            boolean validCookie = false;
            if(incoming.getHeaders().containsKey(AUTH_COOKIE) && _sm.isValid(incoming.getHeaders().getFirst(AUTH_COOKIE))) {
                validCookie =  true;
            }
            return validCookie;
        }
        return false;
    }

    private RequestEntity<?> getOutgoingRequest(RequestEntity<byte[]> incoming, String authCookie) {
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(incoming.getHeaders());
        headers.put(AUTH_COOKIE, Arrays.asList(authCookie));

        List<String> targets = headers.remove(TARGET_URL);
        if(targets == null || targets.isEmpty()) {
            throw new IllegalStateException(String.format("No %s header present", TARGET_URL));
        } else {
            return new RequestEntity<byte[]>(incoming.getBody(), headers, incoming.getMethod(), URI.create(targets.get(0)));
        }
    }

    private RequestEntity<?> getCookieRequest(HttpHeaders headers) {
        HttpHeaders h = new HttpHeaders();
        //Add headers to auth the user
        h.putAll(headers);
        return new RequestEntity<byte[]>(h, HttpMethod.GET, URI.create(_loginTarget));
    }
}
