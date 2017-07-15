package io.pivotal.poc.bac.authrouteservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.CookieValue;
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

    @RequestMapping("cookie")
    public HttpEntity<String> fakeCookie(RequestEntity<byte[]> incoming) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set("Cookie", "SMSESSION=FakeSessionCookie");
        return new HttpEntity<String>("Hello World", responseHeaders);
    }

    @RequestMapping("auth")
    public ResponseEntity<?> service(@CookieValue(value=AUTH_COOKIE, required = false) String cookie, RequestEntity<byte[]> incoming) {
        LOG.debug("Incoming Request: {}", incoming);

        String target = incoming.getHeaders().getFirst(TARGET_URL);
        if(target == null) {
            throw new IllegalStateException(String.format("No %s header present", TARGET_URL));
        }

        target = URI.create(target).getPath();
        String cookies = null;
        if(_sm.isProtected(target, incoming.getMethod(), true) && !validCookie(cookie, URI.create(target).getPath())) {
//            LOG.info("Request not authenticated, logging into SiteMinder.");
//            RequestEntity<?> cookieReq = getCookieRequest(incoming.getHeaders());
//            LOG.debug("Login Cookie Request: {}", cookieReq);
//            ResponseEntity<byte[]> cookieResp = _rs.exchange(cookieReq, byte[].class);
//            LOG.debug("Login Cookie Response: {}", cookieResp);
//            if(cookieResp.getStatusCode() != HttpStatus.OK) {
//                LOG.debug("Login Cookie Response code wasn't 200... ignoring");
//                //return new ResponseEntity<String>("User Not Authorized", new HttpHeaders(), HttpStatus.FORBIDDEN);
//            }
//            cookies = cookieResp.getHeaders().getFirst("Cookie");
            LOG.info("Request not authenticated returning 302.");
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.putAll(incoming.getHeaders());
            responseHeaders.setLocation(URI.create(_loginTarget));
            return new ResponseEntity<byte[]>(responseHeaders, HttpStatus.TEMPORARY_REDIRECT);
        } else {
            cookies = incoming.getHeaders().getFirst("Cookie");  //this is needed to simply propogate all cookies on unprotected requests
        }

        RequestEntity<?> outgoing = getOutgoingRequest(incoming, cookies);
        LOG.debug("Outgoing Request: {}", outgoing);

        return _rs.exchange(outgoing, byte[].class);
    }

    private boolean validCookie(String cookie, String target) {
        LOG.debug("Validating cookie: " + cookie);
        if(cookie != null && _sm.isValid(cookie, true)) {
            LOG.debug("Valid cookie");
            return true;
        } else {
            LOG.debug("Invalidating cookie");
            return false;
        }
    }

    private RequestEntity<?> getOutgoingRequest(RequestEntity<byte[]> incoming, String authCookie) {
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(incoming.getHeaders());
        headers.put("Cookie", Arrays.asList(authCookie));

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
