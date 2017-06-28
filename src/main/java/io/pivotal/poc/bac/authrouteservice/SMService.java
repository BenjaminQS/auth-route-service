package io.pivotal.poc.bac.authrouteservice;

import netegrity.siteminder.javaagent.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.net.URI;

/**
 * Created by azwickey on 6/28/17.
 */
@Component
@Configuration
public class SMService {

    Logger LOG = LoggerFactory.getLogger(SMService.class);

    private final AgentAPI _api = new AgentAPI();
    @Value("${sm.ip:127.0.0.1}") private String _policy_ip;
    @Value("${sm.agent.hostname:localhost}") private String _agentHostName;
    @Value("${sm.agent.sharedSecret:abz123}") private String _sharedSecret;


    public SMService() {
        ServerDef sd = new ServerDef();
        sd.serverIpAddress = _policy_ip;
        _api.init(new InitDef( _agentHostName, _sharedSecret, false, sd));
        LOG.info("SM Agent initialized: " + _api.toString());
    }

    public boolean isValid(String authCokie) {
        LOG.debug("Validating cookie [" + authCokie + "]");
        int rc = _api.decodeSSOToken(authCokie, new TokenDescriptor(0,true), new AttributeList(), false, new StringBuffer());
        LOG.debug("Decode return code: "+ rc);
        return (AgentAPI.SUCCESS == rc) ? true : false;
    }

    public boolean isProtected(URI uri, HttpMethod method) {
        LOG.debug("Checking if URI [" + uri + "[ is protected");
        int rc = _api.isProtected(_agentHostName, new ResourceContextDef(
                _agentHostName,
                _policy_ip,
                uri.getPath(),
                method.name()),
                new RealmDef());
        LOG.debug("IsProtected return code: "+ rc);
        return (AgentAPI.YES == rc) ? true : false;
    }

}
