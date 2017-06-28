package io.pivotal.poc.bac.authrouteservice;

import netegrity.siteminder.javaagent.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;

import java.net.URI;

/**
 * Created by azwickey on 6/28/17.
 */
@Controller
public class SMService implements InitializingBean {

    Logger LOG = LoggerFactory.getLogger(SMService.class);

    private final AgentAPI _api = new AgentAPI();
    @Value("${sm.ip}")
    private String _policyIp;
    @Value("${sm.agent.hostname}")
    private String _agentHostName;
    @Value("${sm.agent.sharedSecret}")
    private String _sharedSecret;

    public void afterPropertiesSet() throws Exception {
        ServerDef sd = new ServerDef();
        sd.serverIpAddress = _policyIp;
        sd.connectionMax = 10;
        sd.connectionMin = 1;
        sd.timeout = 10;
        _api.init(new InitDef( _agentHostName, _sharedSecret, false, sd));
        LOG.info("SM Agent initialized: " + _api.toString());
    }

    public boolean isValid(String authCokie) {
        LOG.debug("Validating cookie [" + authCokie + "]");
        int rc = _api.decodeSSOToken(authCokie, new TokenDescriptor(0,true), new AttributeList(), false, new StringBuffer());
        LOG.debug("Decode return code: "+ rc);
        switch (rc) {
            case AgentAPI.SUCCESS:
                return true;
            case AgentAPI.FAILURE:
                return false;
            default: throw new RuntimeException("Error Occurred Checking if decoding cookie; ReturnCode: " + rc);
        }
    }

    public boolean isProtected(URI uri, HttpMethod method) {
        LOG.debug("Checking if URI [" + uri + "[ is protected");
        int rc = _api.isProtected(_agentHostName, new ResourceContextDef(
                _agentHostName,
                _policyIp,
                uri.getPath(),
                method.name()),
                new RealmDef());
        LOG.debug("IsProtected return code: "+ rc);
        switch (rc) {
            case AgentAPI.YES:
                return true;
            case AgentAPI.NO:
                return false;
            default: throw new RuntimeException("Error Occurred Checking if resource is protected; ReturnCode: " + rc);

        }
    }

}
