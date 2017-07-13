package io.pivotal.poc.bac.authrouteservice;

import com.ca.siteminder.sdk.agentapi.SmRegHost;
import com.ca.siteminder.sdk.agentapi.Util;
import com.netegrity.util.Fips140Mode;
import netegrity.siteminder.javaagent.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
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
    @Value("${sm.user}")
    private String _policyUsername;
    @Value("${sm.password}")
    private String _policyPwd;

    public void afterPropertiesSet() throws Exception {

        String secret = getSharedSecret();
        LOG.info("SM Agent hostname: " +  _agentHostName);
        LOG.info("SM Agent Policy Server IP: " + _policyIp);
        LOG.info("SM Agent shared secret: " + secret);

        ServerDef sd = new ServerDef();
        sd.serverIpAddress = _policyIp;
        sd.connectionMax = 10;
        sd.connectionMin = 1;
        sd.timeout = 10;
        int result = _api.init(new InitDef( _agentHostName, secret, false, sd));
        LOG.info("SM Agent initialized: " + _api.toString());
        LOG.info("SM Agent initialization return code: " + result);
    }

    private String getSharedSecret() {
        Fips140Mode fipsMode = Fips140Mode.getFips140ModeObject();
        fipsMode.setMode(Util.resolveSetting());

        String address = _policyIp;
        String filename = "smhost.conf";
        String hostname = "_agentHostName";
        String hostConfig = "hostConfig";
        String username = _policyUsername;
        String password = _policyPwd;
        boolean bRollover = false;
        boolean bOverwrite = true;
        SmRegHost reghost = new SmRegHost(address,filename,hostname,hostConfig,username,password,bRollover,bOverwrite);
        try {
            reghost.register();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return reghost.getSharedSecret();
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
        LOG.debug("Checking if URI [" + uri + "] is protected");
        int rc = _api.isProtected(_agentHostName,
                new ResourceContextDef(
                    _agentHostName,
                    "Cloudfoundry",
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
