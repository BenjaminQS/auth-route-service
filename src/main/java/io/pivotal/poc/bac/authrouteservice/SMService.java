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
    @Value("${sm.agent.name}")
    private String _agent;
    @Value("${sm.hostconfig}")
    private String _hc;

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
        String hostname = _agentHostName;
        String hostconfig = _hc;
        String username = _policyUsername;
        String password = _policyPwd;
        boolean bRollover = false;
        boolean bOverwrite = true;

        LOG.info("*** SM registration values ***");
        LOG.info("SM registration address: " + address);
        LOG.info("SM registration filename: " + filename);
        LOG.info("SM registration hostname: " + hostname);
        LOG.info("SM registration hostconfig: " + hostconfig);
        LOG.info("SM registration username: " + username);
        LOG.info("SM registration password: " + password);
        LOG.info("SM registration bRollover: " + bRollover);
        LOG.info("SM registration bOverwrite: " + bOverwrite);

        SmRegHost reghost = new SmRegHost(address,filename,hostname,hostconfig,username,password,bRollover,bOverwrite);
        try {
            reghost.register();
        } catch(Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Unable to register Siteminder agent: " + ex.getMessage(), ex);
        }
        return reghost.getSharedSecret();
    }

    public boolean isValid(String authCookie, boolean retry) {
        LOG.debug("Validating cookie [" + authCookie + "]");
        int rc = _api.decodeSSOToken(authCookie, new TokenDescriptor(0,true), new AttributeList(), false, new StringBuffer());
        LOG.debug("Decode return code: "+ rc);
        switch (rc) {
            case AgentAPI.SUCCESS:
                return true;
            case AgentAPI.FAILURE:
                return false;
            default:
                if(retry) {
                    LOG.debug("SM may have timedout... retrying");
                     try { afterPropertiesSet(); } catch(Exception ex) { ex.printStackTrace(); }
                    return isValid(authCookie, false);
                }
                throw new RuntimeException("Error Occurred Checking if decoding cookie; ReturnCode: " + rc);
        }
    }

    public boolean isProtected(String uri, HttpMethod method, boolean retry) {
        LOG.debug("Checking if URI [" + uri + "] is protected");
        int rc = _api.isProtected(_agentHostName,
                new ResourceContextDef(
                    _agent,
                    "Cloudfoundry",
                    uri,
                    method.name()),
                    new RealmDef());
        LOG.debug("IsProtected return code: "+ rc);
        switch (rc) {
            case AgentAPI.YES:
                LOG.debug("Resource is protected");
                return true;
            case AgentAPI.NO:
                LOG.debug("Resource is not protected");
                return false;
            default:
                if(retry) {
                    LOG.debug("SM may have timedout... retrying");
                    try { afterPropertiesSet(); } catch(Exception ex) { ex.printStackTrace(); }
                    return isProtected(uri, method, false);
                }
                throw new RuntimeException("Error Occurred Checking if resource is protected; ReturnCode: " + rc);

        }
    }
}
