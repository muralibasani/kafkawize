package com.kafkamgt.uiapi.auth;

import com.kafkamgt.uiapi.config.ManageDatabase;
import com.kafkamgt.uiapi.dao.RegisterUserInfo;
import com.kafkamgt.uiapi.model.RegisterUserInfoModel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.UUID;

import static org.springframework.beans.BeanUtils.copyProperties;

//ActiveDirectoryLdapAuthenticationProvider

@Service
@Slf4j
public class KwAuthenticationService {
    @Value("${spring.ad.domain:}")
    private String adDomain;

    @Value("${spring.ad.url:}")
    private String adUrl;

    @Value("${spring.ad.rootDn:}")
    private String adRootDn;

    @Value("${spring.ad.filter:}")
    private String adFilter;

    @Autowired
    ManageDatabase manageDatabase;

    private final static String searchFilter = "(&(objectClass=user)(userPrincipalName={0}))";

    ContextFactory contextFactory = new ContextFactory();

    static class ContextFactory {
        ContextFactory() {
        }

        DirContext createContext(Hashtable<?, ?> env) throws NamingException {
            return new InitialLdapContext(env, null);
        }
    }

    HashMap<String, Object> searchUser(String username, String pwd) throws NamingException {
        HashMap<String, Object> userObject = new HashMap<>();
        DirContext ctx = bindAsUser(username, pwd);
        DirContextOperations var5;
        try {
            var5 = this.searchForUser(ctx, username);
            Attributes attributes = var5.getAttributes();

            userObject.put("userFound", Boolean.TRUE);
            userObject.put("attributes", attributes);
        } catch (NamingException var9) {
            log.error("Failed to locate directory entry for authenticated user: " + username, var9);
            userObject.put("userFound", Boolean.FALSE);
        } finally {
            LdapUtils.closeContext(ctx);
        }

        return userObject;
    }

    private DirContext bindAsUser(String username, String password) {
        String bindUrl = this.adUrl;
        Hashtable<String, Object> env = new Hashtable<>();
        env.put("java.naming.security.authentication", "simple");
        String bindPrincipal = this.createBindPrincipal(username);
        env.put("java.naming.security.principal", bindPrincipal);
        env.put("java.naming.provider.url", bindUrl);
        env.put("java.naming.security.credentials", password);
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.factory.object", DefaultDirObjectFactory.class.getName());

        try {
            return this.contextFactory.createContext(env);
        } catch (NamingException var7) {
            try {
                throw var7;
            } catch (NamingException e) {
                log.error(e.toString());
            }
        }

        return null;
    }

    private DirContextOperations searchForUser(DirContext context, String username) throws NamingException {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(2);
        String bindPrincipal = this.createBindPrincipal(username);
        String searchRoot = this.adRootDn != null ? this.adRootDn : this.searchRootFromPrincipal(bindPrincipal);
        String searchFilterUpdated;
        if(adFilter != null && !adFilter.equals(""))
            searchFilterUpdated = adFilter;
        else
            searchFilterUpdated = searchFilter;

        try {
            return SpringSecurityLdapTemplate.searchForSingleEntryInternal(context, searchControls, searchRoot,
                    searchFilterUpdated, new Object[]{bindPrincipal, username});
        } catch (IncorrectResultSizeDataAccessException var8) {
            if (var8.getActualSize() != 0) {
                throw var8;
            } else {
                throw this.badCredentials();
            }
        }
    }

    private String searchRootFromPrincipal(String bindPrincipal) {
        int atChar = bindPrincipal.lastIndexOf(64);
        if (atChar < 0) {
//            this.logger.debug("User principal '" + bindPrincipal + "' does not contain the domain, and no domain has been configured");
            throw this.badCredentials();
        } else {
            return this.rootDnFromDomain(bindPrincipal.substring(atChar + 1));
        }
    }

    private BadCredentialsException badCredentials() {
        return new BadCredentialsException("Bad credentials");
    }

    private String rootDnFromDomain(String domain) {
        String[] tokens = StringUtils.tokenizeToStringArray(domain, ".");
        StringBuilder root = new StringBuilder();
        String[] var4 = tokens;
        int var5 = tokens.length;

        for(int var6 = 0; var6 < var5; ++var6) {
            String token = var4[var6];
            if (root.length() > 0) {
                root.append(',');
            }

            root.append("dc=").append(token);
        }

        return root.toString();
    }

    String createBindPrincipal(String username) {
        return this.adDomain != null && !username.toLowerCase().endsWith(this.adDomain) ? username + "@" + this.adDomain : username;
    }

    Authentication searchUserAttributes(HttpServletRequest request, HttpServletResponse response) {
        try {
            String userName = request.getParameter("username");
            HashMap<String, Object> userAttributesObject = searchUser(userName, request.getParameter("password"));

            // User found in AD and not in KW db

            if(userAttributesObject.get("userFound").equals(Boolean.TRUE)){
                try{
                    log.info("User found in AD and not in Kafkawize db :{}", userName);
                    String existingRegistrationId = manageDatabase.getHandleDbRequests()
                            .getRegistrationId(userName);

                    if(existingRegistrationId != null){
                        if(existingRegistrationId.equals("PENDING_ACTIVATION"))
                            response.sendRedirect("registrationReview");
                        else
                            response.sendRedirect("register?userRegistrationId=" + existingRegistrationId);
                    }
                    else{
                        String randomId = UUID.randomUUID().toString();

                        RegisterUserInfoModel registerUserInfoModel = new RegisterUserInfoModel();
                        registerUserInfoModel.setRegistrationId(randomId);
                        registerUserInfoModel.setStatus("STAGING");
                        registerUserInfoModel.setRegisteredTime(new Timestamp(System.currentTimeMillis()));
                        registerUserInfoModel.setUsername(userName);
                        registerUserInfoModel.setPwd("");

                        Attributes attributes = (Attributes)userAttributesObject.get("attributes");
                        if(attributes.get("mail")!=null)
                            registerUserInfoModel.setMailid((String) attributes.get("mail").get());
                        if(attributes.get("displayname")!=null)
                            registerUserInfoModel.setFullname((String) attributes.get("displayname").get());

                        RegisterUserInfo registerUserInfo = new RegisterUserInfo();
                        copyProperties(registerUserInfoModel, registerUserInfo);
                        manageDatabase.getHandleDbRequests().registerUserForAD(registerUserInfo);

                        response.sendRedirect("register?userRegistrationId=" + randomId);
                    }
                }catch(Exception e){
                    log.error("Unable to find mail/name fields.");
                    response.sendRedirect("register");
                }
            }
            else{
                // User not found in AD and in KW db
                response.sendRedirect("login?error");
            }
            return null;
        } catch (NamingException | IOException | NullPointerException e) {
            log.error("User not found / Invalid credentials {}", request.getParameter("username"));
            try {
                response.sendRedirect("login?error");
            } catch (IOException ignored) {

            }
            return null;
        }
    }


}
