package com.example.service.impl;

import com.example.service.LdapService;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Hashtable;

@Service
public class LdapServiceImpl implements LdapService {
    @Override
    public String convertSidToStr(byte[] sid) {
        if (sid == null) return null;
        if (sid.length < 8 || sid.length % 4 != 0) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("S-").append(sid[0]);
        int c = sid[1];
        ByteBuffer bb = ByteBuffer.wrap(sid);
        sb.append("-").append((long) bb.getLong() & 0XFFFFFFFFFFFFL);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < c; i++) {
            sb.append("-").append((long) bb.getInt() & 0xFFFFFFFFL);
        }
        return sb.toString();
    }

    @Override
    public Attributes getUserAttributes(String username, String[] attr, DirContext ctx) {
        try {
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(attr);
            NamingEnumeration<SearchResult> answer = ctx.search("OU=test-ou,DC=cit,DC=local", "(sAMAccountName=" + getNameFromUsername(username) + ")", constraints);
            if (answer.hasMore()) {
                return (answer.next()).getAttributes();
            } else {
                throw new Exception("Invalid User");
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    @Override
    public DirContext generateDirContext(String username, String password) {
        try {
            Hashtable<String, String> environment = new Hashtable<String, String>();
            environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            environment.put(Context.PROVIDER_URL, "ldap://192.168.100.3:389");
            environment.put(Context.SECURITY_AUTHENTICATION, "simple");
            environment.put(Context.SECURITY_PRINCIPAL, username);
            environment.put(Context.SECURITY_CREDENTIALS, password);
            environment.put("java.naming.ldap.attributes.binary", "objectSID");
            return new InitialDirContext(environment);
        } catch (NamingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private String getNameFromUsername(String username) {
        return (username.split("[@]"))[0];
    }
}
