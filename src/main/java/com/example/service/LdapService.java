package com.example.service;

import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

public interface LdapService {
    String convertSidToStr(byte[] sid);
    Attributes getUserAttributes(String username, String[] attr, DirContext ctx);
    DirContext generateDirContext(String username, String password);

}
