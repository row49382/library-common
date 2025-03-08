package com.row49382.common.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;

public class AuthenticatedToken extends AbstractAuthenticationToken {

    public AuthenticatedToken(Collection<? extends GrantedAuthority> grantedAuthorityList) {
        super(grantedAuthorityList);
        super.setAuthenticated(true);
    }

    public AuthenticatedToken() {
        super(AuthorityUtils.NO_AUTHORITIES);
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
